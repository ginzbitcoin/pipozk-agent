'use strict';
/*
 * PipoZK - agen Proof Gatekeeper untuk Agent Games (zkVerify).
 *
 * Protokol resmi: https://agentgames.zkverify.io/build
 * (dibaca 15 Nov 2026). Ringkasnya:
 * - Platform POST tugas JSON bertanda tangan ke endpoint terdaftar.
 * - Tiap request masuk diverifikasi lewat header x-agent-games-signature,
 *   yaitu HMAC-SHA256 (hex) dari raw body request.
 * - Tiap respons sukses ditandatangani dengan cara yang sama.
 * - Preflight: request type "agent-games.preflight.v1", jawab
 *   { ok: true, protocolVersion: "v1" }.
 * - Task Gatekeeper: type "agent-games.proof-gatekeeper.v1", field input
 *   berisi registered_vk, proof_vk, minimum, public_balance,
 *   expiry_block, current_block, recipient, condition_recipient,
 *   amount, max_transfer, proof_tx.
 * - Respons: { decision, reason_code, proof, public_signals, proof_tx }.
 * - Batas respons 60 detik, fail closed: ragu berarti REJECT.
 *
 * Server ini TIDAK memanggil jaringan keluar. Keputusan murni dari isi
 * envelope tugas, jadi responsnya instan dan deterministik.
 *
 * Jejak keputusan: tiap keputusan baru dicatat ke file JSONL
 * (DECISIONS_FILE, default decisions.jsonl di folder program) dan
 * bisa dicek publik lewat GET /agent/decisions, lengkap dengan hash
 * chain dan tanda tangan HMAC tiap entri.
 *
 * Secret HMAC TIDAK PERNAH ditulis ke log, respons, atau file apa pun.
 * Yang dicatat hanya sidik jari pendek (8 karakter pertama dari
 * SHA-256 secret) saat startup, untuk memastikan secret yang dipakai
 * adalah yang benar tanpa membocorkan nilainya.
 */

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = parseInt(process.env.PORT || '8741', 10);
const HOST = process.env.HOST || '127.0.0.1';
const MAX_BODY_BYTES = 1024 * 1024; // 1 MB, tugas platform jauh lebih kecil

/* ------------------------------------------------------------------ */
/* Prover Groth16 (proof lokal, opsional)                             */
/* ------------------------------------------------------------------ */
/*
 * Proof Groth16 lokal untuk respons Gatekeeper (circuit resmi
 * gatekeeper.wasm + gatekeeper_final.zkey, snarkjs). Bila modul
 * tidak bisa dimuat (folder proof/ tidak ada / snarkjs belum
 * terpasang), server tetap jalan seperti sebelumnya dengan proof
 * null, bukan crash. Flag env PROOF_ENABLED=0 mematikan proving
 * tanpa ubah kode.
 */

let PROVER = null;
try {
  PROVER = require('./proof/prove-local.cjs');
} catch (err) {
  console.error('[pipozk] prover tidak dimuat, proof tetap null: ' + err.message);
}
const PROOF_ENABLED = (process.env.PROOF_ENABLED || '1').trim() !== '0';

// reason_code yang circuit-nya bisa buktikan (lima cek di dalam
// circuit). INVALID_INPUT, TASK_EXPIRED, PROOF_REUSED, dan
// INTERNAL_ERROR tidak bisa dibuktikan circuit (tidak mengenal
// deadline_at, pemakaian ulang proof_tx, atau input rusak), jadi
// tetap dijawab tanpa proof.
const NEEDS_PROOF = {
  OK: true,
  VK_SUBSTITUTION: true,
  RECIPIENT_MISMATCH: true,
  AMOUNT_EXCEEDS_LIMIT: true,
  INSUFFICIENT_BALANCE: true,
  EXPIRED: true,
};

// Status self-test proving saat startup (async, tidak memblokir listen).
const proofStatus = {
  loaded: PROVER !== null,
  enabled: PROOF_ENABLED,
  selfTest: (PROVER && PROOF_ENABLED) ? 'pending' : 'skipped',
  proofMs: null,
  error: null,
};

/* ------------------------------------------------------------------ */
/* Secret                                                             */
/* ------------------------------------------------------------------ */

function loadSecret() {
  const fromEnv = (process.env.AGENT_GAMES_HMAC_SECRET || '').trim();
  if (fromEnv) return fromEnv;
  const file = (process.env.AGENT_GAMES_HMAC_SECRET_FILE || '').trim();
  if (file) {
    try {
      return fs.readFileSync(file, 'utf8').trim();
    } catch (err) {
      console.error(`[pipozk] GAGAL membaca file secret ${file}: ${err.message}`);
      process.exit(1);
    }
  }
  return '';
}

const SECRET = loadSecret();
if (!SECRET) {
  console.error('[pipozk] ERROR: secret HMAC tidak ditemukan.');
  console.error('[pipozk] Isi env AGENT_GAMES_HMAC_SECRET atau AGENT_GAMES_HMAC_SECRET_FILE');
  console.error('[pipozk] dengan secret dari dashboard (Rotate Secret). Server berhenti.');
  process.exit(1);
}
const SECRET_KEY = Buffer.from(SECRET, 'utf8');
const SECRET_FINGERPRINT = crypto.createHash('sha256').update(SECRET_KEY).digest('hex').slice(0, 8);

/* ------------------------------------------------------------------ */
/* HMAC                                                               */
/* ------------------------------------------------------------------ */

function hmacHex(bodyBuffer) {
  return crypto.createHmac('sha256', SECRET_KEY).update(bodyBuffer).digest('hex');
}

function signaturesEqual(received, expectedHex) {
  if (typeof received !== 'string' || !received) return false;
  const a = Buffer.from(received.trim().toLowerCase(), 'utf8');
  const b = Buffer.from(expectedHex.trim().toLowerCase(), 'utf8');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/* ------------------------------------------------------------------ */
/* Util                                                               */
/* ------------------------------------------------------------------ */

function log(fields) {
  const line = Object.assign({ time: new Date().toISOString() }, fields);
  console.log(JSON.stringify(line));
}

// Terima angka bulat sebagai number atau string desimal ("500"),
// dan juga string hex ("0x1f4"). Kembalikan BigInt atau null bila tidak valid.
function parseBigInt(value) {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number' && Number.isInteger(value)) return BigInt(value);
  if (typeof value === 'string') {
    const s = value.trim();
    if (/^-?\d+$/.test(s)) return BigInt(s);
    if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
  }
  return null;
}

function parseDate(value) {
  if (typeof value !== 'string' || !value.trim()) return null;
  const d = new Date(value.trim());
  return Number.isNaN(d.getTime()) ? undefined : d;
}

/* ------------------------------------------------------------------ */
/* Aturan keputusan Gatekeeper                                         */
/* ------------------------------------------------------------------ */
/*
 * APPROVE hanya bila SEMUA cek lolos. Satu cek gagal berarti REJECT
 * dengan reason_code cek itu. Ini turunan dari Security checklist di
 * /build (VK cocok, input publik membuktikan ambang + penerima +
 * jumlah, referensi proof belum dipakai, final sebelum approve,
 * signature + timestamp tugas valid) yang dipetakan ke field-field
 * envelope tugas.
 *
 * Satu-satunya reason_code yang tertulis di dokumen resmi adalah
 * VK_SUBSTITUTION (contoh respons di /build). Kode lain di bawah ini
 * adalah nama deskriptif buatan kami supaya alasan penolakan bisa
 * dibaca di log; platform hanya mencatat reason_code apa adanya.
 *
 * Skor (dari /build): keputusan benar +12, menyetujui jebakan -6,
 * menolak request valid -3, timeout/offline -2, proof tidak lolos
 * verifikasi -2, plus bonus reliabilitas. Karena menyetujui jebakan
 * lebih mahal daripada menolak yang valid, aturan di sini condong
 * ketat (fail closed).
 */

const REASON_OK = 'OK';

// Cache idempotensi: task_id -> respons yang sudah dikirim.
// Platform boleh mengirim ulang task yang sama sesudah gagal jaringan;
// kiriman ulang harus mendapat jawaban yang identik, bukan dinilai
// sebagai pemakaian ulang proof.
const taskCache = new Map();

// proof_tx -> task_id pertama yang memakainya. Proof yang sama di
// task_id berbeda berarti referensi dipakai ulang.
const proofSeen = new Map();

function decideGatekeeper(envelope) {
  const input = envelope.input;
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { decision: 'REJECT', reason_code: 'INVALID_INPUT' };
  }

  // 1. Verification key: proof harus memakai kunci yang terdaftar.
  //    Ini satu-satunya reason_code yang didokumentasikan resmi.
  const registeredVk = input.registered_vk;
  const proofVk = input.proof_vk;
  if (typeof registeredVk !== 'string' || !registeredVk.trim()
    || typeof proofVk !== 'string' || !proofVk.trim()) {
    return { decision: 'REJECT', reason_code: 'INVALID_INPUT' };
  }
  if (proofVk.trim().toLowerCase() !== registeredVk.trim().toLowerCase()) {
    return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION' };
  }

  // 2. Penerima: penerima transfer harus sama dengan penerima syarat.
  const recipient = input.recipient;
  const conditionRecipient = input.condition_recipient;
  if (typeof recipient !== 'string' || !recipient.trim()
    || typeof conditionRecipient !== 'string' || !conditionRecipient.trim()) {
    return { decision: 'REJECT', reason_code: 'INVALID_INPUT' };
  }
  if (recipient.trim().toLowerCase() !== conditionRecipient.trim().toLowerCase()) {
    return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH' };
  }

  // 3. Jumlah: harus positif dan tidak melebihi batas transfer.
  const amount = parseBigInt(input.amount);
  const maxTransfer = parseBigInt(input.max_transfer);
  if (amount === null || maxTransfer === null) {
    return { decision: 'REJECT', reason_code: 'INVALID_INPUT' };
  }
  if (amount <= 0n) {
    return { decision: 'REJECT', reason_code: 'INVALID_INPUT' };
  }
  if (amount > maxTransfer) {
    return { decision: 'REJECT', reason_code: 'AMOUNT_EXCEEDS_LIMIT' };
  }

  // 4. Ambang saldo: saldo publik harus mencapai minimum yang disyaratkan.
  const publicBalance = parseBigInt(input.public_balance);
  const minimum = parseBigInt(input.minimum);
  if (publicBalance === null || minimum === null) {
    return { decision: 'REJECT', reason_code: 'INVALID_INPUT' };
  }
  if (publicBalance < minimum) {
    return { decision: 'REJECT', reason_code: 'INSUFFICIENT_BALANCE' };
  }

  // 5. Kedaluwarsa blok: blok saat ini harus masih sebelum blok kedaluwarsa.
  const expiryBlock = parseBigInt(input.expiry_block);
  const currentBlock = parseBigInt(input.current_block);
  if (expiryBlock === null || currentBlock === null) {
    return { decision: 'REJECT', reason_code: 'INVALID_INPUT' };
  }
  if (currentBlock >= expiryBlock) {
    return { decision: 'REJECT', reason_code: 'EXPIRED' };
  }

  // 6. Batas waktu tugas: deadline_at yang sudah lewat berarti tugas basi.
  if (typeof envelope.deadline_at === 'string' && envelope.deadline_at.trim()) {
    const deadline = parseDate(envelope.deadline_at);
    if (deadline === undefined) {
      return { decision: 'REJECT', reason_code: 'INVALID_INPUT' };
    }
    if (deadline !== null && Date.now() > deadline.getTime()) {
      return { decision: 'REJECT', reason_code: 'TASK_EXPIRED' };
    }
  }

  // 7. Stempel waktu: issued_at yang tidak bisa dibaca berarti envelope rusak.
  if (typeof envelope.issued_at === 'string' && envelope.issued_at.trim()) {
    const issued = parseDate(envelope.issued_at);
    if (issued === undefined) {
      return { decision: 'REJECT', reason_code: 'INVALID_INPUT' };
    }
  }

  // 8. Referensi proof belum dipakai di task lain.
  const proofTx = (typeof input.proof_tx === 'string' && input.proof_tx.trim())
    ? input.proof_tx.trim()
    : null;
  const taskId = (typeof envelope.task_id === 'string' && envelope.task_id.trim())
    ? envelope.task_id.trim()
    : null;
  if (proofTx) {
    const firstUser = proofSeen.get(proofTx);
    if (firstUser && firstUser !== taskId) {
      return { decision: 'REJECT', reason_code: 'PROOF_REUSED' };
    }
  }

  return { decision: 'APPROVE', reason_code: REASON_OK };
}

/* ------------------------------------------------------------------ */
/* Jejak keputusan (decision trail) - Wildcard                        */
/* ------------------------------------------------------------------ */
/*
 * Tiap keputusan Gatekeeper yang baru (bukan kiriman ulang) dicatat
 * sebagai satu entri jejak yang bisa dicek publik:
 * - Entri disimpan append-only di file JSONL (DECISIONS_FILE), jadi
 *   jejak selamat dari restart server.
 * - Entri dirangkai hash chain: tiap entri menyimpan prev_hash (hash
 *   entri sebelumnya) dan entry_hash (hash kanonik isi entri). Siapa
 *   pun bisa memeriksa rantai hash tanpa secret.
 * - Entri ditandatangani HMAC-SHA256 dengan secret agen (tanda tangan
 *   atas entry_hash). Hanya pemegang secret yang bisa membuat tanda
 *   tangan yang cocok, jadi entri tidak bisa dipalsukan. Verifikasi
 *   tanda tangan dilakukan server lewat endpoint /verify (secret
 *   tidak pernah keluar dari server).
 * - Entri menyimpan input lengkap tugas, jadi siapa pun bisa
 *   menjalankan ulang 10 cek Gatekeeper terhadap input itu dan
 *   memastikan keputusan + reason_code yang tercatat sudah benar.
 * - Daftar cek di tiap entri diturunkan dari reason_code dan urutan
 *   evaluasi yang didokumentasikan: cek sebelum cek yang gagal
 *   "pass", cek yang gagal "fail", cek sesudahnya "skipped".
 *   Bila reason_code OK, semua cek "pass".
 * - Kiriman ulang task_id yang sama TIDAK membuat entri baru
 *   (idempotent, jawaban dikembalikan dari cache).
 * - Saat startup, cache idempotensi + proof terpakai dibangun ulang
 *   dari file jejak, supaya restart di tengah ronde tidak mengulang
 *   penilaian.
 */

const DECISIONS_FILE = (process.env.DECISIONS_FILE || '').trim()
  || path.join(__dirname, 'decisions.jsonl');
const GENESIS_PREV_HASH = '0'.repeat(64);
const MAX_DECISIONS_MEMORY = 10000;
const MAX_DECISIONS_PAGE = 200;

const CHECK_ORDER = [
  'INVALID_INPUT',
  'VK_SUBSTITUTION',
  'RECIPIENT_MISMATCH',
  'AMOUNT_EXCEEDS_LIMIT',
  'INSUFFICIENT_BALANCE',
  'EXPIRED',
  'TASK_EXPIRED',
  'PROOF_REUSED',
  'INTERNAL_ERROR',
];

// JSON deterministik: kunci objek diurutkan secara rekursif, supaya
// hash dan tanda tangan bisa dihitung ulang siapa pun dari isi entri.
function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalJson(value[k])).join(',') + '}';
}

function deriveChecks(reasonCode) {
  if (reasonCode === REASON_OK) {
    return CHECK_ORDER.map((code) => ({ check: code, result: 'pass' }));
  }
  const failIndex = CHECK_ORDER.indexOf(reasonCode);
  if (failIndex === -1) {
    return CHECK_ORDER.map((code) => ({ check: code, result: 'skipped' }));
  }
  return CHECK_ORDER.map((code, i) => ({
    check: code,
    result: i < failIndex ? 'pass' : (i === failIndex ? 'fail' : 'skipped'),
  }));
}

function sha256Hex(text) {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

function buildEntry(seq, prevHash, fields) {
  const record = {
    seq,
    task_id: fields.taskId,
    mode: fields.mode || '',
    decision: fields.decision,
    reason_code: fields.reasonCode,
    checks: deriveChecks(fields.reasonCode),
    proof_tx: fields.proofTx,
    proof: fields.proof || null,
    public_signals: fields.publicSignals || null,
    input: fields.input,
    input_hash: sha256Hex(canonicalJson(fields.input)),
    issued_at: fields.issuedAt || null,
    decided_at: new Date().toISOString(),
    prev_hash: prevHash,
  };
  record.entry_hash = sha256Hex(canonicalJson(record));
  record.signature = crypto.createHmac('sha256', SECRET_KEY)
    .update(record.entry_hash, 'utf8').digest('hex');
  return record;
}

function entryCanonicalWithoutSignature(entry) {
  const copy = Object.assign({}, entry);
  delete copy.signature;
  delete copy.entry_hash;
  return canonicalJson(copy);
}

function verifyEntrySignature(entry) {
  if (!entry || typeof entry.signature !== 'string') return false;
  const expected = crypto.createHmac('sha256', SECRET_KEY)
    .update(entry.entry_hash, 'utf8').digest('hex');
  const a = Buffer.from(entry.signature.trim().toLowerCase(), 'utf8');
  const b = Buffer.from(expected.trim().toLowerCase(), 'utf8');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function verifyEntryHash(entry) {
  if (!entry || typeof entry.entry_hash !== 'string') return false;
  return sha256Hex(entryCanonicalWithoutSignature(entry)) === entry.entry_hash;
}

const trailEntries = [];
let trailNextSeq = 1;
let trailLastHash = GENESIS_PREV_HASH;

function loadTrail() {
  let raw;
  try {
    raw = fs.readFileSync(DECISIONS_FILE, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') {
      log({ kind: 'trail', result: 'new_file', file: DECISIONS_FILE });
      return;
    }
    console.error(`[pipozk] GAGAL membaca file jejak ${DECISIONS_FILE}: ${err.message}`);
    return;
  }
  let loaded = 0;
  let skipped = 0;
  for (const line of raw.split('\n')) {
    const s = line.trim();
    if (!s) continue;
    let entry;
    try {
      entry = JSON.parse(s);
    } catch (e) {
      skipped += 1;
      continue;
    }
    if (!entry || typeof entry.seq !== 'number' || typeof entry.entry_hash !== 'string') {
      skipped += 1;
      continue;
    }
    trailEntries.push(entry);
    if (entry.seq >= trailNextSeq) trailNextSeq = entry.seq + 1;
    trailLastHash = entry.entry_hash;
    if (entry.task_id) {
      taskCache.set(entry.task_id, {
        decision: entry.decision,
        reason_code: entry.reason_code,
        proof: entry.proof || null,
        public_signals: entry.public_signals || null,
        proof_tx: entry.proof_tx,
      });
    }
    if (entry.proof_tx) proofSeen.set(entry.proof_tx, entry.task_id);
    loaded += 1;
  }
  if (trailEntries.length > MAX_DECISIONS_MEMORY) {
    trailEntries.splice(0, trailEntries.length - MAX_DECISIONS_MEMORY);
  }
  log({ kind: 'trail', result: 'loaded', loaded, skipped, next_seq: trailNextSeq });
}

function recordDecision(fields) {
  const entry = buildEntry(trailNextSeq, trailLastHash, fields);
  try {
    fs.appendFileSync(DECISIONS_FILE, JSON.stringify(entry) + '\n', 'utf8');
  } catch (err) {
    console.error(`[pipozk] GAGAL menulis jejak keputusan: ${err.message}`);
    return null;
  }
  trailEntries.push(entry);
  if (trailEntries.length > MAX_DECISIONS_MEMORY) trailEntries.shift();
  trailNextSeq += 1;
  trailLastHash = entry.entry_hash;
  return entry;
}

function verifyChain() {
  let prev = GENESIS_PREV_HASH;
  for (const entry of trailEntries) {
    if (entry.prev_hash !== prev) {
      return { valid: false, count: trailEntries.length, first_bad_seq: entry.seq };
    }
    if (!verifyEntryHash(entry)) {
      return { valid: false, count: trailEntries.length, first_bad_seq: entry.seq };
    }
    prev = entry.entry_hash;
  }
  return {
    valid: true,
    count: trailEntries.length,
    head_seq: trailEntries.length ? trailEntries[trailEntries.length - 1].seq : 0,
    head_hash: trailLastHash,
  };
}

/* ------------------------------------------------------------------ */
/* HTTP                                                               */
/* ------------------------------------------------------------------ */

function sendJson(res, statusCode, obj, sign) {
  const body = Buffer.from(JSON.stringify(obj), 'utf8');
  const headers = {
    'Content-Type': 'application/json',
    'Content-Length': body.length,
  };
  if (sign) headers['x-agent-games-signature'] = hmacHex(body);
  res.writeHead(statusCode, headers);
  res.end(body);
}

async function handleTask(body, res) {
  // Preflight: jawab { ok: true, protocolVersion: "v1" } bertanda tangan.
  if (body.type === 'agent-games.preflight.v1') {
    const out = { ok: true, protocolVersion: 'v1' };
    log({ kind: 'preflight', result: 'ok' });
    sendJson(res, 200, out, true);
    return;
  }

  // Task Gatekeeper. Bentuk cadangan "action": "decide" juga diterima,
  // seandainya platform mengirim varian itu; field input dibaca dari
  // body.input atau langsung dari body.
  const isGatekeeper = body.type === 'agent-games.proof-gatekeeper.v1'
    || body.action === 'decide';
  if (!isGatekeeper) {
    log({ kind: 'task', result: 'unknown_type', type: String(body.type || body.action || '') });
    sendJson(res, 400, { ok: false, error: 'unknown_task' }, true);
    return;
  }

  const envelope = body.input && typeof body.input === 'object'
    ? body
    : { task_id: body.task_id, issued_at: body.issued_at, deadline_at: body.deadline_at, input: body };

  const taskId = (typeof envelope.task_id === 'string' && envelope.task_id.trim())
    ? envelope.task_id.trim()
    : null;

  // Kiriman ulang task_id yang sama: kembalikan jawaban identik.
  if (taskId && taskCache.has(taskId)) {
    const cached = taskCache.get(taskId);
    log({ kind: 'decide', task_id: taskId, decision: cached.decision, reason_code: cached.reason_code, replay: true });
    sendJson(res, 200, cached, true);
    return;
  }

  let verdict;
  try {
    verdict = decideGatekeeper(envelope);
  } catch (err) {
    // Gagal apa pun saat menilai berarti REJECT (fail closed).
    log({ kind: 'decide', task_id: taskId, decision: 'REJECT', reason_code: 'INTERNAL_ERROR', error: err.message });
    verdict = { decision: 'REJECT', reason_code: 'INTERNAL_ERROR' };
  }

  const input = (envelope.input && typeof envelope.input === 'object') ? envelope.input : {};
  const proofTx = (typeof input.proof_tx === 'string' && input.proof_tx.trim())
    ? input.proof_tx.trim()
    : null;

  // Proof Groth16 lokal (bila reason_code bisa dibuktikan circuit).
  // Gagal proving TIDAK PERNAH mengubah keputusan: jawab keputusan
  // yang benar tanpa proof (rugi -2) daripada timeout (juga -2, tapi
  // berisiko kehilangan tugas). proof_tx tetap menggemakan pointer
  // dari tugas masuk.
  let proof = null;
  let publicSignals = null;
  if (PROVER && PROOF_ENABLED && NEEDS_PROOF[verdict.reason_code]) {
    try {
      const circuitInput = PROVER.buildCircuitInput(
        {
          task_id: taskId,
          registered_vk: input.registered_vk,
          proof_vk: input.proof_vk,
          minimum: input.minimum,
          public_balance: input.public_balance,
          expiry_block: input.expiry_block,
          current_block: input.current_block,
          recipient: input.recipient,
          condition_recipient: input.condition_recipient,
          amount: input.amount,
          max_transfer: input.max_transfer,
        },
        verdict.decision,
      );
      const r = await PROVER.generateProof(circuitInput);
      proof = r.proof;
      publicSignals = r.publicSignals;
      log({ kind: 'prove', task_id: taskId, proof_ms: r.proofMs });
    } catch (err) {
      log({ kind: 'prove', task_id: taskId, result: 'failed', error: err.message });
    }
  }

  const out = {
    decision: verdict.decision,
    reason_code: verdict.reason_code,
    proof,
    public_signals: publicSignals,
    proof_tx: proofTx,
  };

  if (taskId) taskCache.set(taskId, out);
  if (proofTx) proofSeen.set(proofTx, taskId);

  // Catat ke jejak keputusan publik. Bila penulisan jejak gagal,
  // keputusan tetap dikirim (jejak sekunder, respons primer).
  const trailEntry = recordDecision({
    taskId,
    mode: envelope.mode || '',
    decision: out.decision,
    reasonCode: out.reason_code,
    proofTx,
    proof: out.proof,
    publicSignals: out.public_signals,
    input,
    issuedAt: (typeof envelope.issued_at === 'string') ? envelope.issued_at : null,
  });

  log({ kind: 'decide', task_id: taskId, decision: out.decision, reason_code: out.reason_code, mode: envelope.mode || '', trail_seq: trailEntry ? trailEntry.seq : null });
  sendJson(res, 200, out, true);
}

function handleDecisions(req, res, urlPath) {
  const segments = urlPath.split('/').filter(Boolean); // ['agent', 'decisions', ...]

  // GET /agent/decisions/chain: verifikasi seluruh rantai hash.
  if (segments.length === 3 && segments[2] === 'chain') {
    const chain = verifyChain();
    sendJson(res, 200, Object.assign({ ok: true }, chain), false);
    return;
  }

  // GET /agent/decisions/<seq> dan /agent/decisions/<seq>/verify.
  if (segments.length === 3 || segments.length === 4) {
    const seq = parseInt(segments[2], 10);
    if (!Number.isInteger(seq) || String(seq) !== segments[2]) {
      sendJson(res, 404, { ok: false, error: 'not_found' }, false);
      return;
    }
    const entry = trailEntries.find((e) => e.seq === seq);
    if (!entry) {
      sendJson(res, 404, { ok: false, error: 'not_found' }, false);
      return;
    }
    if (segments.length === 4 && segments[3] === 'verify') {
      const idx = trailEntries.indexOf(entry);
      const prev = idx > 0 ? trailEntries[idx - 1] : null;
      const chainOk = prev
        ? entry.prev_hash === prev.entry_hash
        : entry.prev_hash === GENESIS_PREV_HASH;
      const hashOk = verifyEntryHash(entry);
      const sigOk = verifyEntrySignature(entry);
      sendJson(res, 200, {
        ok: true, seq: entry.seq, valid: hashOk && sigOk && chainOk,
        hash_ok: hashOk, sig_ok: sigOk, chain_ok: chainOk, entry,
      }, false);
      return;
    }
    if (segments.length === 3) {
      sendJson(res, 200, { ok: true, entry }, false);
      return;
    }
    sendJson(res, 404, { ok: false, error: 'not_found' }, false);
    return;
  }

  // GET /agent/decisions: daftar, terbaru dulu (atau ?order=asc).
  if (segments.length === 2) {
    const query = (req.url || '').split('?')[1] || '';
    const params = new URLSearchParams(query);
    let list = trailEntries.slice();
    const taskId = params.get('task_id');
    const decision = params.get('decision');
    const reasonCode = params.get('reason_code');
    if (taskId) list = list.filter((e) => e.task_id === taskId);
    if (decision) list = list.filter((e) => e.decision === decision);
    if (reasonCode) list = list.filter((e) => e.reason_code === reasonCode);
    const order = (params.get('order') || 'desc').toLowerCase();
    list.sort((a, b) => (order === 'asc' ? a.seq - b.seq : b.seq - a.seq));
    let limit = parseInt(params.get('limit') || '50', 10);
    if (!Number.isInteger(limit) || limit < 1) limit = 50;
    if (limit > MAX_DECISIONS_PAGE) limit = MAX_DECISIONS_PAGE;
    let offset = parseInt(params.get('offset') || '0', 10);
    if (!Number.isInteger(offset) || offset < 0) offset = 0;
    const page = list.slice(offset, offset + limit);
    sendJson(res, 200, { ok: true, total: list.length, count: page.length, entries: page }, false);
    return;
  }

  sendJson(res, 404, { ok: false, error: 'not_found' }, false);
}

const server = http.createServer((req, res) => {
  const urlPath = (req.url || '/').split('?')[0];

  // Monitoring lokal, tanpa signature.
  if (req.method === 'GET' && urlPath === '/health') {
    sendJson(res, 200, {
      ok: true,
      proofReady: PROVER !== null && PROOF_ENABLED && proofStatus.selfTest === 'ok',
      proofSelfTest: proofStatus,
    }, false);
    return;
  }

  // Jejak keputusan publik (tanpa signature): daftar, satu entri,
  // verifikasi satu entri, dan verifikasi rantai hash.
  if (req.method === 'GET' && (urlPath === '/agent/decisions' || urlPath.startsWith('/agent/decisions/'))) {
    handleDecisions(req, res, urlPath);
    return;
  }

  // Info singkat untuk GET di path utama.
  if (req.method === 'GET' && (urlPath === '/' || urlPath === '/agent')) {
    sendJson(res, 200, { ok: true, service: 'PipoZK', track: 'proof-gatekeeper' }, false);
    return;
  }

  // Hanya POST ke / atau /agent yang melayani tugas.
  if (req.method !== 'POST' || (urlPath !== '/' && urlPath !== '/agent')) {
    sendJson(res, 404, { ok: false, error: 'not_found' }, false);
    return;
  }

  const chunks = [];
  let size = 0;
  let tooLarge = false;
  req.on('data', (chunk) => {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) {
      tooLarge = true;
      return;
    }
    chunks.push(chunk);
  });
  req.on('end', () => {
    if (tooLarge) {
      sendJson(res, 413, { ok: false, error: 'body_too_large' }, false);
      return;
    }
    const rawBody = Buffer.concat(chunks);

    // Verifikasi signature terhadap raw body SEBELUM parse JSON.
    const received = req.headers['x-agent-games-signature'];
    if (!signaturesEqual(received, hmacHex(rawBody))) {
      log({ kind: 'auth', result: 'invalid_signature' });
      sendJson(res, 401, { ok: false, error: 'invalid_signature' }, false);
      return;
    }

    let body;
    try {
      body = JSON.parse(rawBody.toString('utf8'));
    } catch (err) {
      log({ kind: 'task', result: 'invalid_json' });
      sendJson(res, 400, { ok: false, error: 'invalid_json' }, true);
      return;
    }
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      log({ kind: 'task', result: 'invalid_json' });
      sendJson(res, 400, { ok: false, error: 'invalid_json' }, true);
      return;
    }

    handleTask(body, res).catch((err) => {
      log({ kind: 'task', result: 'handler_error', error: err.message });
      try {
        if (!res.headersSent) sendJson(res, 500, { ok: false, error: 'internal' }, false);
      } catch (e) { /* soket sudah tutup */ }
    });
  });
  req.on('error', () => {
    try { sendJson(res, 400, { ok: false, error: 'bad_request' }, false); } catch (e) { /* soket sudah tutup */ }
  });
});

loadTrail();

// Self-test proving sekali saat startup (async, tidak memblokir listen).
// Gagal self-test tidak menghentikan server: proof per tugas tetap
// dicoba, dan bila proving memang rusak tiap tugas jatuh ke fallback
// tanpa proof.
if (PROVER && PROOF_ENABLED) {
  PROVER.selfTest().then((r) => {
    proofStatus.selfTest = 'ok';
    proofStatus.proofMs = r.proofMs;
    log({ kind: 'prove', result: 'selftest_ok', proof_ms: r.proofMs });
  }).catch((err) => {
    proofStatus.selfTest = 'failed';
    proofStatus.error = err.message;
    console.error('[pipozk] self-test proving GAGAL: ' + err.message);
  });
}

server.listen(PORT, HOST, () => {
  console.log(`[pipozk] PipoZK jalan di http://${HOST}:${PORT} (secret fingerprint: ${SECRET_FINGERPRINT})`);
});
