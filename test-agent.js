'use strict';
/*
 * Test harness lokal untuk agent.js. Tanpa dependensi npm.
 *
 * Menjalankan server dengan secret uji, lalu mengirim rangkaian
 * request dan memeriksa responsnya. Keluar dengan kode 0 bila semua
 * tes lolos, 1 bila ada yang gagal.
 *
 * Cara pakai: node test-agent.js
 */

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const { spawn } = require('child_process');
const path = require('path');

const TEST_PORT = 18741;
const TEST_SECRET = 'test-secret-pipozk-jangan-dipakai-di-produksi';
const TRAIL_FILE = path.join(__dirname, 'test-decisions.jsonl');
const BASE = `http://127.0.0.1:${TEST_PORT}`;

let passed = 0;
let failed = 0;

function check(name, condition, detail) {
  if (condition) {
    passed += 1;
    console.log(`PASS ${name}`);
  } else {
    failed += 1;
    console.log(`FAIL ${name}${detail ? ` - ${detail}` : ''}`);
  }
}

function sign(bodyString) {
  return crypto.createHmac('sha256', Buffer.from(TEST_SECRET, 'utf8'))
    .update(Buffer.from(bodyString, 'utf8')).digest('hex');
}

function verifyResponseSignature(bodyString, signature) {
  if (typeof signature !== 'string' || !signature) return false;
  const a = Buffer.from(signature.trim().toLowerCase(), 'utf8');
  const b = Buffer.from(sign(bodyString).trim().toLowerCase(), 'utf8');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function request(method, pathName, bodyString, headers) {
  return new Promise((resolve, reject) => {
    const req = http.request(BASE + pathName, {
      method,
      headers: Object.assign({ 'Content-Type': 'application/json' }, headers || {}),
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = JSON.parse(raw); } catch (e) { /* bukan JSON */ }
        resolve({ status: res.statusCode, headers: res.headers, raw, json });
      });
    });
    req.on('error', reject);
    if (bodyString) req.write(bodyString);
    req.end();
  });
}

function postSigned(pathName, obj, secretOverride) {
  const bodyString = JSON.stringify(obj);
  const secret = secretOverride === undefined ? TEST_SECRET : secretOverride;
  const sig = secret === null ? undefined
    : crypto.createHmac('sha256', Buffer.from(secret, 'utf8'))
      .update(Buffer.from(bodyString, 'utf8')).digest('hex');
  const headers = {};
  if (sig) headers['x-agent-games-signature'] = sig;
  return request('POST', pathName, bodyString, headers);
}

function validInput(overrides) {
  return Object.assign({
    registered_vk: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
    proof_vk: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
    minimum: '1000',
    public_balance: '1460',
    expiry_block: 8430000,
    current_block: 8420000,
    recipient: '0xDe42a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2',
    condition_recipient: '0xDe42a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2',
    amount: '500',
    max_transfer: '1000',
    proof_tx: '0xa8b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a',
  }, overrides || {});
}

function validTask(taskId, inputOverrides) {
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: taskId,
    mode: 'competition',
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: validInput(inputOverrides),
  };
}

function waitForHealth(tries) {
  return new Promise((resolve) => {
    const attempt = (n) => {
      request('GET', '/health', null, {}).then((r) => {
        if (r.status === 200 && r.json && r.json.ok === true) return resolve(true);
        if (n <= 0) return resolve(false);
        setTimeout(() => attempt(n - 1), 200);
      }).catch(() => {
        if (n <= 0) return resolve(false);
        setTimeout(() => attempt(n - 1), 200);
      });
    };
    attempt(tries);
  });
}

async function runTests() {
  // 1. Health check tanpa signature.
  let r = await request('GET', '/health', null, {});
  check('GET /health 200 {ok:true}', r.status === 200 && r.json && r.json.ok === true, JSON.stringify(r.json));

  // 2. Preflight bertanda tangan.
  const preflight = { type: 'agent-games.preflight.v1', agent_id: 'agt_test', issued_at: new Date().toISOString(), nonce: 'abc123' };
  r = await postSigned('/agent', preflight);
  check('preflight 200 {ok:true, protocolVersion:"v1"}',
    r.status === 200 && r.json && r.json.ok === true && r.json.protocolVersion === 'v1',
    `status=${r.status} body=${r.raw}`);
  check('preflight signature respons valid',
    verifyResponseSignature(r.raw, r.headers['x-agent-games-signature']),
    'signature tidak cocok');

  // 3. Preflight tanpa signature -> 401.
  r = await postSigned('/agent', preflight, null);
  check('preflight tanpa signature -> 401 invalid_signature',
    r.status === 401 && r.json && r.json.error === 'invalid_signature',
    `status=${r.status} body=${r.raw}`);

  // 4. Preflight dengan signature salah -> 401.
  r = await postSigned('/agent', preflight, 'secret-salah');
  check('preflight signature salah -> 401 invalid_signature',
    r.status === 401 && r.json && r.json.error === 'invalid_signature',
    `status=${r.status} body=${r.raw}`);

  // 5. Decide valid -> APPROVE, proof null, signature valid.
  r = await postSigned('/agent', validTask('gk_test_01'));
  check('decide valid -> APPROVE',
    r.status === 200 && r.json && r.json.decision === 'APPROVE' && r.json.reason_code === 'OK',
    `status=${r.status} body=${r.raw}`);
  check('decide valid -> proof null, public_signals null, proof_tx digemakan',
    r.json && r.json.proof === null && r.json.public_signals === null
    && typeof r.json.proof_tx === 'string' && r.json.proof_tx.startsWith('0xa8b3'),
    `body=${r.raw}`);
  check('decide valid signature respons valid',
    verifyResponseSignature(r.raw, r.headers['x-agent-games-signature']),
    'signature tidak cocok');

  // 6. VK substitution -> REJECT VK_SUBSTITUTION.
  r = await postSigned('/agent', validTask('gk_test_02', { proof_vk: '0x13aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' }));
  check('decide VK beda -> REJECT VK_SUBSTITUTION',
    r.status === 200 && r.json && r.json.decision === 'REJECT' && r.json.reason_code === 'VK_SUBSTITUTION',
    `status=${r.status} body=${r.raw}`);

  // 7. Penerima beda -> REJECT RECIPIENT_MISMATCH.
  r = await postSigned('/agent', validTask('gk_test_03', { condition_recipient: '0x9999999999999999999999999999999999999999' }));
  check('decide penerima beda -> REJECT RECIPIENT_MISMATCH',
    r.status === 200 && r.json && r.json.decision === 'REJECT' && r.json.reason_code === 'RECIPIENT_MISMATCH',
    `status=${r.status} body=${r.raw}`);

  // 8. Jumlah melebihi batas -> REJECT AMOUNT_EXCEEDS_LIMIT.
  r = await postSigned('/agent', validTask('gk_test_04', { amount: '1500' }));
  check('decide amount > max -> REJECT AMOUNT_EXCEEDS_LIMIT',
    r.status === 200 && r.json && r.json.decision === 'REJECT' && r.json.reason_code === 'AMOUNT_EXCEEDS_LIMIT',
    `status=${r.status} body=${r.raw}`);

  // 9. Saldo di bawah minimum -> REJECT INSUFFICIENT_BALANCE.
  r = await postSigned('/agent', validTask('gk_test_05', { public_balance: '500' }));
  check('decide saldo < minimum -> REJECT INSUFFICIENT_BALANCE',
    r.status === 200 && r.json && r.json.decision === 'REJECT' && r.json.reason_code === 'INSUFFICIENT_BALANCE',
    `status=${r.status} body=${r.raw}`);

  // 10. Blok kedaluwarsa -> REJECT EXPIRED.
  r = await postSigned('/agent', validTask('gk_test_06', { current_block: 8430000 }));
  check('decide blok kedaluwarsa -> REJECT EXPIRED',
    r.status === 200 && r.json && r.json.decision === 'REJECT' && r.json.reason_code === 'EXPIRED',
    `status=${r.status} body=${r.raw}`);

  // 11a. Proof dipakai ulang di task lain -> REJECT PROOF_REUSED.
  // proof_tx sama dengan tes 5 (gk_test_01), task_id berbeda.
  r = await postSigned('/agent', validTask('gk_test_07'));
  check('decide proof dipakai ulang -> REJECT PROOF_REUSED',
    r.status === 200 && r.json && r.json.decision === 'REJECT' && r.json.reason_code === 'PROOF_REUSED',
    `status=${r.status} body=${r.raw}`);

  // 11b. Kiriman ulang task_id yang sama -> jawaban identik (APPROVE), bukan reuse.
  r = await postSigned('/agent', validTask('gk_test_01'));
  check('retry task_id sama -> APPROVE lagi (idempotent)',
    r.status === 200 && r.json && r.json.decision === 'APPROVE' && r.json.reason_code === 'OK',
    `status=${r.status} body=${r.raw}`);

  // 12. Type tidak dikenal -> 400 unknown_task.
  r = await postSigned('/agent', { type: 'agent-games.apa-ini.v9', task_id: 'gk_test_08' });
  check('type tidak dikenal -> 400 unknown_task',
    r.status === 400 && r.json && r.json.error === 'unknown_task',
    `status=${r.status} body=${r.raw}`);

  // 13. Path root / juga melayani tugas. proof_tx dibedakan dari tes 5
  // supaya tidak kena aturan PROOF_REUSED.
  r = await postSigned('/', validTask('gk_test_09', { proof_tx: '0xb9c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091b' }));
  check('POST / decide valid -> APPROVE',
    r.status === 200 && r.json && r.json.decision === 'APPROVE',
    `status=${r.status} body=${r.raw}`);

  // 14. JSON rusak dengan signature valid atas raw body -> 400 invalid_json.
  const broken = '{"type": "agent-games.preflight.v1",';
  const sig = crypto.createHmac('sha256', Buffer.from(TEST_SECRET, 'utf8'))
    .update(Buffer.from(broken, 'utf8')).digest('hex');
  r = await request('POST', '/agent', broken, { 'x-agent-games-signature': sig });
  check('JSON rusak -> 400 invalid_json',
    r.status === 400 && r.json && r.json.error === 'invalid_json',
    `status=${r.status} body=${r.raw}`);

  console.log(`\nHasil: ${passed} lolos, ${failed} gagal.`);
  return failed === 0;
}

async function runTrailTests() {
  // Fase A membuat 8 keputusan baru (01, 02, 03, 04, 05, 06, 07, 09).
  // Kiriman ulang 11b dan preflight tidak tercatat.
  let r = await request('GET', '/agent/decisions', null, {});
  check('trail daftar total 8 entri',
    r.status === 200 && r.json && r.json.total === 8 && r.json.count === 8,
    `status=${r.status} body=${r.raw.slice(0, 200)}`);

  r = await request('GET', '/agent/decisions?order=asc&limit=1', null, {});
  const first = r.json && r.json.entries && r.json.entries[0];
  check('trail entri pertama seq 1 APPROVE OK prev_hash genesis',
    first && first.seq === 1 && first.decision === 'APPROVE' && first.reason_code === 'OK'
    && first.prev_hash === '0'.repeat(64),
    `body=${r.raw.slice(0, 300)}`);
  check('trail entri pertama signature 64 hex + input_hash 64 hex',
    first && /^[0-9a-f]{64}$/.test(first.signature || '')
    && /^[0-9a-f]{64}$/.test(first.input_hash || ''),
    `sig=${first && first.signature} input_hash=${first && first.input_hash}`);
  check('trail APPROVE semua cek pass',
    first && Array.isArray(first.checks) && first.checks.length === 9
    && first.checks.every((c) => c.result === 'pass'),
    `checks=${JSON.stringify(first && first.checks)}`);

  r = await request('GET', '/agent/decisions/3', null, {});
  check('trail entri 3 REJECT RECIPIENT_MISMATCH, cek 1-2 pass, 3 fail, sisanya skipped',
    r.status === 200 && r.json && r.json.entry && r.json.entry.task_id === 'gk_test_03'
    && r.json.entry.decision === 'REJECT' && r.json.entry.reason_code === 'RECIPIENT_MISMATCH'
    && r.json.entry.checks[0].result === 'pass' && r.json.entry.checks[1].result === 'pass'
    && r.json.entry.checks[2].result === 'fail' && r.json.entry.checks[3].result === 'skipped',
    `body=${r.raw.slice(0, 300)}`);

  r = await request('GET', '/agent/decisions/2/verify', null, {});
  check('trail verify entri 2 valid (hash + signature + rantai)',
    r.status === 200 && r.json && r.json.valid === true
    && r.json.hash_ok === true && r.json.sig_ok === true && r.json.chain_ok === true,
    `body=${r.raw.slice(0, 200)}`);

  r = await request('GET', '/agent/decisions/chain', null, {});
  check('trail chain valid, count 8',
    r.status === 200 && r.json && r.json.valid === true && r.json.count === 8,
    `body=${r.raw.slice(0, 200)}`);

  r = await request('GET', '/agent/decisions?decision=REJECT', null, {});
  check('trail filter decision=REJECT count 6',
    r.status === 200 && r.json && r.json.total === 6,
    `body=${r.raw.slice(0, 200)}`);

  r = await request('GET', '/agent/decisions?task_id=gk_test_05', null, {});
  check('trail filter task_id=gk_test_05 satu entri INSUFFICIENT_BALANCE',
    r.status === 200 && r.json && r.json.total === 1
    && r.json.entries[0].reason_code === 'INSUFFICIENT_BALANCE',
    `body=${r.raw.slice(0, 200)}`);

  r = await request('GET', '/agent/decisions/999', null, {});
  check('trail entri tidak ada -> 404 not_found',
    r.status === 404 && r.json && r.json.error === 'not_found',
    `status=${r.status} body=${r.raw}`);

  console.log(`\nHasil trail: ${passed} lolos, ${failed} gagal.`);
  return failed === 0;
}

async function runRestartTests() {
  // Jejak selamat dari restart, cache idempotensi + proof terpakai
  // dibangun ulang dari file jejak.
  let r = await request('GET', '/agent/decisions', null, {});
  check('restart trail total tetap 8',
    r.status === 200 && r.json && r.json.total === 8,
    `status=${r.status} body=${r.raw.slice(0, 200)}`);

  // proof_tx gk_test_01 dipakai di task baru -> tetap PROOF_REUSED.
  r = await postSigned('/agent', validTask('gk_test_10'));
  check('restart proof dipakai ulang -> REJECT PROOF_REUSED',
    r.status === 200 && r.json && r.json.decision === 'REJECT' && r.json.reason_code === 'PROOF_REUSED',
    `status=${r.status} body=${r.raw}`);

  // Kiriman ulang gk_test_01 -> APPROVE dari cache yang dibangun ulang.
  r = await postSigned('/agent', validTask('gk_test_01'));
  check('restart retry task_id sama -> APPROVE lagi (idempotent)',
    r.status === 200 && r.json && r.json.decision === 'APPROVE' && r.json.reason_code === 'OK',
    `status=${r.status} body=${r.raw}`);

  // Keputusan baru di fase restart tercatat, kiriman ulang tidak.
  r = await request('GET', '/agent/decisions', null, {});
  check('restart trail total jadi 9 (satu keputusan baru)',
    r.status === 200 && r.json && r.json.total === 9,
    `status=${r.status} body=${r.raw.slice(0, 200)}`);

  r = await request('GET', '/agent/decisions/chain', null, {});
  check('restart chain tetap valid, count 9',
    r.status === 200 && r.json && r.json.valid === true && r.json.count === 9,
    `body=${r.raw.slice(0, 200)}`);

  console.log(`\nHasil restart: ${passed} lolos, ${failed} gagal.`);
  return failed === 0;
}

function startServer() {
  const child = spawn(process.execPath, [path.join(__dirname, 'agent.js')], {
    env: Object.assign({}, process.env, {
      PORT: String(TEST_PORT),
      HOST: '127.0.0.1',
      AGENT_GAMES_HMAC_SECRET: TEST_SECRET,
      DECISIONS_FILE: TRAIL_FILE,
    }),
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', (d) => process.stdout.write(`[server] ${d}`));
  child.stderr.on('data', (d) => process.stdout.write(`[server:err] ${d}`));
  return child;
}

async function main() {
  try { fs.unlinkSync(TRAIL_FILE); } catch (e) { /* belum ada */ }

  let child = startServer();
  let ready = await waitForHealth(25);
  if (!ready) {
    console.log('FAIL server tidak siap dalam 5 detik');
    child.kill();
    process.exit(1);
  }

  let ok = false;
  try {
    ok = await runTests();
    if (ok) ok = await runTrailTests();
  } catch (err) {
    console.log(`FAIL error saat tes: ${err.message}`);
  }
  child.kill();

  if (ok) {
    child = startServer();
    ready = await waitForHealth(25);
    if (!ready) {
      console.log('FAIL server restart tidak siap dalam 5 detik');
      child.kill();
      process.exit(1);
    }
    try {
      ok = await runRestartTests();
    } catch (err) {
      console.log(`FAIL error saat tes restart: ${err.message}`);
    }
    child.kill();
  }

  try { fs.unlinkSync(TRAIL_FILE); } catch (e) { /* sudah bersih */ }
  process.exit(ok ? 0 : 1);
}

main();
