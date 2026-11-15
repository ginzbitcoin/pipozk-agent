# PipoZK

Agen Proof Gatekeeper untuk Agent Games (zkVerify), akun lugartigre.
Track: Proof Gatekeeper saja. Status: MVP, sudah lolos tes lokal,
sudah di-deploy di VPS (endpoint https://agent.resver.web.id/agent),
belum lolos preflight platform. Tambahan Wildcard: jejak keputusan
yang bisa diverifikasi (lihat `WILDCARD.md`).

## Cara kerja singkat

Platform mengirim tugas JSON bertanda tangan ke endpoint publik agen.
Agen memverifikasi signature HMAC, menilai tugas dengan aturan
deterministik, lalu mengembalikan keputusan bertanda tangan.
Platform tidak pernah menjalankan kode ini; agen harus di-host sendiri
di alamat HTTPS publik.

Dokumen resmi yang dipakai: https://agentgames.zkverify.io/build,
https://agentgames.zkverify.io/guide, https://agentgames.zkverify.io/rules
(dibaca 15 Nov 2026). Bila dokumen resmi berubah, dokumen resmi yang menang.

## Menjalankan

Tanpa dependensi npm, hanya modul bawaan Node.js (`http`, `crypto`, `fs`).
Node 18 ke atas cukup (diuji di Node 24, target deploy Node 22).

```sh
AGENT_GAMES_HMAC_SECRET="<secret dari dashboard>" node agent.js
```

Atau secret dari file (mode 600, satu baris):

```sh
AGENT_GAMES_HMAC_SECRET_FILE="$HOME/.pipozk/hmac-secret" node agent.js
```

Server bind `127.0.0.1`, port dari env `PORT` (default 8741).
Di belakang reverse proxy atau tunnel HTTPS, daftarkan path lengkap
sebagai endpoint di dashboard, contoh `https://host/agent`.
Platform menulis di /build: daftarkan path handler penuh, bukan root
saja, dan tanpa custom port. Secret yang dipakai dicetak sebagai
sidik jari pendek (8 karakter pertama SHA-256) saat startup, bukan
nilainya, supaya bisa dipastikan secret yang dipakai sudah benar.

## Variabel env

- `PORT`: port listen, default 8741.
- `HOST`: alamat bind, default 127.0.0.1.
- `AGENT_GAMES_HMAC_SECRET`: secret HMAC dari dashboard (Rotate Secret).
  Diambil dari env ini dulu bila ada.
- `AGENT_GAMES_HMAC_SECRET_FILE`: path file berisi secret (satu baris,
  whitespace ujung dibuang). Dipakai bila env secret tidak diisi.
  Bila secret tidak ada di keduanya, server berhenti dengan pesan error.

## Endpoint

- `POST /` dan `POST /agent`: menerima tugas platform. Keduanya
  dilayani supaya endpoint terdaftar apa pun bentuknya tetap jalan.
- `GET /health`: `{ ok: true }`, tanpa signature, untuk monitoring lokal.
- `GET /` dan `GET /agent`: info singkat `{ ok, service, track }`.
- `GET /agent/decisions`: daftar jejak keputusan publik, tanpa
  signature. Filter: `?task_id=`, `?decision=`, `?reason_code=`,
  `?order=asc`, `?limit=`, `?offset=`.
- `GET /agent/decisions/<seq>`: satu entri jejak.
- `GET /agent/decisions/<seq>/verify`: verifikasi satu entri
  (`valid`, `hash_ok`, `sig_ok`, `chain_ok`).
- `GET /agent/decisions/chain`: verifikasi seluruh rantai hash.

## Skema protokol (dari /build)

Preflight, request dari platform:

```json
{ "type": "agent-games.preflight.v1", "agent_id": "agt_...", "issued_at": "", "nonce": "abc123" }
```

Preflight, respons agen (bertanda tangan):

```json
{ "ok": true, "protocolVersion": "v1" }
```

Task Gatekeeper, request dari platform:

```json
{
  "type": "agent-games.proof-gatekeeper.v1",
  "task_id": "gk_8d31_...",
  "mode": "competition",
  "issued_at": "",
  "deadline_at": "",
  "input": {
    "registered_vk": "0x7d...91",
    "proof_vk": "0x13...aa",
    "minimum": "1000",
    "public_balance": "1460",
    "expiry_block": 8430000,
    "current_block": 8420000,
    "recipient": "0xDe42...9f01",
    "condition_recipient": "0xDe42...9f01",
    "amount": "500",
    "max_transfer": "1000",
    "proof_tx": "0xa8...2c"
  }
}
```

Task Gatekeeper, respons agen (bertanda tangan):

```json
{ "decision": "REJECT", "reason_code": "VK_SUBSTITUTION", "proof": null, "public_signals": null, "proof_tx": "0xa8...2c" }
```

Signature: header `x-agent-games-signature`, HMAC-SHA256 (hex) dari
raw body. Agen memverifikasi signature request sebelum parse JSON,
dan menandatangani tiap respons sukses dengan cara yang sama.
Batas respons 60 detik. Kiriman ulang `task_id` yang sama harus
dijawab identik (idempotency key).

## Aturan keputusan

APPROVE hanya bila semua cek lolos, sesuai urutan ini. Satu cek gagal
berarti REJECT dengan reason_code cek itu. Fail closed: ragu atau
error saat menilai berarti REJECT.

1. `INVALID_INPUT`: envelope atau input tidak lengkap, atau ada angka
   yang tidak bisa dibaca.
2. `VK_SUBSTITUTION`: `proof_vk` tidak sama dengan `registered_vk`.
   Ini satu-satunya reason_code yang tertulis di dokumen resmi
   (contoh respons di /build). Kode lain di bawah ini adalah nama
   deskriptif buatan kami.
3. `RECIPIENT_MISMATCH`: `recipient` tidak sama dengan
   `condition_recipient`.
4. `AMOUNT_EXCEEDS_LIMIT`: `amount` melebihi `max_transfer`, atau
   `amount` tidak positif.
5. `INSUFFICIENT_BALANCE`: `public_balance` di bawah `minimum`.
6. `EXPIRED`: `current_block` sudah mencapai atau melewati
   `expiry_block`.
7. `TASK_EXPIRED`: `deadline_at` sudah lewat.
8. `PROOF_REUSED`: `proof_tx` yang sama sudah dipakai di `task_id`
   lain. Kiriman ulang `task_id` yang sama bukan reuse, jawabannya
   dikembalikan identik dari cache.
9. `INTERNAL_ERROR`: error apa pun saat menilai (fail closed).
10. APPROVE memakai `reason_code` `OK`.

Skor per /build: keputusan benar +12, menyetujui jebakan -6, menolak
request valid -3, timeout/offline -2, proof tidak lolos verifikasi -2,
plus bonus reliabilitas. Karena menyetujui jebakan lebih mahal
daripada menolak yang valid, aturan di sini condong ketat.

Catatan: dokumen resmi tidak memuat daftar jebakan bernama dan tidak
memuat daftar reason_code lengkap. Cek di atas diturunkan dari
field-field envelope tugas dan Security checklist di /build.

## Jejak keputusan yang bisa diverifikasi (Wildcard)

Tiap keputusan baru dicatat sebagai satu entri jejak yang bisa dicek
publik, supaya klaim agen bisa diaudit, bukan sekadar dipercaya.
Detail lengkap + cara verifikasi untuk panel ada di `WILDCARD.md`.

- Entri disimpan append-only di file JSONL (`DECISIONS_FILE`,
  default `decisions.jsonl` di folder program), jadi jejak selamat
  dari restart server.
- Entri dirangkai hash chain (`prev_hash` + `entry_hash`): mengubah
  atau menghapus entri lama merusak rantai, dan siapa pun bisa
  memeriksanya tanpa secret lewat `GET /agent/decisions/chain`.
- Entri ditandatangani HMAC-SHA256 dengan secret agen (tanda tangan
  atas `entry_hash`); hanya pemegang secret yang bisa membuatnya,
  jadi entri tidak bisa dipalsukan. Verifikasi tanda tangan lewat
  `GET /agent/decisions/<seq>/verify` (secret tidak pernah keluar
  dari server).
- Entri menyimpan input lengkap tugas + daftar 10 cek (`pass`,
  `fail`, `skipped`) yang diturunkan dari `reason_code`, jadi siapa
  pun bisa menjalankan ulang ceknya dan memastikan keputusan yang
  tercatat sudah benar.
- Kiriman ulang `task_id` yang sama TIDAK membuat entri baru
  (idempotent). Preflight bukan keputusan, tidak dicatat.
- Saat startup, cache idempotensi + proof terpakai dibangun ulang
  dari file jejak, jadi restart di tengah ronde tidak mengulang
  penilaian.

Variabel env tambahan: `DECISIONS_FILE` (path file jejak, default
`decisions.jsonl` di folder program).

## Batasan MVP

- `proof` dan `public_signals` selalu null: pembuktian Groth16
  (Circom 2.x, snarkjs, artefak `gatekeeper.wasm` dan
  `gatekeeper_final.zkey`) belum dibangun. Per /build, bukti yang
  dihilangkan atau tidak valid dikenai -2 per task. Jadi MVP ini
  bisa lolos preflight dan menjawab decide, tapi skor per task
  kemungkinan terpotong 2 poin sampai proof dibangun.
- `proof_tx` hanya menggemakan pointer dari tugas masuk, bukan bukti
  submisi on-chain.
- Tidak ada verifikasi on-chain (tidak ada panggilan jaringan keluar):
  finalisasi proof dan status proof_tx di chain tidak dicek. Cek
  `expiry_block` dari envelope adalah proksi yang tersedia.
- Cache idempotensi dan proof terpakai dibangun ulang dari file
  jejak saat startup (lihat seksi jejak keputusan di atas), jadi
  restart di tengah ronde tidak mengulang penilaian.
- Tidak ada rate limit masuk dan tidak ada autentikasi selain HMAC:
  endpoint harus selalu di belakang HTTPS dan tidak diekspos langsung
  tanpa reverse proxy atau tunnel.

Langkah lanjut sesudah MVP: unduh artefak circuit dari
`/api/circuit-info` (vkHash Gatekeeper
`0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`),
bangun proof Groth16 lokal dengan snarkjs, lalu submit ke zkVerify
lewat Kurier dan tunggu Finalized sebelum mengembalikan `proof_tx`.

## Cara tes

```sh
node test-agent.js
```

Tes menjalankan server di port 18741 dengan secret uji, lalu
memeriksa 33 kasus: health, preflight (tanda tangan valid, tanpa
signature, signature salah), decide valid (APPROVE), tiap jebakan
(VK, penerima, jumlah, saldo, blok kedaluwarsa, proof dipakai ulang),
retry task_id sama (idempotent), type tidak dikenal, path root, dan
JSON rusak; lalu jejak keputusan (daftar 8 entri, isi entri pertama,
verifikasi satu entri, rantai hash, filter, 404); lalu persistensi
restart (jejak tetap 8, proof terpakai tetap ditolak, retry tetap
idempotent, jejak jadi 9, rantai tetap valid). Semua harus PASS;
hasil terakhir: 33 lolos, 0 gagal (15 Nov 2026).

## Keamanan secret

- Secret hanya dibaca dari env atau file yang ditunjuk env.
- Secret tidak pernah ditulis ke log, respons, atau file apa pun.
- Jangan commit file `.env` atau file berisi secret apa pun.
  `.gitignore` sudah menutup `.env`, `*secret*`, dan `node_modules`.
- Bila secret bocor, putar dari dashboard (Rotate Secret): secret
  lama langsung berhenti berlaku, lalu isi secret baru dan restart
  agen.
