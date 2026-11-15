'use strict';
/*
 * Seed demo decisions untuk jejak keputusan Wildcard.
 * Membaca secret HMAC dari file VPS, TIDAK PERNAH mencetak nilainya.
 * Tiap tugas memakai mode "self-test" supaya jelas ini keputusan demo,
 * bukan tugas platform. Dijalankan sekali sesudah deploy trail.
 *
 * Cara pakai (di VPS): node seed-decisions.js
 */

const https = require('https');
const crypto = require('crypto');
const fs = require('fs');

const SECRET = fs.readFileSync('/data/home/pipozk-agent/.hmac-secret', 'utf8').trim();
const HOST = 'agent.resver.web.id';

function baseInput(overrides) {
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
    proof_tx: null,
  }, overrides || {});
}

function task(taskId, inputOverrides, proofTx) {
  const input = baseInput(inputOverrides);
  input.proof_tx = proofTx;
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: taskId,
    mode: 'self-test',
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input,
  };
}

const tasks = [
  task('demo_approve_01', {}, '0xd1a0000000000000000000000000000000000000000000000000000000000001'),
  task('demo_vk_01', { proof_vk: '0x13aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' }, '0xd1a0000000000000000000000000000000000000000000000000000000000002'),
  task('demo_recipient_01', { condition_recipient: '0x9999999999999999999999999999999999999999' }, '0xd1a0000000000000000000000000000000000000000000000000000000000003'),
  task('demo_amount_01', { amount: '1500' }, '0xd1a0000000000000000000000000000000000000000000000000000000000004'),
  task('demo_balance_01', { public_balance: '500' }, '0xd1a0000000000000000000000000000000000000000000000000000000000005'),
];

function post(obj) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(obj);
    const sig = crypto.createHmac('sha256', Buffer.from(SECRET, 'utf8'))
      .update(Buffer.from(body, 'utf8')).digest('hex');
    const req = https.request({
      hostname: HOST, port: 443, path: '/agent', method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        'x-agent-games-signature': sig,
      },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

(async () => {
  for (const t of tasks) {
    const r = await post(t);
    let j = null;
    try { j = JSON.parse(r.body); } catch (e) { /* bukan JSON */ }
    console.log(`${t.task_id}: HTTP ${r.status} decision=${j ? j.decision : '?'} reason=${j ? j.reason_code : '?'}`);
  }
})();
