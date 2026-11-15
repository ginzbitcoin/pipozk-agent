# PipoZK: an auditable agent (Wildcard submission)

Agent Games Season 01, Wildcard track. Agent: PipoZK, account @lugartigre.
Live endpoint: https://agent.resver.web.id/agent
Repository: https://github.com/ginzbitcoin/pipozk-agent

## The problem

An agent's decision is a claim you have to trust. When an agent
approves a transfer or rejects a proof, nobody can check afterwards
whether it actually followed its own rules, or whether the answer
was invented after the fact. For agents that move value or judge
evidence, "trust me" is not good enough. Decisions need receipts.

## Who it helps

Anyone who has to rely on an agent's verdict: the platform that
receives the decision, the user whose request was approved or
rejected, and any third party auditing the agent later. In Agent
Games, that means the tournament organizers and other participants
can audit PipoZK's decisions instead of taking them on faith.

## What the agent does

PipoZK is a Proof Gatekeeper agent. The platform sends it a signed
task (a zero-knowledge proof claim: verification key, recipient,
amount, balance threshold, expiry block, proof reference). The agent
verifies the task signature, evaluates the claim against 10
deterministic fail-closed checks, and returns a signed decision
(APPROVE or REJECT with a reason code) within seconds.

The Wildcard addition is the decision trail. Every fresh decision
the agent makes is recorded in a public, tamper-evident log that
anyone can read and verify. The agent no longer just claims it
decided correctly; it shows its work, entry by entry.

## How the decision trail works

Each decision becomes one entry in an append-only JSONL file on the
agent host, served publicly at `GET /agent/decisions`:

- `seq`: monotonic sequence number, starting at 1.
- `task_id`, `mode`, `decision`, `reason_code`: what was decided.
- `checks`: the 10 checks with a result each (`pass`, `fail`, or
  `skipped`), derived from the reason code and the documented
  evaluation order. If the reason is `OK`, all checks passed.
- `proof_tx` and the full `input` of the task, so anyone can re-run
  the 10 checks against the stored input and confirm the decision.
- `input_hash`: SHA-256 of the canonical (key-sorted) input JSON.
- `prev_hash` and `entry_hash`: the entries form a hash chain. Each
  entry stores the hash of the previous entry, so editing or deleting
  an earlier entry breaks the chain. Anyone can check the chain
  without any secret.
- `signature`: HMAC-SHA256 of the entry hash, keyed by the agent
  secret. Only the agent (and the platform, which issued the secret)
  can produce a matching signature, so entries cannot be forged.
  The secret never leaves the server; the server verifies signatures
  on request through the `/verify` endpoint.
- `issued_at` and `decided_at`: when the task was issued and when
  the agent decided.

Public endpoints (no signature required, read-only):

- `GET /agent/decisions` : list entries, newest first.
  Filters: `?task_id=`, `?decision=`, `?reason_code=`,
  `?order=asc`, `?limit=`, `?offset=`.
- `GET /agent/decisions/<seq>` : one entry.
- `GET /agent/decisions/<seq>/verify` : re-checks one entry and
  reports `valid`, `hash_ok`, `sig_ok`, `chain_ok`.
- `GET /agent/decisions/chain` : checks the whole hash chain and
  reports `valid`, `count`, `head_seq`, `head_hash`.

Replays do not create new entries: a repeated `task_id` is answered
identically from cache, as the protocol requires. Preflight checks
are not decisions and are not recorded.

## How to verify one entry (checklist)

1. Fetch it: `GET /agent/decisions/<seq>`.
2. Re-run the 10 checks yourself against the stored `input`
   (rules are listed in the repository README). The stored
   `decision` and `reason_code` must match your result.
3. Recompute `input_hash`: SHA-256 of the canonical JSON of
   `input` (object keys sorted recursively). It must match.
4. Check the chain: `GET /agent/decisions/chain` must report
   `valid: true`, and the entry's `prev_hash` must equal the
   previous entry's `entry_hash`.
5. Check the signature: `GET /agent/decisions/<seq>/verify` must
   report `sig_ok: true`. The signature proves the entry was
   created by this agent; forging it would require the agent secret.

## Key decisions

- No external dependencies. The agent is one Node.js file using
  only built-in modules (`http`, `crypto`, `fs`, `path`), so the
  whole decision path is readable in one place.
- Fail closed. Any doubt or error while evaluating means REJECT,
  because approving a trap (-6) costs more than rejecting a valid
  request (-3).
- Deterministic and offline. Decisions come only from the task
  envelope; the agent makes no outbound network calls, so answers
  are instant and reproducible.
- Restart-safe. The decision log survives restarts, and the
  idempotency cache plus the used-proof set are rebuilt from the
  log on startup, so a restart mid-round cannot re-approve a proof
  that was already used.
- The trail never blocks the decision. If writing a trail entry
  fails, the decision is still answered; the failure is logged.

## zkVerify (optional)

PipoZK runs inside the zkVerify Agent Games context, and its
decisions are about zkVerify proofs: whether the proof's
verification key matches the registered key, and whether the proof
reference was already used. The trail makes those judgments
checkable, which is the verifiability layer on top of the proof
system itself.

Documented next step, not yet built: generate the real Groth16
proof locally (Circom 2.x, snarkjs, `gatekeeper.wasm` and
`gatekeeper_final.zkey` from `/api/circuit-info`), submit it to
zkVerify through Kurier, and wait for Finalized before returning
`proof_tx`. Today the agent returns `proof: null` and echoes the
incoming `proof_tx`, which the tournament rules penalize by 2
points per task. The decision trail is independent of that work
and already live.

## Status

Live on a VPS (Node 22, systemd service, Cloudflare Tunnel +
nginx, public HTTPS endpoint). Local test suite: 33 checks pass,
0 fail, covering the protocol, every trap, the decision trail
(hash chain, signatures, filters, verification endpoints), and
restart persistence. Run it with `node test-agent.js`.

## Links

- Repository: https://github.com/ginzbitcoin/pipozk-agent
- Live endpoint: https://agent.resver.web.id/agent
- Decision trail: https://agent.resver.web.id/agent/decisions
- Chain check: https://agent.resver.web.id/agent/decisions/chain
- Agent Games docs used: https://agentgames.zkverify.io/build,
  https://agentgames.zkverify.io/guide,
  https://agentgames.zkverify.io/rules
