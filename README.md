# mutation-firewall

Deterministic hash-integrity layer for a single write gateway.

## Modules
- `canonical.ts`: strict canonical JSON (NFC, sorted keys, rejects non-plain types), SHA-256, constant-time compare
- `envelope.ts`: signed mutation envelope (binds payload hash, artifact, actor, nonce, timestamp)
- `signature.ts`: EIP-191 signature verification against a trusted address set
- `log.ts`: append-only hash-chained log with `verifyChain()`
- `mutation-firewall.ts`: prioritized mutation rules and deterministic evaluation

## Design decisions
- `-0` is normalized to `0`.
- Time is never read internally; timestamps are injected.
- Actors sign the envelope hash, not the bare payload hash.

## Not yet implemented
- `MutationFirewall.write()` gateway (allowlist, nonce tracking, fail-closed log write)
- Proposal queue and `approve()` for governance/routing changes
- Persistent log storage
- Authenticated actor identity

## Run
```
npm install
npm test
```
