import { describe, expect, it } from 'vitest';
import { Wallet } from 'ethers';
import { envelopeHash, verifyPayloadBinding, type MutationEnvelope } from '../src/envelope';
import { computePayloadHash } from '../src/canonical';
import { verifyEnvelopeSignature } from '../src/signature';

const payload = { rule: 'x', value: 1 };
const mk = (over: Partial<MutationEnvelope> = {}): MutationEnvelope => ({
  artifactId: 'a1',
  artifactType: 'CONFIG',
  payloadHash: computePayloadHash(payload),
  actorId: 'actor',
  nonce: 1,
  timestamp: '2026-01-01T00:00:00.000Z',
  ...over,
});

describe('envelope + signature', () => {
  const wallet = Wallet.createRandom();
  const trusted = new Set([wallet.address.toLowerCase()]);

  it('accepts a trusted signature', async () => {
    const sig = await wallet.signMessage(envelopeHash(mk()));
    expect(verifyEnvelopeSignature(envelopeHash(mk()), sig, trusted).ok).toBe(true);
  });
  it('rejects an untrusted signer', async () => {
    const other = Wallet.createRandom();
    const sig = await other.signMessage(envelopeHash(mk()));
    expect(verifyEnvelopeSignature(envelopeHash(mk()), sig, trusted).ok).toBe(false);
  });
  it('signature does not transfer to a different artifact or nonce', async () => {
    const sig = await wallet.signMessage(envelopeHash(mk()));
    expect(verifyEnvelopeSignature(envelopeHash(mk({ artifactId: 'a2' })), sig, trusted).ok).toBe(false);
    expect(verifyEnvelopeSignature(envelopeHash(mk({ nonce: 2 })), sig, trusted).ok).toBe(false);
  });
  it('rejects a malformed signature', () => {
    expect(verifyEnvelopeSignature(envelopeHash(mk()), '0xdead', trusted).ok).toBe(false);
  });
  it('detects a tampered payload', () => {
    expect(verifyPayloadBinding({ ...payload, value: 2 }, mk()).ok).toBe(false);
    expect(verifyPayloadBinding(payload, mk()).ok).toBe(true);
  });
});
