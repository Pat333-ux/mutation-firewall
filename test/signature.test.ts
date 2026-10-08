import { describe, expect, it } from 'vitest';
import { Wallet } from 'ethers';
import { envelopeHash, verifyPayloadBinding, type MutationEnvelope } from '../src/envelope';
import { computePayloadHash } from '../src/canonical';
import {
  canonicalSign,
  sign,
  verify,
  verifyCanonical,
  verifyEnvelopeSignature,
} from '../src/signature';

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

  describe('canonical signatures', () => {
    it('produces stable signatures for equivalent object key order', async () => {
      const first = await sign({ b: 2, a: 1 });
      const second = await sign({ a: 1, b: 2 });

      expect(first.signature).toBe(second.signature);
      expect(first.envelope.canonical).toBe('{"a":1,"b":2}');
    });

    it('signs and verifies with HMAC', async () => {
      const result = await sign({ action: 'write' }, 'secret-key');

      expect(result.envelope.algorithm).toBe('SHA256-HMAC');
      expect(result.envelope.keyId).toBe('default');
      expect((await verify({ action: 'write' }, result.signature, 'secret-key')).valid).toBe(true);
      expect((await verify({ action: 'write' }, result.signature, 'wrong-key')).valid).toBe(false);
    });

    it('requires a key for HMAC and rejects modified payloads', async () => {
      await expect(
        canonicalSign({}, { algorithm: 'SHA256-HMAC' }),
      ).rejects.toThrow('SHA256-HMAC requires a key.');

      const result = await canonicalSign(
        { value: 1 },
        { algorithm: 'SHA256-HASH' },
      );
      expect(
        (await verifyCanonical(
          { value: 2 },
          result.signature,
          { algorithm: 'SHA256-HASH' },
        )).valid,
      ).toBe(false);
    });
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
