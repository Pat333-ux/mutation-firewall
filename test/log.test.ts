import { describe, expect, it } from 'vitest';
import { HashChainLog, GENESIS_HASH, verifyChain } from '../src/log';

const fields = (n: number) => ({
  mutationId: `m${n}`,
  decision: 'ACCEPT' as const,
  actorId: 'actor',
  artifactType: 'CONFIG',
  reason: 'ok',
  payloadHash: 'p'.repeat(64),
  envelopeHash: 'e'.repeat(64),
  timestamp: '2026-01-01T00:00:00.000Z',
});

const build = () => {
  const log = new HashChainLog();
  for (let i = 0; i < 3; i++) log.append(fields(i));
  return log;
};

describe('HashChainLog', () => {
  it('starts at genesis', () => {
    expect(build().snapshot()[0]!.previousLogHash).toBe(GENESIS_HASH);
  });
  it('is deterministic: same history gives identical hashes', () => {
    expect(build().snapshot()).toEqual(build().snapshot());
  });
  it('verifies an intact chain', () => {
    expect(build().verify()).toBe(-1);
  });
  it('detects an edited entry', () => {
    const s = build().snapshot();
    s[1]!.reason = 'tampered';
    expect(verifyChain(s)).toBe(1);
  });
  it('detects a removed entry', () => {
    const s = build().snapshot();
    s.splice(1, 1);
    expect(verifyChain(s)).not.toBe(-1);
  });
});
