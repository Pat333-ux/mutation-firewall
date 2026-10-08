import { describe, expect, it } from 'vitest';
import { canonicalize, sha256, safeEqualHex, computePayloadHash } from '../src/canonical';

describe('canonicalize test vectors', () => {
  it('sorts keys recursively', () => {
    expect(canonicalize({ b: 1, a: { d: 2, c: 3 } })).toBe('{"a":{"c":3,"d":2},"b":1}');
  });
  it('preserves array order', () => {
    expect(canonicalize([{ b: 1, a: 2 }, 3, 'x'])).toBe('[{"a":2,"b":1},3,"x"]');
  });
  it('normalizes unicode to NFC', () => {
    expect(canonicalize('e\u0301')).toBe(canonicalize('\u00e9'));
  });
  it('normalizes -0 to 0', () => {
    expect(canonicalize(-0)).toBe('0');
  });
  it('rejects non-finite numbers', () => {
    for (const n of [NaN, Infinity, -Infinity]) expect(() => canonicalize(n)).toThrow();
  });
  it('rejects unsupported types', () => {
    const bad: unknown[] = [undefined, () => 1, Symbol('s'), 10n, new Date(0), new Map(), new Set(), new (class A {})()];
    for (const b of bad) expect(() => canonicalize(b)).toThrow();
    expect(() => canonicalize({ a: undefined })).toThrow();
  });
  it('rejects keys colliding after NFC', () => {
    expect(() => canonicalize({ '\u00e9': 1, 'e\u0301': 2 })).toThrow();
  });
});

describe('hashing', () => {
  it('matches the known SHA-256 vector for "abc"', () => {
    expect(sha256('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });
  it('is stable regardless of key order', () => {
    expect(computePayloadHash({ a: 1, b: 2 })).toBe(computePayloadHash({ b: 2, a: 1 }));
  });
  it('safeEqualHex handles mismatch and length differences', () => {
    expect(safeEqualHex('aa', 'aa')).toBe(true);
    expect(safeEqualHex('aa', 'ab')).toBe(false);
    expect(safeEqualHex('aa', 'aaa')).toBe(false);
  });
});
