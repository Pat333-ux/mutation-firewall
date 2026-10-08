import { createHash, timingSafeEqual } from 'node:crypto';

/**
 * Canonical JSON. Accepts only: plain objects, arrays, strings,
 * finite numbers, booleans, null. Everything else throws.
 * - object keys sorted (by UTF-16 code unit order) after NFC normalization
 * - strings and keys NFC-normalized
 * - -0 is normalized to 0 (explicit, documented behavior)
 * - keys that collide after NFC normalization throw
 */
export function canonicalize(v: unknown): string {
  if (v === null) return 'null';
  switch (typeof v) {
    case 'string':
      return JSON.stringify(v.normalize('NFC'));
    case 'boolean':
      return v ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(v)) throw new TypeError('non-finite number');
      return Object.is(v, -0) ? '0' : JSON.stringify(v);
    case 'object':
      break;
    default:
      throw new TypeError(`unsupported type: ${typeof v}`);
  }
  if (Array.isArray(v)) {
    return `[${v.map(canonicalize).join(',')}]`;
  }
  const proto = Object.getPrototypeOf(v);
  if (proto !== Object.prototype && proto !== null) {
    throw new TypeError('only plain objects are allowed');
  }
  const o = v as Record<string, unknown>;
  const seen = new Set<string>();
  const parts: Array<[string, string]> = [];
  for (const key of Object.keys(o)) {
    const nk = key.normalize('NFC');
    if (seen.has(nk)) throw new TypeError(`duplicate key after NFC: ${nk}`);
    seen.add(nk);
    parts.push([nk, canonicalize(o[key])]);
  }
  parts.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  return `{${parts.map(([k, val]) => `${JSON.stringify(k)}:${val}`).join(',')}}`;
}

export const sha256 = (s: string): string =>
  createHash('sha256').update(s, 'utf8').digest('hex');

export const computePayloadHash = (payload: unknown): string =>
  sha256(canonicalize(payload));

/** Constant-time comparison of two hex digests. */
export function safeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  const ba = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  return timingSafeEqual(ba, bb);
}
