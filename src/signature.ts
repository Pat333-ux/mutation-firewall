import { createHmac } from 'node:crypto';
import { verifyMessage } from 'ethers';
import { canonicalize, safeEqualHex, sha256 } from './canonical.js';

export type SignatureAlgorithm = 'SHA256-HMAC' | 'SHA256-HASH';

export interface SignatureOptions {
  algorithm: SignatureAlgorithm;
  key?: string;
}

export interface SignatureEnvelope {
  payload: unknown;
  canonical: string;
  algorithm: SignatureAlgorithm;
  keyId?: string;
}

export interface SignatureResult {
  signature: string;
  envelope: SignatureEnvelope;
}

export interface VerificationResult {
  valid: boolean;
  expected: string;
  actual: string;
  envelope: SignatureEnvelope;
}

function signatureFor(canonicalPayload: string, options: SignatureOptions): string {
  if (options.algorithm === 'SHA256-HMAC') {
    if (!options.key) {
      throw new Error('SHA256-HMAC requires a key.');
    }
    return createHmac('sha256', options.key)
      .update(canonicalPayload, 'utf8')
      .digest('hex');
  }
  return sha256(canonicalPayload);
}

export async function canonicalSign(
  payload: unknown,
  options: SignatureOptions,
): Promise<SignatureResult> {
  const canonicalPayload = canonicalize(payload);
  const envelope: SignatureEnvelope = {
    payload,
    canonical: canonicalPayload,
    algorithm: options.algorithm,
    ...(options.key ? { keyId: 'default' } : {}),
  };

  return {
    signature: signatureFor(canonicalPayload, options),
    envelope,
  };
}

export async function verifyCanonical(
  payload: unknown,
  signature: string,
  options: SignatureOptions,
): Promise<VerificationResult> {
  const result = await canonicalSign(payload, options);

  return {
    valid: safeEqualHex(result.signature, signature),
    expected: result.signature,
    actual: signature,
    envelope: result.envelope,
  };
}

export async function sign(
  payload: unknown,
  key?: string,
): Promise<SignatureResult> {
  return canonicalSign(payload, {
    algorithm: key ? 'SHA256-HMAC' : 'SHA256-HASH',
    key,
  });
}

export async function verify(
  payload: unknown,
  signature: string,
  key?: string,
): Promise<VerificationResult> {
  return verifyCanonical(payload, signature, {
    algorithm: key ? 'SHA256-HMAC' : 'SHA256-HASH',
    key,
  });
}

/**
 * Verifies an EIP-191 personal_sign signature over the envelope hash and
 * checks the recovered address against a trusted set (stored lowercased).
 */
export function verifyEnvelopeSignature(
  envelopeHashHex: string,
  signature: string,
  trusted: ReadonlySet<string>,
): { ok: boolean; recovered?: string } {
  try {
    const recovered = verifyMessage(envelopeHashHex, signature).toLowerCase();
    return { ok: trusted.has(recovered), recovered };
  } catch {
    return { ok: false };
  }
}
