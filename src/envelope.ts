import { canonicalize, computePayloadHash, safeEqualHex, sha256 } from './canonical.js';

export interface MutationEnvelope {
  artifactId: string;
  artifactType: string;
  payloadHash: string;
  actorId: string;
  nonce: number; // per-actor, strictly increasing
  timestamp: string; // injected by caller, ISO 8601
  chainId?: number;
}

export const envelopeHash = (e: MutationEnvelope): string => sha256(canonicalize(e));

/** Recomputes the payload hash and compares it to the envelope's claim. */
export function verifyPayloadBinding(
  payload: unknown,
  envelope: MutationEnvelope,
): { ok: boolean; actualHash: string } {
  const actualHash = computePayloadHash(payload);
  return { ok: safeEqualHex(actualHash, envelope.payloadHash), actualHash };
}
