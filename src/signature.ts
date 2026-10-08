import { verifyMessage } from 'ethers';

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
