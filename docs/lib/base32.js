export const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Encode bytes as a Base32 string (RFC 4648, no padding).
 * @param {Uint8Array | number[]} bytes
 * @returns {string}
 */
export function base32Encode(bytes) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | (bytes[i] & 0xff);
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

/**
 * Decode a Base32 string (RFC 4648) into bytes.
 * Spaces and `=` padding are ignored, case insensitive — so a secret copied out of
 * a "can't scan the QR code?" dialog can be pasted straight in.
 * @param {string} input
 * @returns {Uint8Array}
 */
export function base32Decode(input) {
  const s = String(input).replace(/[\s=]/g, '').toUpperCase();
  if (!s) throw new Error('secret is empty');
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of s) {
    const idx = ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error(`invalid Base32 character: ${ch}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  if (out.length === 0) throw new Error('secret is too short');
  return new Uint8Array(out);
}

/**
 * Normalise a secret: uppercase, strip spaces and padding.
 * @param {string} secret
 * @returns {string}
 */
export function normalizeSecret(secret) {
  return String(secret).replace(/[\s=]/g, '').toUpperCase();
}
