import { base32Decode, base32Encode } from './base32.js';

const WEBCRYPT_ALGO = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };

export const ALGORITHMS = ['SHA1', 'SHA256', 'SHA512'];

export const DEFAULTS = { digits: 6, period: 30, algorithm: 'SHA1' };

function subtle() {
  const s = globalThis.crypto && globalThis.crypto.subtle;
  if (!s) {
    throw new Error(
      'Web Crypto (globalThis.crypto.subtle) is not available in this runtime. ' +
        'Use Node.js >= 18, or any modern browser served over https / localhost.'
    );
  }
  return s;
}

/**
 * HMAC a message with the given algorithm. Runs on Web Crypto, so the same code
 * works in browsers, Node 18+, Workers, Deno and Bun.
 * @param {string} algorithm SHA1 | SHA256 | SHA512
 * @param {Uint8Array} keyBytes
 * @param {Uint8Array} msgBytes
 * @returns {Promise<Uint8Array>}
 */
export async function hmac(algorithm, keyBytes, msgBytes) {
  const algo = WEBCRYPT_ALGO[String(algorithm || 'SHA1').toUpperCase()];
  if (!algo) throw new Error(`unsupported algorithm: ${algorithm}`);
  const key = await subtle().importKey('raw', keyBytes, { name: 'HMAC', hash: algo }, false, ['sign']);
  return new Uint8Array(await subtle().sign('HMAC', key, msgBytes));
}

/**
 * 8-byte big-endian counter, as required by RFC 4226.
 * Uses BigInt internally so counters above 2^53 stay exact — passing a
 * `number` or a `bigint` both work.
 * @param {number | bigint} counter
 * @returns {Uint8Array}
 */
export function counterBytes(counter) {
  const b = new Uint8Array(8);
  let c = BigInt(counter);
  for (let i = 7; i >= 0; i--) {
    b[i] = Number(c & 0xffn);
    c >>= 8n;
  }
  return b;
}

/**
 * HOTP — RFC 4226.
 * @param {string | Uint8Array} secret Base32 secret (or raw key bytes)
 * @param {number} counter
 * @param {{digits?: number, algorithm?: string}} [options]
 * @returns {Promise<string>} zero-padded code
 */
export async function hotp(secret, counter, options = {}) {
  const { digits = DEFAULTS.digits, algorithm = DEFAULTS.algorithm } = options;
  if (!Number.isInteger(digits) || digits < 6 || digits > 8) {
    throw new Error('digits must be an integer between 6 and 8');
  }
  const keyBytes = typeof secret === 'string' ? base32Decode(secret) : secret;
  const mac = await hmac(algorithm, keyBytes, counterBytes(counter));
  const offset = mac[mac.length - 1] & 0x0f;
  const bin =
    ((mac[offset] & 0x7f) << 24) |
    ((mac[offset + 1] & 0xff) << 16) |
    ((mac[offset + 2] & 0xff) << 8) |
    (mac[offset + 3] & 0xff);
  return String(bin % 10 ** digits).padStart(digits, '0');
}

/**
 * TOTP — RFC 6238. Thin wrapper over HOTP with a time-based counter.
 * @param {string | Uint8Array} secret
 * @param {{digits?: number, period?: number, algorithm?: string, timestamp?: number}} [options]
 * @returns {Promise<string>}
 */
export async function totp(secret, options = {}) {
  const { period = DEFAULTS.period, timestamp = Date.now(), ...rest } = options;
  if (!Number.isFinite(period) || period <= 0) throw new Error('period must be a positive number');
  return hotp(secret, Math.floor(timestamp / 1000 / period), rest);
}

/**
 * Seconds left before the current code expires — handy for a countdown ring.
 * @param {number} [period]
 * @param {number} [timestamp]
 * @returns {number} 1..period
 */
export function remainingSeconds(period = DEFAULTS.period, timestamp = Date.now()) {
  return period - (Math.floor(timestamp / 1000) % period);
}

/**
 * Generate a random Base32 secret (160 bits by default, what most platforms issue).
 * @param {number} [byteLength]
 * @returns {string}
 */
export function generateSecret(byteLength = 20) {
  const bytes = new Uint8Array(byteLength);
  const c = globalThis.crypto;
  if (!c || !c.getRandomValues) throw new Error('globalThis.crypto.getRandomValues is not available');
  c.getRandomValues(bytes);
  return base32Encode(bytes);
}
