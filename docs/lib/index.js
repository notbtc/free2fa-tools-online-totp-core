/**
 * 2faguide-tools-online-totp-core
 *
 * Zero-dependency TOTP / HOTP core (RFC 4226 / RFC 6238) on top of Web Crypto.
 * Same code in browsers, Node 18+, Workers, Deno and Bun.
 *
 *   import { totp, parseOtpauth } from '2faguide-tools-online-totp-core';
 *   await totp('JBSWY3DPEHPK3PXP'); // -> '123456'
 */

export { ALPHABET, base32Encode, base32Decode, normalizeSecret } from './base32.js';
export {
  ALGORITHMS,
  DEFAULTS,
  hmac,
  counterBytes,
  hotp,
  totp,
  remainingSeconds,
  generateSecret,
} from './otp.js';
export { parseOtpauth, buildOtpauth } from './otpauth.js';
