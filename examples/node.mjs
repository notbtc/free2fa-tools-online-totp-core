/**
 * Node example: generate a secret, print the current code and the countdown.
 *
 *   node examples/node.mjs
 */
import { totp, hotp, generateSecret, remainingSeconds, buildOtpauth, parseOtpauth } from '../src/index.js';

const secret = generateSecret();
console.log('secret          :', secret);
console.log('otpauth URI     :', buildOtpauth({ secret, name: 'demo@example.com', issuer: 'Free2FA' }));

const code = await totp(secret);
console.log('current TOTP    :', code, `(${remainingSeconds()}s left)`);

// Same secret, but as HOTP with an incrementing counter
console.log('HOTP counter=0  :', await hotp(secret, 0));
console.log('HOTP counter=1  :', await hotp(secret, 1));

// Round-trip an otpauth:// URI (what a QR code contains)
const parsed = parseOtpauth('otpauth://totp/Free2FA:demo@example.com?secret=' + secret + '&issuer=Free2FA');
console.log('parsed URI      :', parsed);
console.log('same code?      :', (await totp(parsed.secret)) === code);
