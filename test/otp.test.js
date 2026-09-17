import test from 'node:test';
import assert from 'node:assert/strict';
import { hotp, totp, remainingSeconds, generateSecret, counterBytes } from '../src/otp.js';
import { base32Encode } from '../src/base32.js';

// RFC 4226 / RFC 6238 use the ASCII key "12345678901234567890".
const SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

// RFC 6238 Appendix B gives each algorithm its own key length:
// SHA1 20 bytes, SHA256 32 bytes, SHA512 64 bytes.
const secretFor = (length) => base32Encode(new TextEncoder().encode('12345678901234567890'.repeat(4).slice(0, length)));
const SECRET_SHA1 = secretFor(20);
const SECRET_SHA256 = secretFor(32);
const SECRET_SHA512 = secretFor(64);
assert.equal(SECRET_SHA1, SECRET);

// --- RFC 4226 (HOTP) Appendix D -------------------------------------------
const HOTP_VECTORS = [
  [0, '755224'],
  [1, '287082'],
  [2, '359152'],
  [3, '969429'],
  [4, '338314'],
  [5, '254676'],
  [6, '287922'],
  [7, '162583'],
  [8, '399871'],
  [9, '520489'],
];

test('hotp matches the RFC 4226 test vectors', async () => {
  for (const [counter, expected] of HOTP_VECTORS) {
    assert.equal(await hotp(SECRET, counter), expected, `counter=${counter}`);
  }
});

// --- RFC 6238 (TOTP) Appendix B -------------------------------------------
// [unixSeconds, SHA1, SHA256, SHA512] with 8 digits and a 30s step
const TOTP_VECTORS = [
  [59, '94287082', '46119246', '90693936'],
  [1111111109, '07081804', '68084774', '25091201'],
  [1111111111, '14050471', '67062674', '99943326'],
  [1234567890, '89005924', '91819424', '93441116'],
  [2000000000, '69279037', '90698825', '38618901'],
  [20000000000, '65353130', '77737706', '47863826'],
];

test('totp matches the RFC 6238 test vectors (all three algorithms)', async () => {
  for (const [seconds, sha1, sha256, sha512] of TOTP_VECTORS) {
    const at = seconds * 1000;
    const opts = { digits: 8, timestamp: at };
    assert.equal(await totp(SECRET_SHA1, { ...opts, algorithm: 'SHA1' }), sha1, `SHA1 @${seconds}`);
    assert.equal(await totp(SECRET_SHA256, { ...opts, algorithm: 'SHA256' }), sha256, `SHA256 @${seconds}`);
    assert.equal(await totp(SECRET_SHA512, { ...opts, algorithm: 'SHA512' }), sha512, `SHA512 @${seconds}`);
  }
});

test('totp accepts a raw Uint8Array key too', async () => {
  const raw = new TextEncoder().encode('12345678901234567890');
  assert.equal(await totp(raw, { algorithm: 'SHA1', digits: 8, timestamp: 59_000 }), '94287082');
});

test('totp defaults to 6 digits / 30s / SHA1 and zero-pads', async () => {
  const eight = await totp(SECRET, { digits: 8, timestamp: 59_000 });
  const six = await totp(SECRET, { timestamp: 59_000 });
  assert.match(six, /^\d{6}$/);
  // 6-digit code is the same truncated value taken mod 10^6, i.e. the tail of the 8-digit code
  assert.equal(six, eight.slice(-6));
});

test('totp honours a custom period', async () => {
  const a = await totp(SECRET, { period: 60, timestamp: 59_000 });
  const b = await totp(SECRET, { period: 60, timestamp: 60_000 });
  assert.notEqual(a, b);
});

test('counterBytes is 8 bytes big-endian', () => {
  assert.deepEqual([...counterBytes(1)], [0, 0, 0, 0, 0, 0, 0, 1]);
  // pass a bigint to stay exact — this literal is above Number.MAX_SAFE_INTEGER
  assert.deepEqual([...counterBytes(0x0102030405060708n)], [1, 2, 3, 4, 5, 6, 7, 8]);
  assert.deepEqual([...counterBytes(0xffffffffffffffffn)], [255, 255, 255, 255, 255, 255, 255, 255]);
});

test('remainingSeconds stays inside 1..period', () => {
  for (const t of [0, 1_000, 29_000, 30_000, 59_999, 1_700_000_000_000]) {
    const r = remainingSeconds(30, t);
    assert.ok(r >= 1 && r <= 30, `remainingSeconds(${t}) = ${r}`);
  }
  assert.equal(remainingSeconds(30, 0), 30);
  assert.equal(remainingSeconds(30, 1_000), 29);
});

test('generateSecret produces decodable 160-bit secrets', () => {
  const s = generateSecret();
  assert.match(s, /^[A-Z2-7]{32}$/); // 20 bytes -> 32 chars
  assert.notEqual(generateSecret(), generateSecret());
});

test('bad options throw instead of returning garbage', async () => {
  await assert.rejects(() => totp(SECRET, { period: 0 }), /period/);
  await assert.rejects(() => totp(SECRET, { digits: 9 }), /digits/);
  await assert.rejects(() => totp(SECRET, { algorithm: 'MD5' }), /unsupported/);
});
