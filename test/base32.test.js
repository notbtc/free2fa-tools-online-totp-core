import test from 'node:test';
import assert from 'node:assert/strict';
import { base32Encode, base32Decode, normalizeSecret } from '../src/base32.js';

// RFC 4648 test vectors (§10)
const VECTORS = [
  ['', ''],
  ['f', 'MY'],
  ['fo', 'MZXQ'],
  ['foo', 'MZXW6'],
  ['foob', 'MZXW6YQ'],
  ['fooba', 'MZXW6YTB'],
  ['foobar', 'MZXW6YTBOI'],
];

test('base32Encode matches RFC 4648 vectors', () => {
  for (const [plain, encoded] of VECTORS) {
    const bytes = new TextEncoder().encode(plain);
    assert.equal(base32Encode(bytes), encoded, `encode("${plain}")`);
  }
});

test('base32Encode matches RFC 4648 vectors (typed array input)', () => {
  assert.equal(base32Encode([102, 111, 111, 98, 97, 114]), 'MZXW6YTBOI');
});

test('base32Decode round-trips', () => {
  for (const [plain, encoded] of VECTORS) {
    if (!encoded) continue; // '' is not a decodable secret, covered below
    const decoded = base32Decode(encoded);
    assert.equal(new TextDecoder().decode(decoded), plain);
  }
});

test('base32Decode tolerates lowercase, spaces and padding', () => {
  assert.deepEqual(base32Decode('jbswy3dpehpk3pxp'), base32Decode('JBSWY3DPEHPK3PXP'));
  assert.deepEqual(base32Decode('JBSW Y3DP EHPK 3PXP'), base32Decode('JBSWY3DPEHPK3PXP'));
  assert.deepEqual(base32Decode('MZXW6YTBOI======'), base32Decode('MZXW6YTBOI'));
});

test('base32Decode rejects bad input', () => {
  assert.throws(() => base32Decode(''), /empty/);
  assert.throws(() => base32Decode('JBSWY3DPEHPK3PX1'), /invalid Base32/); // 1 is not in the alphabet
  assert.throws(() => base32Decode('='), /empty/); // padding only -> no payload
  // 'MY' is a valid 1-byte payload (RFC 4648: 'f'), so it must decode, not throw
  assert.deepEqual(base32Decode('MY'), new Uint8Array([102]));
});

test('normalizeSecret strips spaces, padding and case', () => {
  assert.equal(normalizeSecret(' jbswy 3dpe hpk3pxp '), 'JBSWY3DPEHPK3PXP');
  assert.equal(normalizeSecret('JBSWY3DPEHPK3PXP===='), 'JBSWY3DPEHPK3PXP');
});
