import test from 'node:test';
import assert from 'node:assert/strict';
import { parseOtpauth, buildOtpauth } from '../src/otpauth.js';

const SECRET = 'JBSWY3DPEHPK3PXP';

test('parses a plain totp URI', () => {
  const p = parseOtpauth('otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub');
  assert.equal(p.type, 'totp');
  assert.equal(p.secret, SECRET);
  assert.equal(p.issuer, 'GitHub');
  assert.equal(p.name, 'octocat');
  assert.equal(p.digits, 6);
  assert.equal(p.period, 30);
  assert.equal(p.algorithm, 'SHA1');
});

test('parses the full option set', () => {
  const p = parseOtpauth(
    'otpauth://totp/ACME%3Aalice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME&digits=8&period=60&algorithm=SHA256'
  );
  assert.equal(p.issuer, 'ACME');
  assert.equal(p.name, 'alice@example.com');
  assert.equal(p.digits, 8);
  assert.equal(p.period, 60);
  assert.equal(p.algorithm, 'SHA256');
});

test('falls back to the label when there is no issuer query param', () => {
  const p = parseOtpauth('otpauth://totp/Free2FA:me?secret=JBSWY3DPEHPK3PXP');
  assert.equal(p.issuer, 'Free2FA');
  assert.equal(p.name, 'me');
});

test('normalises a messy secret', () => {
  const p = parseOtpauth('otpauth://totp/x?secret=jbswy%203dpehpk3pxp');
  assert.equal(p.secret, SECRET);
});

test('parses hotp and keeps the counter', () => {
  const p = parseOtpauth('otpauth://hotp/Yubico?secret=JBSWY3DPEHPK3PXP&counter=7&digits=6');
  assert.equal(p.type, 'hotp');
  assert.equal(p.counter, 7);
});

test('returns null for junk instead of throwing', () => {
  assert.equal(parseOtpauth(''), null);
  assert.equal(parseOtpauth('https://example.com'), null);
  assert.equal(parseOtpauth('otpauth://totp/x'), null); // no secret
  assert.equal(parseOtpauth(null), null);
  assert.equal(parseOtpauth(undefined), null);
});

test('clamps unknown digits / period / algorithm to defaults', () => {
  const p = parseOtpauth('otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=7&period=45&algorithm=MD5');
  assert.equal(p.digits, 6);
  assert.equal(p.period, 30);
  assert.equal(p.algorithm, 'SHA1');
});

test('buildOtpauth emits a minimal, defaults-only URI', () => {
  assert.equal(buildOtpauth({ secret: SECRET, name: 'octocat' }), 'otpauth://totp/octocat?secret=' + SECRET);
});

test('buildOtpauth only writes non-default params', () => {
  const uri = buildOtpauth({
    secret: SECRET,
    name: 'alice@example.com',
    issuer: 'ACME',
    digits: 8,
    period: 60,
    algorithm: 'SHA256',
  });
  assert.equal(
    uri,
    'otpauth://totp/ACME%3Aalice%40example.com?secret=' +
      SECRET +
      '&issuer=ACME&digits=8&period=60&algorithm=SHA256'
  );
});

test('buildOtpauth supports hotp', () => {
  assert.equal(
    buildOtpauth({ type: 'hotp', secret: SECRET, name: 'key', counter: 3 }),
    'otpauth://hotp/key?secret=' + SECRET + '&counter=3'
  );
});

test('build -> parse round-trips', () => {
  const src = { secret: SECRET, name: 'me@example.com', issuer: 'Free2FA', digits: 8, period: 60, algorithm: 'SHA256' };
  const p = parseOtpauth(buildOtpauth(src));
  assert.equal(p.secret, src.secret);
  assert.equal(p.issuer, 'Free2FA');
  assert.equal(p.name, 'me@example.com');
  assert.equal(p.digits, 8);
  assert.equal(p.period, 60);
  assert.equal(p.algorithm, 'SHA256');
});

test('buildOtpauth requires a secret', () => {
  assert.throws(() => buildOtpauth({ name: 'x' }), /secret is required/);
});
