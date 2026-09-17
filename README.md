# free2fa-tools-online-totp-core

[![npm version](https://img.shields.io/npm/v/2faguide-tools-online-totp-core.svg)](https://www.npmjs.com/package/2faguide-tools-online-totp-core)
[![license](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)
[![dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](./package.json)
[![node](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg)](https://nodejs.org)

> Published on npm as **[`2faguide-tools-online-totp-core`](https://www.npmjs.com/package/2faguide-tools-online-totp-core)**
> — npm rejects the word `free2fa` in new package names, so the registry name differs
> from the repository name. It is the same code.

Zero-dependency TOTP / HOTP core (RFC 4226 / RFC 6238) built on Web Crypto — the
engine behind the **[Free2FA online 2FA tool](https://2faguide.com/online-totp/)**.

Runs unchanged in browsers, Node 18+, Cloudflare Workers, Deno and Bun. No
`crypto` shims, no `Buffer`, no build step: it is three small ESM files on top of
`globalThis.crypto.subtle`.

## Why another TOTP library?

- **Zero dependencies.** Nothing to audit, nothing to break on install.
- **One code path everywhere.** Web Crypto is in every modern runtime, so the
  browser build and the Node build are literally the same file.
- **Spec-tested.** Every test vector from RFC 4226 Appendix D and RFC 6238
  Appendix B (SHA1 / SHA256 / SHA512, 6 and 8 digits) is asserted in CI.
- **Secrets never leave the device.** Everything is computed locally; there is no
  network code in this package at all.

## Install

```bash
npm install 2faguide-tools-online-totp-core
```

Or straight from git, if you would rather read the whole thing first (it is ~300 lines):

```bash
npm install github:notbtc/free2fa-tools-online-totp-core
```

## Usage

```js
import { totp, hotp, generateSecret, remainingSeconds, buildOtpauth, parseOtpauth } from '2faguide-tools-online-totp-core';

// A secret is the Base32 string a platform shows when you pick "use an authenticator app"
const secret = 'JBSWY3DPEHPK3PXP';

const code = await totp(secret);               // '123456'
const left = remainingSeconds();               // 30 -> 1, handy for a countdown ring

// Counter based (RFC 4226) instead of time based
await hotp(secret, 0);

// Generate a fresh 160-bit secret
const fresh = generateSecret();                // 'EOKOLTTNTFINYTWZLTE2KWJA36PML77F'

// Build the URI you put in a QR code
buildOtpauth({ secret: fresh, name: 'me@example.com', issuer: 'ACME' });
// otpauth://totp/ACME%3Ame%40example.com?secret=EOKOL...&issuer=ACME

// ...and read one back
parseOtpauth('otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub');
// { type: 'totp', secret: 'JBSWY3DPEHPK3PXP', issuer: 'GitHub', name: 'octocat',
//   digits: 6, period: 30, algorithm: 'SHA1', counter: 0 }
```

In a browser, just point a module script at it — no bundler needed:

```html
<script type="module">
  import { totp } from 'https://esm.sh/2faguide-tools-online-totp-core';
  document.querySelector('#code').textContent = await totp(secret);
</script>
```

> Web Crypto requires a secure context, so serve your page over `https` or `localhost`.

## API

| Export | Description |
| --- | --- |
| `totp(secret, options?)` | Time-based code (RFC 6238). `options`: `digits`, `period`, `algorithm`, `timestamp`. |
| `hotp(secret, counter, options?)` | Counter-based code (RFC 4226). `counter` may be a `number` or `bigint`. |
| `remainingSeconds(period?, timestamp?)` | Seconds before the current code rotates. |
| `generateSecret(byteLength?)` | Random Base32 secret, 160 bits by default. |
| `parseOtpauth(uri)` | Parse an `otpauth://` URI. Returns `null` for junk instead of throwing. |
| `buildOtpauth(params)` | Build an `otpauth://` URI, skipping default values. |
| `base32Encode(bytes)` / `base32Decode(str)` | RFC 4648 Base32, no padding. |
| `normalizeSecret(str)` | Uppercase and strip spaces / padding. |
| `hmac(algorithm, key, msg)` | Raw HMAC over Web Crypto, if you need it. |

Codes are returned as **strings**, not numbers — `07081804` is a valid 8-digit
code and `7081804` is not.

## Try it online

A hosted version of this code is running at
**[2faguide.com/online-totp](https://2faguide.com/online-totp/)** — paste a
secret, get the current 6-digit code and a countdown, with nothing uploaded to a
server. Useful for the "I can't scan the QR code" moment when you are setting up
two-factor authentication on a desktop.

## About Free2FA

[Free2FA](https://2faguide.com) is a free two-factor authenticator for WeChat
users, with encrypted cloud backup and a recycle bin — so a lost phone does not
mean re-binding every account. This package is the verification core we extracted
from it and are giving back.

- Website: <https://2faguide.com>
- Online 2FA tool: <https://2faguide.com/online-totp/>
- Two-factor guides: <https://2faguide.com/guide/>

## License

[MIT](./LICENSE) © Free2FA
