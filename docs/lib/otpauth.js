import { normalizeSecret } from './base32.js';
import { ALGORITHMS, DEFAULTS } from './otp.js';

function safeDecode(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

/**
 * Parse an `otpauth://` URI (the one you get from a QR code).
 * Returns null when the input is not a usable otpauth URI, so it is safe to
 * call on arbitrary user input.
 *
 * @param {string} raw
 * @returns {{type: string, secret: string, issuer: string, name: string,
 *            digits: number, period: number, algorithm: string, counter: number} | null}
 */
export function parseOtpauth(raw) {
  const text = String(raw == null ? '' : raw).trim();
  if (!/^otpauth:\/\//i.test(text)) return null;

  let url;
  try {
    // Borrow the URL parser: otpauth:// is not a special scheme, so swap the scheme.
    url = new URL(text.replace(/^otpauth:/i, 'https:'));
  } catch {
    return null;
  }

  const type = url.hostname.toLowerCase();
  if (type !== 'totp' && type !== 'hotp') return null;

  const secretRaw = (url.searchParams.get('secret') || '').trim();
  if (!secretRaw) return null;

  const label = safeDecode(url.pathname.replace(/^\/+/, ''));
  const queryIssuer = url.searchParams.get('issuer') || '';
  const [labelIssuer, labelAccount] = label.includes(':')
    ? [label.slice(0, label.indexOf(':')), label.slice(label.indexOf(':') + 1)]
    : ['', label];

  const issuer = (queryIssuer || labelIssuer || '').trim();
  const account = (labelAccount || '').trim();

  const digits = Number(url.searchParams.get('digits') || DEFAULTS.digits);
  const period = Number(url.searchParams.get('period') || DEFAULTS.period);
  const counter = Number(url.searchParams.get('counter') || 0);
  const algorithm = String(url.searchParams.get('algorithm') || DEFAULTS.algorithm).toUpperCase();

  return {
    type,
    secret: normalizeSecret(secretRaw),
    issuer,
    name: account || issuer,
    digits: digits === 8 ? 8 : 6,
    period: period === 60 ? 60 : 30,
    algorithm: ALGORITHMS.includes(algorithm) ? algorithm : 'SHA1',
    counter: Number.isFinite(counter) ? counter : 0,
  };
}

/**
 * Build an `otpauth://` URI (to render as a QR code).
 * Only non-default values are written out, keeping the URI short and
 * Google-Authenticator friendly.
 *
 * @param {{type?: string, secret: string, name?: string, issuer?: string,
 *          digits?: number, period?: number, algorithm?: string, counter?: number}} params
 * @returns {string}
 */
export function buildOtpauth(params) {
  const {
    type = 'totp',
    secret,
    name = '',
    issuer = '',
    digits = DEFAULTS.digits,
    period = DEFAULTS.period,
    algorithm = DEFAULTS.algorithm,
    counter = 0,
  } = params || {};

  if (!secret) throw new Error('secret is required');

  const label = issuer ? `${issuer}:${name || issuer}` : name || 'Free2FA';
  const parts = ['secret=' + normalizeSecret(secret)];
  if (issuer) parts.push('issuer=' + encodeURIComponent(issuer));
  if (Number(digits) !== 6) parts.push('digits=' + Number(digits));
  if (type === 'hotp') parts.push('counter=' + Number(counter));
  else if (Number(period) !== 30) parts.push('period=' + Number(period));
  if (String(algorithm).toUpperCase() !== 'SHA1') parts.push('algorithm=' + String(algorithm).toUpperCase());

  return `otpauth://${type === 'hotp' ? 'hotp' : 'totp'}/${encodeURIComponent(label)}?${parts.join('&')}`;
}
