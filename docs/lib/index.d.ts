export type Algorithm = 'SHA1' | 'SHA256' | 'SHA512';
export type OtpType = 'totp' | 'hotp';

export interface HotpOptions {
  /** Code length, 6–8. Default `6`. */
  digits?: number;
  /** `SHA1` (default), `SHA256` or `SHA512`. */
  algorithm?: Algorithm;
}

export interface TotpOptions extends HotpOptions {
  /** Step size in seconds. Default `30`. */
  period?: number;
  /** Unix time in milliseconds. Default `Date.now()`. */
  timestamp?: number;
}

export interface OtpauthParams {
  type: OtpType;
  secret: string;
  /** Account name, e.g. the email address you log in with. */
  name: string;
  issuer: string;
  digits: number;
  period: number;
  algorithm: Algorithm;
  counter: number;
}

export interface BuildOtpauthParams {
  type?: OtpType;
  secret: string;
  name?: string;
  issuer?: string;
  digits?: number;
  period?: number;
  algorithm?: Algorithm;
  counter?: number;
}

export declare const ALPHABET: string;
export declare function base32Encode(bytes: Uint8Array | number[]): string;
export declare function base32Decode(input: string): Uint8Array;
export declare function normalizeSecret(secret: string): string;

export declare const ALGORITHMS: readonly Algorithm[];
export declare const DEFAULTS: { digits: 6; period: 30; algorithm: Algorithm };

export declare function hmac(algorithm: Algorithm, keyBytes: Uint8Array, msgBytes: Uint8Array): Promise<Uint8Array>;
export declare function counterBytes(counter: number | bigint): Uint8Array;
export declare function hotp(secret: string | Uint8Array, counter: number | bigint, options?: HotpOptions): Promise<string>;
export declare function totp(secret: string | Uint8Array, options?: TotpOptions): Promise<string>;
export declare function remainingSeconds(period?: number, timestamp?: number): number;
export declare function generateSecret(byteLength?: number): string;

export declare function parseOtpauth(raw: string): OtpauthParams | null;
export declare function buildOtpauth(params: BuildOtpauthParams): string;
