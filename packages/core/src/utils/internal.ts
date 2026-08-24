import type {
  AccessToken,
  IdTokenClaims,
  Jwk,
  MonoCloudUser,
  SecurityAlgorithms,
  JwsHeaderParameters,
} from '../types';

/**
 * @ignore
 * Converts a string to a Base64URL encoded string.
 *
 * @param input - The string to encode.
 *
 * @returns The Base64URL encoded string.
 */
export const toB64Url = (input: string): string =>
  input.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

/**
 * @ignore
 * Parses a string value into a boolean.
 *
 * @param value - The string value to parse.
 *
 * @returns `true` if "true", `false` if "false", otherwise `undefined`.
 */
export const getBoolean = (value?: string): boolean | undefined => {
  const v = value?.toLowerCase()?.trim();

  if (v === 'true') {
    return true;
  }

  if (v === 'false') {
    return false;
  }

  return undefined;
};

/**
 * @ignore
 * Parses a string value into a number.
 *
 * @param value - The string value to parse.
 *
 * @returns The parsed number, or `undefined` if empty or invalid.
 */
export const getNumber = (value?: string): number | undefined => {
  const v = value?.trim();

  if (v === undefined || v.length === 0) {
    return undefined;
  }

  const p = parseInt(v, 10);

  return Number.isNaN(p) ? undefined : p;
};

/**
 * @ignore
 * Ensures that a string has a leading forward slash.
 *
 * @param val - The string to check.
 *
 * @returns The string with a leading slash.
 */
export const ensureLeadingSlash = (val?: string): string => {
  const v = val?.trim();

  if (!v) {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    return v!;
  }

  return v.startsWith('/') ? v : `/${v}`;
};

/**
 * @ignore
 * Removes a trailing forward slash from a string.
 *
 * @param val - The string to check.
 *
 * @returns The string without a trailing slash.
 */
export const removeTrailingSlash = (val?: string): string => {
  const v = val?.trim();

  if (!v) {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    return v!;
  }

  return v.endsWith('/') ? v.substring(0, v.length - 1) : v;
};

/**
 * @ignore
 * Checks if a value is present (not null, undefined, or an empty string).
 *
 * @param value - The value to check.
 *
 * @returns `true` if the value is present, `false` otherwise.
 */
export const isPresent = (
  value?: string | number | boolean
): value is string | number | boolean => {
  if (typeof value === 'boolean' || typeof value === 'number') {
    return true;
  }
  const v = value?.trim();
  return v !== undefined && v !== null && v.length > 0;
};

/**
 * @ignore
 * Checks if a URL is an absolute URL (starts with http:// or https://).
 *
 * @param url - The URL to check.
 *
 * @returns `true` if absolute, `false` otherwise.
 */
export const isAbsoluteUrl = (url: string): boolean =>
  (url?.startsWith('http://') || url?.startsWith('https://')) ?? false;

/**
 * @ignore
 * Checks if two URLs have the same origin (host and port).
 *
 * @param url - The first URL.
 * @param urlToCheck - The second URL to compare against.
 *
 * @returns `true` if they share the same origin, `false` otherwise.
 */
export const isSameHost = (url: string, urlToCheck: string): boolean => {
  try {
    const u = new URL(url);
    const u2 = new URL(urlToCheck);

    return u.origin === u2.origin;
  } catch {
    return false;
  }
};

/**
 * @ignore
 * Converts a string to a Uint8Array using TextEncoder.
 *
 * @param str - The string to convert.
 *
 * @returns A Uint8Array representation of the string.
 */
export const stringToArrayBuffer = (str: string): Uint8Array => {
  const encoder = new TextEncoder();
  return encoder.encode(str);
};

/**
 * @ignore
 * Converts an ArrayBuffer to a string using TextDecoder.
 *
 * @param buffer - The buffer to convert.
 *
 * @returns The decoded string.
 */
export const arrayBufferToString = (buffer: ArrayBuffer): string => {
  const decoder = new TextDecoder();
  return decoder.decode(buffer);
};

/**
 * @ignore
 * Encodes a string as standard (padded) Base64 from its UTF-8 bytes.
 *
 * @param input - The string to encode.
 *
 * @returns The Base64 encoded string.
 */
export const encodeBase64 = (input: string): string =>
  btoa(
    stringToArrayBuffer(input).reduce(
      (acc, byte) => acc + String.fromCharCode(byte),
      ''
    )
  );

/**
 * @ignore
 * Compares two strings without leaking their contents through timing.
 *
 * @param a - The first string.
 * @param b - The second string.
 *
 * @returns `true` if the strings are equal.
 */
export const timingSafeEqual = (a: string, b: string): boolean => {
  const aBytes = stringToArrayBuffer(a);
  const bBytes = stringToArrayBuffer(b);

  if (aBytes.length !== bBytes.length) {
    return false;
  }

  let result = 0;

  for (let i = 0; i < aBytes.length; i++) {
    result |= aBytes[i] ^ bBytes[i];
  }

  return result === 0;
};

/**
 * @ignore
 * Converts a Base64URL string back to a standard Base64 string with padding.
 *
 * @param input - The Base64URL string.
 *
 * @returns A standard Base64 string.
 */
export const fromB64Url = (input: string): string => {
  let str = input;
  if (str.length % 4 !== 0) {
    str += '==='.slice(0, 4 - (str.length % 4));
  }

  str = str.replace(/-/g, '+').replace(/_/g, '/');

  return str;
};

/**
 * @ignore
 * Decodes a Base64URL encoded string.
 *
 * @param input - The Base64URL string to decode.
 *
 * @returns The decoded plaintext string.
 */
export const decodeBase64Url = (input: string): string =>
  atob(fromB64Url(input).replace(/\s/g, ''));

/**
 * @ignore
 * Converts a Uint8Array to a Base64URL encoded string.
 *
 * @param buffer - The buffer to encode.
 *
 * @returns The Base64URL encoded string.
 */
export const arrayBufferToBase64 = (buffer: Uint8Array): string => {
  const bytes = new Uint8Array(buffer);
  const binary = bytes.reduce(
    (acc, byte) => acc + String.fromCharCode(byte),
    ''
  );
  return btoa(binary).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
};

/**
 * @ignore
 * Gets the current Unix timestamp in seconds.
 *
 * @returns The current timestamp.
 */
export const now = (): number => Math.floor(Date.now() / 1000);

const SUPPORTED_JWS_ALGS: SecurityAlgorithms[] = [
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'ES256',
  'ES384',
  'ES512',
];

/**
 * Retrieves a public CryptoKey from a JWK set based on the JWS header.
 *
 * @param jwks - The set of JSON Web Keys.
 * @param header - The JWS header containing the algorithm and key ID.
 *
 * @returns A promise that resolves to the CryptoKey.
 *
 * @throws If no applicable key or multiple keys are found or the algorithm is unsupported.
 */
export const getPublicSigKeyFromIssuerJwks = async (
  jwks: Jwk[],
  header: JwsHeaderParameters
): Promise<CryptoKey> => {
  const { alg, kid } = header;

  if (!SUPPORTED_JWS_ALGS.includes(alg)) {
    throw new Error('unsupported JWS "alg" identifier');
  }

  let kty: string;
  switch (alg.slice(0, 2)) {
    case 'RS': // Fall through
    case 'PS':
      kty = 'RSA';
      break;
    case 'ES':
      kty = 'EC';
      break;
  }

  const candidates = jwks.filter(jwk => {
    // filter keys based on the mapping of signature algorithms to Key Type
    if (jwk.kty !== kty) {
      return false;
    }

    // filter keys based on the JWK Key ID in the header
    if (kid !== undefined && kid !== jwk.kid) {
      return false;
    }

    // filter keys based on the key's declared Algorithm
    if (jwk.alg !== undefined && alg !== jwk.alg) {
      return false;
    }

    // filter keys based on the key's declared Public Key Use
    if (jwk.use !== undefined && jwk.use !== 'sig') {
      return false;
    }

    // filter keys based on the key's declared Key Operations
    if (jwk.key_ops?.includes('verify') === false) {
      return false;
    }

    // filter keys based on alg-specific key requirements
    switch (true) {
      case alg === 'ES256' && jwk.crv !== 'P-256': // Fall through
      case alg === 'ES384' && jwk.crv !== 'P-384': // Fall through
      case alg === 'ES512' && jwk.crv !== 'P-521': // Fall through
        return false;
    }

    return true;
  });

  const { 0: jwk, length } = candidates;

  if (length !== 1) {
    throw new Error(
      'error when selecting a JWT verification key, multiple applicable keys found, a "kid" JWT Header Parameter is required'
    );
  }

  let algorithm:
    RsaHashedImportParams | EcKeyImportParams | AlgorithmIdentifier;

  switch (alg) {
    case 'PS256': // Fall through
    case 'PS384': // Fall through
    case 'PS512':
      algorithm = { name: 'RSA-PSS', hash: `SHA-${alg.slice(-3)}` };
      break;
    case 'RS256': // Fall through
    case 'RS384': // Fall through
    case 'RS512':
      algorithm = { name: 'RSASSA-PKCS1-v1_5', hash: `SHA-${alg.slice(-3)}` };
      break;
    case 'ES256': // Fall through
    case 'ES384':
      algorithm = { name: 'ECDSA', namedCurve: `P-${alg.slice(-3)}` };
      break;
    case 'ES512':
      algorithm = { name: 'ECDSA', namedCurve: 'P-521' };
      break;
  }

  const { ext, key_ops, use, ...k } = jwk;

  const key = await crypto.subtle.importKey('jwk', k, algorithm, true, [
    'verify',
  ]);

  if (key.type !== 'public') {
    throw new Error('jwks_uri must only contain public keys');
  }

  return key;
};

const CHUNK_SIZE = 0x8000;

/**
 * @ignore
 * Encodes a Uint8Array or ArrayBuffer into a Base64URL string using chunked processing.
 *
 * @param input - The data to encode.
 *
 * @returns The Base64URL encoded string.
 */
export const encodeBase64Url = (input: Uint8Array | ArrayBuffer): string => {
  if (input instanceof ArrayBuffer) {
    // eslint-disable-next-line no-param-reassign
    input = new Uint8Array(input);
  }

  const arr = [];
  for (let i = 0; i < input.byteLength; i += CHUNK_SIZE) {
    arr.push(
      String.fromCharCode.apply(
        null,
        Array.from(new Uint8Array(input.slice(i, i + CHUNK_SIZE)))
      )
    );
  }
  return btoa(arr.join(''))
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
};

/**
 * @ignore
 * Computes a SHA-256 hash of the input string and returns it as a Base64URL encoded string.
 *
 * @param input - The string to hash.
 *
 * @returns The Base64URL encoded SHA-256 hash.
 */
export const sha256 = async (input: string): Promise<string> =>
  encodeBase64Url(
    await crypto.subtle.digest(
      'SHA-256',
      stringToArrayBuffer(input) as BufferSource
    )
  );

/**
 * @ignore
 * Computes the base64url-encoded left-most half of the digest of `value`,
 * using the hash algorithm implied by an id token signing algorithm.
 *
 * @param value - The value to hash (for example an access token, code or state).
 * @param alg - The id token signing algorithm.
 *
 * @returns The base64url encoded left-most half of the digest.
 */
export const hashTokenValue = async (
  value: string,
  alg: SecurityAlgorithms
): Promise<string> => {
  const digest = `SHA-${alg.slice(-3)}`;

  const hash = new Uint8Array(
    await crypto.subtle.digest(
      digest,
      stringToArrayBuffer(value) as BufferSource
    )
  );

  return encodeBase64Url(hash.slice(0, hash.length / 2));
};

/**
 * @ignore
 * Validates an OpenID Connect hash claim (such as `at_hash`, `c_hash` or
 * `s_hash`) against the value it was derived from.
 *
 * @param value - The value the hash was derived from (for example the access token or state).
 * @param expectedHash - The hash claim value present in the id token.
 * @param alg - The id token signing algorithm.
 *
 * @returns `true` when the computed hash matches `expectedHash`, `false` otherwise.
 */
export const validateTokenHash = async (
  value: string,
  expectedHash: string,
  alg: SecurityAlgorithms
): Promise<boolean> =>
  timingSafeEqual(await hashTokenValue(value, alg), expectedHash);

/**
 * @ignore
 * Generates a random Base64URL encoded string.
 *
 * @param length - The number of random bytes to generate.
 *
 * @returns A random Base64URL string.
 */
export const randomBytes = (length = 32): string =>
  encodeBase64Url(crypto.getRandomValues(new Uint8Array(length)));

/**
 * @ignore
 * Checks if a value is a non-null, non-array JSON object.
 *
 * @param input - The value to check.
 *
 * @returns `true` if the value is a JSON object.
 */
export const isJsonObject = <T>(input: unknown): input is T => {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    return false;
  }

  return true;
};

/**
 * @ignore
 * Resolves a client secret supplied as a string.
 *
 * When the string parses to a JWK — a JSON object with a string `kty` member, such as the
 * private key used with the `private_key_jwt` client authentication method — the parsed object
 * is returned. Any other value (a plain-text secret, non-JWK JSON, or a value already provided
 * as an object) is returned unchanged.
 *
 * @param value - The raw client secret (a string, a JWK object, or `undefined`).
 *
 * @returns The parsed JWK object, the original string secret, or `undefined`.
 */
export const parseClientSecret = (
  value?: string | Jwk
): string | Jwk | undefined => {
  if (typeof value !== 'string') {
    return value;
  }

  try {
    const parsed: unknown = JSON.parse(value);
    if (
      typeof parsed === 'object' &&
      parsed !== null &&
      typeof (parsed as Record<string, unknown>).kty === 'string'
    ) {
      return parsed as Jwk;
    }
  } catch {
    // Not JSON — fall through and treat the value as a plain-text secret.
  }

  return value;
};

/**
 * @ignore
 * Parses a space-separated string into an array of strings.
 *
 * @param s - The space-separated string.
 *
 * @returns An array of strings, or `undefined` if input is empty.
 */
export const parseSpaceSeparated = (s?: string): string[] | undefined =>
  s
    ?.split(/\s+/)
    .map(x => x.trim())
    .filter(Boolean);

/**
 * @ignore
 * Parses a space-separated string into a Set of strings.
 *
 * @param s - The space-separated string.
 *
 * @returns A Set containing the unique strings.
 */
export const parseSpaceSeparatedSet = (s?: string): Set<string> => {
  if (!s) {
    return new Set();
  }

  return new Set(parseSpaceSeparated(s));
};

/**
 * @ignore
 * Compares two Sets for equality.
 *
 * @param a - The first Set.
 * @param b - The second Set.
 * @param strict - If `true`, requires both sets to be the same size. Defaults to `true`.
 *
 * @returns `true` if the sets are equal.
 */
export const setsEqual = (
  a: Set<string>,
  b: Set<string>,
  strict = true
): boolean => {
  if (strict && a.size !== b.size) {
    return false;
  }

  for (const v of a) {
    if (!b.has(v)) {
      return false;
    }
  }

  return true;
};

/**
 * Finds a specific access token in an array based on resource and scopes.
 *
 * @param tokens - The array of access tokens.
 * @param resource - Space-separated resource indicators.
 * @param scopes - Space-separated scopes.
 *
 * @returns The matching AccessToken, or `undefined` if not found.
 */
export const findToken = (
  tokens?: AccessToken[],
  resource?: string,
  scopes?: string
): AccessToken | undefined => {
  if (!Array.isArray(tokens) || tokens.length === 0) {
    return undefined;
  }

  const desiredResource = parseSpaceSeparatedSet(resource);
  const desiredScopes = parseSpaceSeparatedSet(scopes);

  return tokens.find(
    t =>
      setsEqual(desiredResource, parseSpaceSeparatedSet(t.resource)) &&
      setsEqual(desiredScopes, parseSpaceSeparatedSet(t.requestedScopes))
  );
};

/**
 * @ignore
 * Builds the session user claims from existing claims and newly fetched claims.
 *
 * @param existingUser - Existing session user claims.
 * @param idTokenClaims - Claims extracted from ID token.
 * @param userinfoClaims - Claims fetched from UserInfo endpoint.
 * @param strict - If `true`, creates claims from new inputs only (falls back to existing when none). If `false`, merges into existing claims.
 *
 * @returns Updated user claims for the session.
 */
export const profileSync = (
  existingUser?: MonoCloudUser,
  idTokenClaims?: Partial<IdTokenClaims>,
  userinfoClaims?: Partial<MonoCloudUser>,
  strict = false
): MonoCloudUser => {
  const hasIdTokenClaims =
    !!idTokenClaims && Object.keys(idTokenClaims).length > 0;
  const hasUserinfoClaims =
    !!userinfoClaims && Object.keys(userinfoClaims).length > 0;

  if (!hasIdTokenClaims && !hasUserinfoClaims) {
    return existingUser ?? ({} as MonoCloudUser);
  }

  if (strict) {
    return {
      ...(idTokenClaims ?? {}),
      ...(userinfoClaims ?? {}),
    } as MonoCloudUser;
  }

  return {
    ...(existingUser ?? {}),
    ...(idTokenClaims ?? {}),
    ...(userinfoClaims ?? {}),
  } as MonoCloudUser;
};
