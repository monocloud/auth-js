import type {
  AccessToken,
  Jwk,
  JWSAlgorithm,
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
export const isPresent = (value?: string | number | boolean): boolean => {
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
export const now = (): number => Math.ceil(Date.now() / 1000);

const SUPPORTED_JWS_ALGS: JWSAlgorithm[] = [
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
    | RsaHashedImportParams
    | EcKeyImportParams
    | AlgorithmIdentifier;

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
 * @param a - The first Set
 * @param b - The second Set
 * @param strict - If `true`, requires both sets to be the same size. @defaultValue true
 *
 * @returns `true` if the sets are equal
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
