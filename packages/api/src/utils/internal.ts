import type { Jwk, SecurityAlgorithms, JwsHeaderParameters } from '../types';

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
 * Converts a string to a Uint8Array using TextEncoder.
 */
export const stringToArrayBuffer = (str: string): Uint8Array => {
  const encoder = new TextEncoder();
  return encoder.encode(str);
};

/**
 * @ignore
 * Converts a Base64URL string back to a standard Base64 string with padding.
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
 */
export const decodeBase64Url = (input: string): string =>
  atob(fromB64Url(input).replace(/\s/g, ''));

/**
 * @ignore
 * Gets the current Unix timestamp in seconds.
 */
export const now = (): number => Math.ceil(Date.now() / 1000);

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
    if (jwk.kty !== kty) {
      return false;
    }

    if (kid !== undefined && kid !== jwk.kid) {
      return false;
    }

    if (jwk.alg !== undefined && alg !== jwk.alg) {
      return false;
    }

    if (jwk.use !== undefined && jwk.use !== 'sig') {
      return false;
    }

    if (jwk.key_ops?.includes('verify') === false) {
      return false;
    }

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

const checkRsaKeyAlgorithm = (key: CryptoKey): void => {
  const { algorithm } = key as CryptoKey & {
    algorithm: RsaHashedKeyAlgorithm;
  };

  /* v8 ignore if -- @preserve */
  if (
    typeof algorithm.modulusLength !== 'number' ||
    algorithm.modulusLength < 2048
  ) {
    throw new Error(`Unsupported ${algorithm.name} modulusLength`);
  }
};

const ecdsaHashName = (key: CryptoKey): string => {
  const { algorithm } = key as CryptoKey & { algorithm: EcKeyAlgorithm };
  switch (algorithm.namedCurve) {
    case 'P-256':
      return 'SHA-256';
    case 'P-384':
      return 'SHA-384';
    case 'P-521':
      return 'SHA-512';
    /* v8 ignore next */
    default:
      throw new Error('unsupported ECDSA namedCurve');
  }
};

/**
 * Converts a CryptoKey to the appropriate crypto.subtle algorithm parameters.
 *
 * @param key - The CryptoKey to convert.
 *
 * @returns The algorithm identifier or parameters for use with crypto.subtle.verify.
 */
export const keyToSubtle = (
  key: CryptoKey
): AlgorithmIdentifier | RsaPssParams | EcdsaParams => {
  switch (key.algorithm.name) {
    case 'HMAC': {
      return { name: key.algorithm.name };
    }
    case 'ECDSA':
      return {
        name: key.algorithm.name,
        hash: ecdsaHashName(key),
      } as EcdsaParams;
    case 'RSA-PSS': {
      checkRsaKeyAlgorithm(key);
      switch ((key.algorithm as RsaHashedKeyAlgorithm).hash.name) {
        case 'SHA-256': // Fall through
        case 'SHA-384': // Fall through
        case 'SHA-512':
          return {
            name: key.algorithm.name,
            saltLength:
              parseInt(
                (key.algorithm as RsaHashedKeyAlgorithm).hash.name.slice(-3),
                10
              ) >> 3,
          } as RsaPssParams;
        /* v8 ignore next */
        default:
          throw new Error('unsupported RSA-PSS hash name');
      }
    }
    case 'RSASSA-PKCS1-v1_5':
      checkRsaKeyAlgorithm(key);
      return key.algorithm.name;
  }
  /* v8 ignore next -- @preserve */
  throw new Error('unsupported CryptoKey algorithm name');
};
