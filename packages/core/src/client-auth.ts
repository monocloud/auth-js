import {
  encodeBase64Url,
  randomBytes,
  stringToArrayBuffer,
} from './utils/internal';
import { ClientAuthMethod, Jwk } from './types';

const algToSubtle = (
  alg?: string
): HmacImportParams | RsaHashedImportParams | EcKeyImportParams => {
  switch (alg) {
    case 'HS256':
    case 'HS384':
    case 'HS512':
      return { name: 'HMAC', hash: `SHA-${alg.slice(-3)}` };
    case 'PS256':
    case 'PS384':
    case 'PS512':
      return { name: 'RSA-PSS', hash: `SHA-${alg.slice(-3)}` };
    case 'RS256':
    case 'RS384':
    case 'RS512':
      return { name: 'RSASSA-PKCS1-v1_5', hash: `SHA-${alg.slice(-3)}` };
    case 'ES256':
    case 'ES384':
      return { name: 'ECDSA', namedCurve: `P-${alg.slice(-3)}` };
    case 'ES512':
      return { name: 'ECDSA', namedCurve: 'P-521' };
    /* v8 ignore next */
    default:
      throw new Error('unsupported JWS algorithm');
  }
};

const psAlg = (key: CryptoKey): string => {
  switch ((key.algorithm as RsaHashedKeyAlgorithm).hash.name) {
    case 'SHA-256':
      return 'PS256';
    case 'SHA-384':
      return 'PS384';
    case 'SHA-512':
      return 'PS512';
    /* v8 ignore next */
    default:
      throw new Error('unsupported RsaHashedKeyAlgorithm hash name');
  }
};

const rsAlg = (key: CryptoKey): string => {
  switch ((key.algorithm as RsaHashedKeyAlgorithm).hash.name) {
    case 'SHA-256':
      return 'RS256';
    case 'SHA-384':
      return 'RS384';
    case 'SHA-512':
      return 'RS512';
    /* v8 ignore next */
    default:
      throw new Error('unsupported RsaHashedKeyAlgorithm hash name');
  }
};

const esAlg = (key: CryptoKey): string => {
  switch ((key.algorithm as EcKeyAlgorithm).namedCurve) {
    case 'P-256':
      return 'ES256';
    case 'P-384':
      return 'ES384';
    case 'P-521':
      return 'ES512';
    /* v8 ignore next */
    default:
      throw new Error('unsupported EcKeyAlgorithm namedCurve');
  }
};

const hsAlg = (key: CryptoKey): string => {
  switch ((key.algorithm as HmacKeyAlgorithm).hash.name) {
    case 'SHA-256':
      return 'HS256';
    case 'SHA-384':
      return 'HS384';
    case 'SHA-512':
      return 'HS512';
    /* v8 ignore next */
    default:
      throw new Error('unsupported HMAC Algorithm hash');
  }
};

const keyToJws = (key: CryptoKey): string => {
  switch (key.algorithm.name) {
    case 'HMAC':
      return hsAlg(key);
    case 'RSA-PSS':
      return psAlg(key);
    case 'RSASSA-PKCS1-v1_5':
      return rsAlg(key);
    case 'ECDSA':
      return esAlg(key);
    /* v8 ignore next */
    default:
      throw new Error('unsupported CryptoKey algorithm name');
  }
};

const checkRsaKeyAlgorithm = (key: CryptoKey): void => {
  const { algorithm } = key as CryptoKey & { algorithm: RsaHashedKeyAlgorithm };

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

const clientAssertionPayload = (
  issuer: string,
  clientId: string,
  skew: number
): Record<string, number | string> => {
  const now = Math.floor(Date.now() / 1000) + skew;
  return {
    jti: randomBytes(),
    aud: issuer,
    exp: now + 60,
    iat: now,
    nbf: now,
    iss: clientId,
    sub: clientId,
  };
};

const jwtAssertionGenerator = async (
  issuer: string,
  clientId: string,
  clientSecret: Jwk,
  body: URLSearchParams,
  skew: number
): Promise<void> => {
  const key = await crypto.subtle.importKey(
    'jwk',
    clientSecret as JsonWebKey,
    algToSubtle(clientSecret.alg),
    false,
    ['sign']
  );

  const header = { alg: keyToJws(key), kid: clientSecret.kid };
  const payload = clientAssertionPayload(issuer, clientId, skew);

  body.set('client_id', clientId);
  body.set(
    'client_assertion_type',
    'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
  );

  const input = `${encodeBase64Url(stringToArrayBuffer(JSON.stringify(header)))}.${encodeBase64Url(stringToArrayBuffer(JSON.stringify(payload)))}`;
  const signature = encodeBase64Url(
    await crypto.subtle.sign(
      keyToSubtle(key),
      key,
      stringToArrayBuffer(input) as BufferSource
    )
  );

  body.set('client_assertion', `${input}.${signature}`);
};

export const clientAuth = async (
  clientId: string,
  clientSecret?: string | Jwk,
  method?: ClientAuthMethod,
  issuer?: string,
  headers?: Record<string, string>,
  body?: URLSearchParams,
  jwtAssertionSkew?: number
): Promise<void> => {
  switch (true) {
    case method === 'client_secret_basic' && !!headers: {
      // eslint-disable-next-line no-param-reassign
      headers.authorization = `Basic ${btoa(`${clientId}:${clientSecret ?? ''}`)}`;
      break;
    }

    case method === 'client_secret_post' && !!body: {
      body.set('client_id', clientId);
      if (typeof clientSecret === 'string') {
        body.set('client_secret', clientSecret);
      }
      break;
    }

    case method === 'client_secret_jwt' &&
      !!issuer &&
      !!body &&
      (typeof clientSecret === 'string' || clientSecret?.kty === 'oct'): {
      const cs =
        typeof clientSecret === 'string'
          ? {
              k: encodeBase64Url(stringToArrayBuffer(clientSecret)),
              kty: 'oct',
              alg: 'HS256',
            }
          : clientSecret;

      await jwtAssertionGenerator(
        issuer,
        clientId,
        cs,
        body,
        jwtAssertionSkew ?? 0
      );
      break;
    }

    case method === 'private_key_jwt' &&
      typeof clientSecret === 'object' &&
      clientSecret.kty !== 'oct' &&
      !!issuer &&
      !!body: {
      await jwtAssertionGenerator(
        issuer,
        clientId,
        clientSecret,
        body,
        jwtAssertionSkew ?? 0
      );
      break;
    }

    default:
      throw new Error('Invalid Client Authentication Method');
  }
};
