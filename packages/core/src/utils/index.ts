import type {
  AuthState,
  CallbackParams,
  IdTokenClaims,
  MonoCloudSession,
  MonoCloudUser,
} from '../types';
import {
  arrayBufferToBase64,
  arrayBufferToString,
  encodeBase64Url,
  fromB64Url,
  now,
  randomBytes,
  stringToArrayBuffer,
} from './internal';

const PBKDF2_ITERATIONS = 310_000;
const SALT_LENGTH = 16;
const GCM_IV_LENGTH = 12;

const deriveEncryptionKey = async (
  secret: string,
  salt: Uint8Array
): Promise<CryptoKey> => {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    stringToArrayBuffer(secret) as BufferSource,
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt as BufferSource,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
};

/**
 * Parses callback parameters from a URL, a URLSearchParams object, or a query string.
 */
export const parseCallbackParams = (
  queryOrUrl: string | URL | URLSearchParams
): CallbackParams => {
  let params;

  if (queryOrUrl instanceof URL) {
    params = queryOrUrl.searchParams;
  } else if (queryOrUrl instanceof URLSearchParams) {
    params = queryOrUrl;
  } else {
    try {
      params = new URL(queryOrUrl).searchParams;
    } catch {
      // eslint-disable-next-line no-param-reassign
      queryOrUrl =
        queryOrUrl.startsWith('?') || queryOrUrl.startsWith('#')
          ? queryOrUrl.substring(1)
          : queryOrUrl;
      params = new URLSearchParams(queryOrUrl);
    }
  }

  const expiresIn = params.get('expires_in');

  return {
    state: params.get('state') ?? undefined,
    accessToken: params.get('access_token') ?? undefined,
    idToken: params.get('id_token') ?? undefined,
    refreshToken: params.get('refresh_token') ?? undefined,
    sessionState: params.get('session_state') ?? undefined,
    expiresIn: expiresIn ? parseInt(expiresIn, 10) : undefined,
    code: params.get('code') ?? undefined,
    error: params.get('error') ?? undefined,
    errorDescription: params.get('error_description') ?? undefined,
  };
};

/**
 * Encrypts a given string using a secret with AES-GCM.
 *
 * @param data - The plaintext data to encrypt.
 * @param secret - The secret used to derive the encryption key.
 * @returns Base64-encoded ciphertext.
 */
export const encrypt = async (
  data: string,
  secret: string
): Promise<string> => {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const iv = crypto.getRandomValues(new Uint8Array(GCM_IV_LENGTH));
  const plaintextBuffer = stringToArrayBuffer(data);
  const key = await deriveEncryptionKey(secret, salt);

  const ciphertext = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
    },
    key,
    plaintextBuffer as BufferSource
  );

  const resultBuffer = new Uint8Array(
    salt.byteLength + iv.byteLength + ciphertext.byteLength
  );
  resultBuffer.set(salt, 0);
  resultBuffer.set(iv, salt.byteLength);
  resultBuffer.set(new Uint8Array(ciphertext), salt.byteLength + iv.byteLength);

  return arrayBufferToBase64(resultBuffer);
};

/**
 * Decrypts an encrypted string using a secret with AES-GCM.
 *
 * @param encrypted - The ciphertext to decrypt.
 * @param secret - The secret used to derive the decryption key.
 *
 * @returns Decrypted plaintext string or undefined if decryption fails.
 */
export const decrypt = async (
  encrypted: string,
  secret: string
): Promise<string | undefined> => {
  try {
    const ciphertextBuffer = Uint8Array.from(atob(fromB64Url(encrypted)), c =>
      c.charCodeAt(0)
    );

    if (ciphertextBuffer.byteLength <= SALT_LENGTH + GCM_IV_LENGTH) {
      return undefined;
    }

    const salt = ciphertextBuffer.slice(0, SALT_LENGTH);
    const iv = ciphertextBuffer.slice(SALT_LENGTH, SALT_LENGTH + GCM_IV_LENGTH);
    const encryptedPayload = ciphertextBuffer.slice(
      SALT_LENGTH + GCM_IV_LENGTH
    );
    const key = await deriveEncryptionKey(secret, salt);
    const decryptedBuffer = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv,
      },
      key,
      encryptedPayload
    );
    return arrayBufferToString(decryptedBuffer);
  } catch {
    return undefined;
  }
};

/**
 * Encrypts a MonoCloud session object with a secret and optional time-to-live (TTL).
 *
 * @param session - The session object to encrypt.
 * @param secret - The secret used for encryption.
 * @param ttl - Optional time-to-live in seconds, after which the session expires.
 * @returns Encrypted session string.
 */
export const encryptSession = (
  session: MonoCloudSession,
  secret: string,
  ttl?: number
): Promise<string> => {
  let expiresAt;

  if (typeof ttl === 'number') {
    expiresAt = now() + ttl;
  }
  return encrypt(JSON.stringify({ session, expiresAt }), secret);
};

/**
 * Decrypts an encrypted MonoCloud session.
 *
 * @param encryptedSession - The encrypted session string to decrypt.
 * @param secret - The secret used for decryption.
 *
 * @returns Session object on success.
 *
 * @throws If decryption fails or the session has expired
 */
export const decryptSession = async (
  encryptedSession: string,
  secret: string
): Promise<MonoCloudSession> => {
  const decryptedText = await decrypt(encryptedSession, secret);

  if (!decryptedText) {
    throw new Error('Invalid session data');
  }

  let payload: { session: MonoCloudSession; expiresAt?: number };
  try {
    payload = JSON.parse(decryptedText);
  } catch {
    throw new Error('Invalid session data');
  }

  const { session, expiresAt } = payload;

  if (!session) {
    throw new Error('Invalid session data');
  }

  if (typeof expiresAt === 'number' && expiresAt < now()) {
    throw new Error('Session Expired');
  }

  return session;
};

/**
 * Encrypts an AuthState object with a secret and optional time-to-live (TTL).
 *
 * @param authState - A type that extends the AuthState interface.
 * @param secret - The secret used for encryption.
 * @param ttl - Optional time-to-live in seconds, after which the auth state expires.
 *
 * @returns Encrypted auth state string.
 */
export const encryptAuthState = <T extends AuthState>(
  authState: T,
  secret: string,
  ttl?: number
): Promise<string> => {
  let expiresAt;

  if (typeof ttl === 'number') {
    expiresAt = now() + ttl;
  }

  return encrypt(JSON.stringify({ authState, expiresAt }), secret);
};

/**
 * Decrypts an encrypted AuthState.
 *
 * @param encryptedAuthState - The encrypted auth state string to decrypt.
 * @param secret - The secret used for decryption.
 *
 * @returns State object on success
 *
 * @throws If decryption fails or the auth state has expired
 *
 */
export const decryptAuthState = async <T extends AuthState>(
  encryptedAuthState: string,
  secret: string
): Promise<T> => {
  const decryptedText = await decrypt(encryptedAuthState, secret);

  if (!decryptedText) {
    throw new Error('Invalid auth state');
  }

  let payload: { authState: T; expiresAt?: number };
  try {
    payload = JSON.parse(decryptedText);
  } catch {
    throw new Error('Invalid auth state');
  }

  const { authState, expiresAt } = payload;

  if (!authState) {
    throw new Error('Invalid auth state');
  }

  if (typeof expiresAt === 'number' && expiresAt < now()) {
    throw new Error('Auth state expired');
  }

  return authState;
};

/**
 * Checks if a user is a member of a specified group or groups.
 *
 * @param user - The user.
 * @param groups - An array of group names or IDs to check membership against.
 * @param groupsClaim - The claim in the user object that contains groups.
 * @param matchAll - If `true`, requires the user to be in all specified groups; if `false`, checks if the user is in at least one of the groups.
 *
 * @returns `true` if the user is in the specified groups, `false` otherwise.
 */
export const isUserInGroup = (
  user: MonoCloudUser | IdTokenClaims,
  groups: string[],
  groupsClaim = 'groups',
  matchAll = false
): boolean => {
  const userGroups = (user[groupsClaim] ?? []) as (
    | string
    | { id: string; name: string }
  )[];

  if (!Array.isArray(groups) || groups.length === 0) {
    return true;
  }

  if (!Array.isArray(userGroups) || userGroups.length === 0) {
    return false;
  }

  let matched = false;

  for (const expectedGroup of groups) {
    const userInGroup = userGroups.some(
      g =>
        (typeof g === 'string' && g === expectedGroup) ||
        (typeof g === 'object' &&
          (g.id === expectedGroup || g.name === expectedGroup))
    );

    if (!matchAll && userInGroup) {
      return userInGroup;
    }

    if (matchAll && !userInGroup) {
      return false;
    }

    matched = userInGroup;
  }

  return matched;
};

/**
 * Generates a random state string.
 */
export const generateState = (): string => randomBytes(32);

/**
 * Generates a PKCE (Proof Key for Code Exchange) code verifier and code challenge.
 *
 */
export const generatePKCE = async (): Promise<{
  codeVerifier: string;
  codeChallenge: string;
}> => {
  const codeVerifier = randomBytes(32);
  return {
    codeVerifier,
    codeChallenge: encodeBase64Url(
      await crypto.subtle.digest(
        'SHA-256',
        stringToArrayBuffer(codeVerifier) as BufferSource
      )
    ),
  };
};

/**
 * Generates a random nonce string.
 */
export const generateNonce = (): string => randomBytes(32);

/**
 * @ignore
 * Merges multiple arrays of strings, removing duplicates.
 *
 * @param args - List of arrays to merge
 *
 * @returns A new array containing unique strings from both input arrays, or `undefined` if both inputs are `undefined`.
 */
export const mergeArrays = (
  ...args: (string[] | undefined)[]
): string[] | undefined => {
  const arrays = args.filter(x => Array.isArray(x));
  return arrays.length > 0
    ? Array.from(new Set(arrays.reduce((acc, x) => [...acc, ...x], [])))
    : undefined;
};
