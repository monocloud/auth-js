/* eslint-disable import/no-extraneous-dependencies */
import { describe, expect, it, vi } from 'vitest';
import { travel } from 'timekeeper';
import {
  AuthState,
  JwsHeaderParameters,
  Jwk,
  MonoCloudSession,
  AccessToken,
} from '../src';
import {
  decrypt,
  decryptAuthState,
  decryptSession,
  encrypt,
  encryptAuthState,
  encryptSession,
  generateNonce,
  generatePKCE,
  generateState,
  isUserInGroup,
  mergeArrays,
  parseCallbackParams,
} from '../src/utils';
import {
  arrayBufferToBase64,
  arrayBufferToString,
  decodeBase64Url,
  encodeBase64Url,
  ensureLeadingSlash,
  findToken,
  fromB64Url,
  getBoolean,
  getNumber,
  getPublicSigKeyFromIssuerJwks,
  isAbsoluteUrl,
  isJsonObject,
  isPresent,
  isSameHost,
  now,
  parseSpaceSeparated,
  parseSpaceSeparatedSet,
  randomBytes,
  removeTrailingSlash,
  setsEqual,
  stringToArrayBuffer,
  toB64Url,
} from '../src/utils/internal';

describe('getBoolean', () => {
  it('should return true when value is "true"', () => {
    const result = getBoolean('true');
    expect(result).toBe(true);
  });

  it('should return false when value is "false"', () => {
    const result = getBoolean('false');
    expect(result).toBe(false);
  });

  it('should return undefined when value is undefined', () => {
    const result = getBoolean(undefined);
    expect(result).toBeUndefined();
  });

  it('should return undefined when value is not "true" or "false"', () => {
    const result = getBoolean('foo');
    expect(result).toBeUndefined();
  });

  it('should ignore leading and trailing whitespace', () => {
    const result = getBoolean('  true  ');
    expect(result).toBe(true);
  });

  it('should ignore case sensitivity', () => {
    const result = getBoolean('TrUe');
    expect(result).toBe(true);
  });
});

describe('getNumber', () => {
  it('should return the parsed number when value is a valid number string', () => {
    const result = getNumber('123');
    expect(result).toBe(123);
  });

  it('should return undefined when value is an empty string', () => {
    const result = getNumber('');
    expect(result).toBeUndefined();
  });

  it('should return undefined when value is undefined', () => {
    const result = getNumber(undefined);
    expect(result).toBeUndefined();
  });

  it('should return undefined when value is not a valid number string', () => {
    const result = getNumber('foo');
    expect(result).toBeUndefined();
  });

  it('should ignore leading and trailing whitespace', () => {
    const result = getNumber('  456  ');
    expect(result).toBe(456);
  });
});

describe('toB64Url', () => {
  it('should convert to base64Url', () => {
    expect(toB64Url('asdfg+hjkl12345/==')).toBe('asdfg-hjkl12345_');
  });
});

describe('fromB64Url', () => {
  it('should convert from base64Url', () => {
    expect(fromB64Url('asdfg-hjkl12345_')).toBe('asdfg+hjkl12345/');
  });
});

describe('ensureLeadingSlash', () => {
  it('should return the input string with a leading slash if it does not have one', () => {
    const result = ensureLeadingSlash('path');
    expect(result).toBe('/path');
  });

  it('should return the input string as is if it already has a leading slash', () => {
    const result = ensureLeadingSlash('/path');
    expect(result).toBe('/path');
  });

  it('should return an empty string if the input is undefined', () => {
    const result = ensureLeadingSlash(undefined);
    expect(result).toBe(undefined);
  });

  it('should return an empty string if the input is an empty string', () => {
    const result = ensureLeadingSlash('');
    expect(result).toBe('');
  });

  it('should trim leading and trailing whitespace before adding a leading slash', () => {
    const result = ensureLeadingSlash('  path  ');
    expect(result).toBe('/path');
  });
});

describe('removeTrailingSlash', () => {
  it('should remove the trailing slash if present', () => {
    const result = removeTrailingSlash('path/');
    expect(result).toBe('path');
  });

  it('should return the input string as is if it does not have a trailing slash', () => {
    const result = removeTrailingSlash('path');
    expect(result).toBe('path');
  });

  it('should return an empty string if the input is undefined', () => {
    const result = removeTrailingSlash(undefined);
    expect(result).toBe(undefined);
  });

  it('should return an empty string if the input is an empty string', () => {
    const result = removeTrailingSlash('');
    expect(result).toBe('');
  });

  it('should trim leading and trailing whitespace before removing the trailing slash', () => {
    const result = removeTrailingSlash('  path/  ');
    expect(result).toBe('path');
  });
});

describe('isPresent', () => {
  it('should return true when value is a non-empty string', () => {
    const result = isPresent('value');
    expect(result).toBe(true);
  });

  it('should return false when value is an empty string', () => {
    const result = isPresent('');
    expect(result).toBe(false);
  });

  it('should return false when value is undefined', () => {
    const result = isPresent(undefined);
    expect(result).toBe(false);
  });

  it('should return false when value is null', () => {
    const result = isPresent(null as any);
    expect(result).toBe(false);
  });

  it('should return false when value is a string with only whitespace', () => {
    const result = isPresent('   ');
    expect(result).toBe(false);
  });

  it('should return true when value is a boolean (false)', () => {
    const result = isPresent(false);
    expect(result).toBe(true);
  });

  it('should return true when value is a boolean (true)', () => {
    const result = isPresent(true);
    expect(result).toBe(true);
  });

  it('should return true when value is a number', () => {
    const result = isPresent(0);
    expect(result).toBe(true);
  });
});

describe('now', () => {
  it('should return the current timestamp in seconds', () => {
    const currentTimestamp = Math.floor(Date.now() / 1000);
    const result = now();
    expect(result - currentTimestamp).toBeLessThanOrEqual(1);
  });
});

describe('isAbsoluteUrl', () => {
  it('should return true for absolute URLs starting with "http:"', () => {
    const result = isAbsoluteUrl('http://example.com');
    expect(result).toBe(true);
  });

  it('should return true for absolute URLs starting with "https:"', () => {
    const result = isAbsoluteUrl('https://example.com');
    expect(result).toBe(true);
  });

  it('should return false for relative URLs', () => {
    const result = isAbsoluteUrl('/path');
    expect(result).toBe(false);
  });

  it('should return false for undefined URLs', () => {
    const result = isAbsoluteUrl(undefined as any);
    expect(result).toBe(false);
  });

  it('should return false for empty URLs', () => {
    const result = isAbsoluteUrl('');
    expect(result).toBe(false);
  });

  it('should return false for URLs starting with "http:" but not followed by "//"', () => {
    const result = isAbsoluteUrl('http:path');
    expect(result).toBe(false);
  });

  it('should return false for URLs starting with "https:" but not followed by "//"', () => {
    const result = isAbsoluteUrl('https:path');
    expect(result).toBe(false);
  });
});

describe('isSameHost', () => {
  it('should return true when the origins of the URLs are the same', () => {
    const url = 'https://example.com/path';
    const urlToCheck = 'https://example.com/other-path';
    const result = isSameHost(url, urlToCheck);
    expect(result).toBe(true);
  });

  it('should return false when the origins of the URLs are different', () => {
    const url = 'https://example.com/path';
    const urlToCheck = 'https://example.org/other-path';
    const result = isSameHost(url, urlToCheck);
    expect(result).toBe(false);
  });

  it('should return false when the URLs are not valid', () => {
    const url = 'invalid-url';
    const urlToCheck = 'https://example.com/other-path';
    const result = isSameHost(url, urlToCheck);
    expect(result).toBe(false);
  });
});

describe('genarateState', () => {
  it('should genarate non empty random string as a state', () => {
    const result = generateState();
    expect(result.length).toBe(43);
    expect(result).toBeTypeOf('string');
  });
});

describe('genarateNonce', () => {
  it('should genarate non empty random string as a nonce', () => {
    const result = generateNonce();
    expect(result.length).toBe(43);
    expect(result).toBeTypeOf('string');
  });
});

describe('genaratePKCE', () => {
  it('should genarate non empty codeVerifier and codeChallenge', async () => {
    const result = await generatePKCE();
    expect(result.codeVerifier.length).toBeGreaterThanOrEqual(43);
    expect(result.codeVerifier).toBeTypeOf('string');
    expect(result.codeChallenge.length).toBeGreaterThanOrEqual(43);
    expect(result.codeChallenge).toBeTypeOf('string');
  });
});

describe('encrypt and decrypt', () => {
  const data = 'dataforencryption';
  const password = 'password';

  it('should encrypt and decrypt data', async () => {
    const encrypted = await encrypt(data, password);
    const decrypted = await decrypt(encrypted, password);
    expect(decrypted).toBe(data);
  });

  it('encrypt should not produce same result everytime', async () => {
    const encrypted1 = await encrypt(data, password);
    const encrypted2 = await encrypt(data, password);
    expect(encrypted2).not.toBe(encrypted1);
  });

  it('incorrect secret should not decrypt', async () => {
    const encrypted = await encrypt(data, password);
    const decrypted = await decrypt(encrypted, 'nope');
    expect(decrypted).toBe(undefined);
  });

  it('decrypt should return undefined if encrypted data is invalid', async () => {
    const encrpyted = await encrypt(data, password);
    const decrypted = await decrypt(`${encrpyted}123`, password);
    expect(decrypted).toBe(undefined);
  });

  it('returns undefined when payload is too short (no ciphertext after salt+iv)', async () => {
    const SALT_LENGTH = 16;
    const GCM_IV_LENGTH = 12;

    const raw = new Uint8Array(SALT_LENGTH + GCM_IV_LENGTH);

    const b64 = btoa(String.fromCharCode(...raw)); // standard base64
    const b64url = b64
      .replace(/=+$/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');

    await expect(decrypt(b64url, 'any-secret')).resolves.toBeUndefined();
  });
});

describe('isUserInGroup', () => {
  it('should return true when the groups expected are empty', () => {
    const result = isUserInGroup({ sub: 'sun' }, []);
    expect(result).toBe(true);
  });

  it.each([
    undefined,
    (): void => {},
    'groups',
    12345678,
    true,
    null,
    NaN,
    Symbol(),
  ])(
    'should return false when the users group claim is not a json array',
    (groups: any) => {
      const result = isUserInGroup({ sub: 'sun', groups }, ['group1']);
      expect(result).toBe(false);
    }
  );

  it('should return true when the expected groups is not an array', () => {
    const result = isUserInGroup({ sub: 'sun' }, {} as string[]);
    expect(result).toBe(true);
  });

  it('should be able to take in custom groups claim name', () => {
    const result = isUserInGroup(
      { sub: 'sun', custom_groups: ['test'] },
      ['test'],
      'custom_groups'
    );
    expect(result).toBe(true);
  });

  it.each([
    [[], ['test'], false, false],
    [undefined, ['test'], false, false],
    [['test'], ['test'], true, false],
    [['test'], ['test', 'test_2'], true, false],
    [['test '], ['test'], false, false],
    [
      ['2c17c510-ba14-43d5-a1cf-4bf9bd0523b8'],
      ['2c17c510-ba14-43d5-a1cf-4bf9bd0523b8'],
      true,
      false,
    ],
    [
      [{ id: '2c17c510-ba14-43d5-a1cf-4bf9bd0523b8', name: 'test' }],
      ['2c17c510-ba14-43d5-a1cf-4bf9bd0523b8'],
      true,
      false,
    ],
    [
      [{ id: '2c17c510-ba14-43d5-a1cf-4bf9bd0523b8', name: 'test' }],
      ['test'],
      true,
      false,
    ],
    [['group1', 'group2'], ['group1', 'group3'], false, true],
    [['group1', 'group2'], ['group1', 'group2'], true, true],
    [['group1', 'group2', 'group3'], ['group1', 'group2'], true, true],
  ])(
    'should return expected result',
    (userGroups, expectedGroups, expectedResult, shouldMatchAll) => {
      const result = isUserInGroup(
        { sub: '', groups: userGroups },
        expectedGroups,
        undefined,
        shouldMatchAll
      );

      expect(result).toBe(expectedResult);
    }
  );
});

describe('encryptSession and decryptSession', () => {
  const session: MonoCloudSession = { user: { sub: 'username' } };

  it('should encrypt and decrypt session', async () => {
    const encrypted = await encryptSession(session, 'password');
    const decrypted = await decryptSession(encrypted, 'password');
    expect(decrypted).toStrictEqual(session);
  });

  it('should not decrypt with incorrect secret', async () => {
    const encrypted = await encryptSession(session, 'password');

    await expect(
      decryptSession(encrypted, 'incorrectpassword')
    ).rejects.toThrow('Invalid session data');
  });

  it('should not decrypt with incorrect session data', async () => {
    const encrypted = await encryptSession(session, 'password');

    await expect(
      decryptSession(`${encrypted}asdfs`, 'password')
    ).rejects.toThrow('Invalid session data');
  });

  it('should not decrypt session when session expires', async () => {
    const encrypted = await encryptSession(session, 'password', 1);
    travel((now() + 2) * 1000);

    await expect(decryptSession(encrypted, 'password')).rejects.toThrow(
      'Session Expired'
    );
  });

  it('should not decrypt with invalid json', async () => {
    const encrypted = await encrypt('{', 'password');

    await expect(decryptSession(encrypted, 'password')).rejects.toThrow(
      'Invalid session data'
    );
  });

  it('should not decrypt with invalid null session', async () => {
    const encrypted = await encrypt('{}', 'password');

    await expect(decryptSession(encrypted, 'password')).rejects.toThrow(
      'Invalid session data'
    );
  });
});

describe('encryptAuthstate and decryptAuthState', () => {
  it('should encrypt and decrypt auth state', async () => {
    const authState: AuthState = {
      nonce: 'nonce',
      state: 'state',
      scopes: 'openid',
    };
    const encrypted = await encryptAuthState(authState, 'password');
    const decrypted = await decryptAuthState(encrypted, 'password');
    expect(decrypted).toStrictEqual(authState);
  });

  it('should not decrypt with incorrect secret', async () => {
    const authState: AuthState = {
      nonce: 'nonce',
      state: 'state',
      scopes: 'openid',
    };
    const encrypted = await encryptAuthState(authState, 'password');
    await expect(
      decryptAuthState(encrypted, 'incorrectpassword')
    ).rejects.toThrow('Invalid auth state');
  });

  it('should not decrypt with invalid auth state', async () => {
    const authState: AuthState = {
      nonce: 'nonce',
      state: 'state',
      scopes: 'openid',
    };
    const encrypted = await encryptAuthState(authState, 'password');

    await expect(
      decryptAuthState(`${encrypted}asdfs`, 'password')
    ).rejects.toThrow('Invalid auth state');
  });

  it('should not decrypt when auth state expires', async () => {
    const authState: AuthState = {
      nonce: 'nonce',
      state: 'state',
      scopes: 'openid',
    };
    const encrypted = await encryptAuthState(authState, 'password', 1);
    travel((now() + 2) * 1000);

    await expect(decryptAuthState(encrypted, 'password')).rejects.toThrow(
      'Auth state expired'
    );
  });

  it('should encrypt extra data in auth state', async () => {
    const encrypted = await encryptAuthState(
      {
        state: 'sdfdgdgd',
        nonce: 'sfddgs',
        codeVerifier: 'sfdsfsdfs',
        maxAge: 2,
        abc: 124,
        hello: { json: 'yes' },
        scopes: 'openid',
      },
      'password'
    );
    const decrypted = await decryptAuthState(encrypted, 'password');
    expect(decrypted).toStrictEqual({
      state: 'sdfdgdgd',
      nonce: 'sfddgs',
      codeVerifier: 'sfdsfsdfs',
      maxAge: 2,
      abc: 124,
      hello: { json: 'yes' },
      scopes: 'openid',
    });
  });

  it('should not decrypt with invalid json', async () => {
    const encrypted = await encrypt('{', 'password');

    await expect(decryptAuthState(encrypted, 'password')).rejects.toThrow(
      'Invalid auth state'
    );
  });

  it('should not decrypt with invalid null auth state', async () => {
    const encrypted = await encrypt('{}', 'password');

    await expect(decryptAuthState(encrypted, 'password')).rejects.toThrow(
      'Invalid auth state'
    );
  });
});

describe('parseCallbackParams', () => {
  it('should give back callback params from a url', () => {
    const result = parseCallbackParams(
      'https://www.example.com/callback?state=abc123&access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9&expires_in=40&id_token=eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ&refresh_token=def456&session_state=ghi789&code=xyz789&error=invalid_url&error_description=theurlparametersareinvalid'
    );
    expect(result).toStrictEqual({
      state: 'abc123',
      accessToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
      idToken:
        'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ',
      refreshToken: 'def456',
      sessionState: 'ghi789',
      expiresIn: 40,
      code: 'xyz789',
      error: 'invalid_url',
      errorDescription: 'theurlparametersareinvalid',
    });
  });

  it('should extract callback params from URLSearchparams', () => {
    const url = new URLSearchParams();
    url.append('state', 'state');
    url.append('code', 'code');

    const result = parseCallbackParams(url);
    expect(result).toStrictEqual({
      state: 'state',
      accessToken: undefined,
      idToken: undefined,
      refreshToken: undefined,
      sessionState: undefined,
      expiresIn: undefined,
      code: 'code',
      error: undefined,
      errorDescription: undefined,
    });
  });

  it('shoud parse a query string', () => {
    const result = parseCallbackParams(
      '?access_token=at&code=code&state=state'
    );
    expect(result).toStrictEqual({
      state: 'state',
      accessToken: 'at',
      idToken: undefined,
      refreshToken: undefined,
      sessionState: undefined,
      expiresIn: undefined,
      code: 'code',
      error: undefined,
      errorDescription: undefined,
    });
  });

  it('should parse a formurl encoded data', () => {
    const result = parseCallbackParams('state=state&access_token=token');
    expect(result).toStrictEqual({
      state: 'state',
      accessToken: 'token',
      idToken: undefined,
      refreshToken: undefined,
      expiresIn: undefined,
      sessionState: undefined,
      code: undefined,
      error: undefined,
      errorDescription: undefined,
    });
  });

  it('should give empty callback params if the callback contains no valid params', () => {
    const result = parseCallbackParams('stringwithoutparams ');
    expect(result).toStrictEqual({
      state: undefined,
      accessToken: undefined,
      idToken: undefined,
      refreshToken: undefined,
      sessionState: undefined,
      expiresIn: undefined,
      code: undefined,
      error: undefined,
      errorDescription: undefined,
    });
  });

  it('should extract callback params from URL`', () => {
    const url = new URL('https://www.example.com/?state=abc123');
    const result = parseCallbackParams(url);
    expect(result).toStrictEqual({
      state: 'abc123',
      accessToken: undefined,
      idToken: undefined,
      refreshToken: undefined,
      expiresIn: undefined,
      sessionState: undefined,
      code: undefined,
      error: undefined,
      errorDescription: undefined,
    });
  });
});

describe('stringToArrayBuffer', () => {
  it('should convert string to ArrayBuffer', () => {
    expect(stringToArrayBuffer('string')).toEqual(
      new Uint8Array([115, 116, 114, 105, 110, 103])
    );
  });
});

describe('arrayBufferToString', () => {
  it('should convert ArrayBuffer to string', () => {
    const result = arrayBufferToString(
      new Uint8Array([115, 116, 114, 105, 110, 103]) as unknown as ArrayBuffer
    );
    expect(result).toBe('string');
  });
});

describe('encodeBase64Url', () => {
  it.each([
    [new Uint8Array([115, 116, 114, 105, 110, 103]).buffer, 'c3RyaW5n'],
    [new Uint8Array([110, 97, 109, 101, 61, 97, 43, 98, 47]), 'bmFtZT1hK2Iv'],
  ])('should encode %o to %s', (bufferValue, expected) => {
    expect(encodeBase64Url(bufferValue)).toBe(expected);
  });
});

describe('decodeBase64Url', () => {
  it.each([
    ['aGVsbG9fd29ybGQtMTIz', 'hello_world-123'],
    ['bmFtZT1hK2IvYw', 'name=a+b/c'],
    ['cGxhaW4tdGV4dA', 'plain-text'],
  ])('should decode Base64Url %s encoded %s', (encodedValue, expected) => {
    expect(decodeBase64Url(encodedValue)).toBe(expected);
  });
});

describe('arrayBufferToBase64', () => {
  it('should convert array buffer to base64', () => {
    expect(arrayBufferToBase64(new Uint8Array([110, 97, 109, 101]))).toBe(
      'bmFtZQ'
    );
  });
});

describe('randomBytes', () => {
  it('should create a random string (default value for number = 32)', () => {
    const result = randomBytes();
    expect(result).toHaveLength(43);
    expect(result).toBeTypeOf('string');
  });

  it.each([
    [8, 11],
    [11, 15],
    [20, 27],
  ])(
    'randomBytes with value %i should return a string of length %i',
    (number, expectedLength) => {
      const result = randomBytes(number);
      expect(result).toHaveLength(expectedLength);
      expect(result).toBeTypeOf('string');
    }
  );
});

describe('isJsonObject()', () => {
  it('should return true for an object', () => {
    const obj = {};
    expect(isJsonObject(obj)).toBe(true);
  });
});

describe('getPublicSigKeyFromIssuerJwks() Tests', () => {
  it('should throw an error if the header does not belong in supported algorithms', async () => {
    try {
      await getPublicSigKeyFromIssuerJwks([], {
        alg: 'HS256',
      } as unknown as JwsHeaderParameters);
    } catch (error) {
      expect((error as any).message).toBe('unsupported JWS "alg" identifier');
    }
  });

  it.each([
    ['PS256', {}],
    ['ES256', {}],
    ['RS256', {}],
    ['PS384', {}],
    ['ES384', {}],
    ['RS384', {}],
    ['PS512', {}],
    ['ES512', {}],
    ['RS512', {}],
    ['ES256', { kty: 'EC', kid: '1' }],
    ['ES384', { kty: 'EC', kid: '1' }],
    ['ES512', { kty: 'EC', kid: '1' }],
    ['ES512', { kty: 'EC', kid: '2' }],
    ['ES512', { kty: 'EC', kid: '1', alg: 'RS256' }],
    ['ES512', { kty: 'EC', kid: '1', alg: 'ES512', use: 'verify' }],
    [
      'ES512',
      { kty: 'EC', kid: '1', alg: 'ES512', use: 'sig', key_ops: ['none'] },
    ],
    [
      'ES512',
      { kty: 'EC', kid: '1', alg: 'ES512', use: 'sig', key_ops: ['verify'] },
    ],
  ])(
    'should throw an error if there are no matches found in JWKS',
    async (alg, jwk) => {
      try {
        await getPublicSigKeyFromIssuerJwks(
          [jwk] as unknown as Jwk[],
          {
            alg,
            kid: '1',
          } as unknown as JwsHeaderParameters
        );
        throw new Error();
      } catch (error) {
        expect((error as any).message).toBe(
          'error when selecting a JWT verification key, multiple applicable keys found, a "kid" JWT Header Parameter is required'
        );
      }
    }
  );

  it('should throw an error if the key contains private parts', async () => {
    const cryptoSpy = vi
      .spyOn(crypto.subtle, 'importKey')
      .mockReturnValue(Promise.resolve({ type: 'private' } as CryptoKey));
    try {
      await getPublicSigKeyFromIssuerJwks(
        [{ alg: 'RS256', kty: 'RSA' }] as unknown as Jwk[],
        {
          alg: 'RS256',
        } as unknown as JwsHeaderParameters
      );
      throw new Error();
    } catch (error) {
      expect((error as any).message).toBe(
        'jwks_uri must only contain public keys'
      );
    } finally {
      cryptoSpy.mockRestore();
    }
  });

  it.each([
    {
      kty: 'RSA',
      e: 'AQAB',
      use: 'sig',
      alg: 'RS256',
      n: 'qO5QAj4fepBXdDXUfuhSYF2iMLRDHUrh0sBooaz9gYtwex6KO9qetha5SU63_asegtVFHCIRMM29pDtH7wMdI0SSXBQbJxtiSD9Bc8Tzqpgc85rCtC3PsBqBWlZBQ3VJsEmxa0VcqtLk21TJCskBJ8sg3FApvllOAa-VKjfMqGEt-uUS8gJf6fG8USNhHfKRBu-bAaOIWuL-nbm0CRVl8nSiWdX8Ovu3qEEG_VlYgs0okUk4L4gWwcdQ0kXtO6qHFHm7UL4HFkAMOrL8Ya7EF_kzT0n_-LSAfTJWd-QoqEXwwofAaAxzjYnEenqOGv4vPWrfWJPaEMuXLVkxHGNZpQ',
    },
    {
      kty: 'RSA',
      e: 'AQAB',
      use: 'sig',
      alg: 'RS384',
      n: '4OYVcVXCd9O-5O-3UdvaUe5etZHvZXE2nznkwTmanfdIiUkT0wWe2gLU75I9vzHgZDT6_t1xiJWiWUkJdWJskL3RA_YNnRDaG3_lQWG_kLgIOEqoOmSgb7EKNiy0VrloXUAs2IgMr3Ni_25ZCywJnsoz-ZGYUh81XDdEpEevexxrhadZHPO8r1xVJfTJdmh8HY6UqmD6vOQFuI4QGkySAiCvXSv0brWWPfQnXuysoUsuE91yNamK-XhssiImDHMkV8VL2AlPRuX65Bt-aGA-qk-XU46-JZN_ExWWzdSeoGte08aL72alRyRXApw2I7GGVSeZOz1g4A71xzqBecAkVQ',
    },
    {
      kty: 'RSA',
      e: 'AQAB',
      use: 'sig',
      alg: 'RS512',
      n: 'xtqqTfdXkDvrOKbFvCqJPpUH8qlYNNDlc_qOeop4pxM65bhSO024Xgtm8zmCaPyjHGj-Ut-s1ZRlAi8dALzAuSldAEo_lAtduk3H3l1Jk589PbT2y72hBGWGmmL6aE6ff7KWob6I8bASu9kJfQNWnW7ElD_Vx_5diQc_z-4uh4Z91T8yzG3LDVr5C_-j3zktoBlJglLdShkbyn0wUt4dq5pqO1sBQpaaAxrCNjF71qfjkkSSDdVPD0pU6ZxW497DNr84GzcuAK4I0cAkft-ZfmaSK9VEHJRyTwPeXWGLNbq4pbjO738uJZjFFhFqwrSRBB7L6dj-K7CkGaN2uB0NaQ',
    },
    {
      kty: 'RSA',
      e: 'AQAB',
      use: 'sig',
      alg: 'PS256',
      n: 'iNvTrr5rW0Id4RRPWwzhFjy4_TEljZKO6iVwDtHuI1SfS9g4toG9nIPzDpTQI31KNl5nivssBiIFpgizhmu5l_0y6QA4HvGMz7-lOTXO1IGQ-qlVd0sdSpFBlhOA0YZAgPDHjTPo9Jv8_bJDrRacDsO9-6hjPntaw8ipxlFcX8XkpezzAIqURjKuCNKH5199-COFYSjQT8q_7wKYSv1c_9dc3kGXRrtxmVjZnz-F1DRDGgnIR48x8B2haaX_jE_k9wJEAAa8lj7chdU4Lrn4EW6umnsHvJzE9VAab057rlPilH9dB5_O1u7dSPtdf9yPguHAy1s4CrV0ykRZjT9ELw',
    },
    {
      kty: 'RSA',
      e: 'AQAB',
      use: 'sig',
      alg: 'PS384',
      n: 'kGw_KKX8CL8oO3kxHMnk_bznFFsCd6R_7XANiNWL7rliWi9ZiaEUHpt7Z_sBq3CDUsPbge0cQ9PQKTWnuCTD10uQMks87w7KDCErx9H1DyACxQ4nRP3rgg0JkDAnPXupIOGyp9MVOYGcrAJXsNtwhe3pA4Pbyxh6al-4_Q0zz_uAu2twsO3Qw_U28WfC_XETK0L1Xw36TTjV5BjUipn8ukpQtC2RQdV83wd4-lWP6vAsyMnYwUpii8fU7xZ6bcsnHooM0FU_bdyRLDPDeo0T1xiqBMjfG9CFe6MtQxmVuWl9qN-PxdqkSWMb0M7aQ653dxs6c4E05ebnb41eCjMs8w',
    },
    {
      kty: 'RSA',
      e: 'AQAB',
      use: 'sig',
      alg: 'PS512',
      n: '1Vwsujst0y0hBDf28ilDq9iEjCdyyGKsIPUjcvHNT1zpKxVHzfweEUkfelME9WYEJoMXmZiSDepzVFEA8J5CqRIzwks8orbfoSiv9w-PFkZS_cyLJo0gldZDgUybjlcCW2Zr44EIvTGOrdWx9oQs7dOL62np56oV-3F8DZ8gXLqXAQrPMckDd0tgKfpn9dpTDmQL6-DBPBkFuGmBAFFyST94hY2Zj5cASyQldTdEYbfMoO0EFNnRgAeytCA66ZLYAsu_zZtZ9afCkG5LPqI08di8oMLhUH61Uf97fMlNxWChuf4k3YIqmNH1wmaI818ptQD4nNTiGVe_kQ35alJ3cw',
    },
    {
      kty: 'EC',
      use: 'sig',
      crv: 'P-256',
      x: 'JCQp1z0Kl3pMtVRHFxMXqkpqultZagKhP_uEE-d0A_c',
      y: 'THZgIatJLEPr1ysbM9w3z8AA7XIVHSsqZG_Q0kht5kE',
      alg: 'ES256',
    },
    {
      kty: 'EC',
      use: 'sig',
      crv: 'P-384',
      x: 'iL2e_FQ4IQAUAxEzi2Ve41UWxNhvnplpgz14Ef_u4ADMWgpuxRwXDndyh13c-Pie',
      y: '9b57xsfdfWL-jQYmA7nhYTRsSnuNt3e-V3Ck9CUvYClrxmbHrr9uwEG-D7YVl_ws',
      alg: 'ES384',
    },
    {
      kty: 'EC',
      use: 'sig',
      crv: 'P-521',
      x: 'AJWbaY2C6dXGnRncC9hgxYpo_ZbFUPPWU2aCbTmH5j3PzvQvpbRL-GR7VbR-HXUgfqpYkpBFFhHGx3YGMTB_qaHj',
      y: 'AUNoMcW--3drxWRO5VqXW1nJ1ssraHOXZL6yuhs3MWdlqYrSJXxGlxoVABGeNEys2kvr9U7e-aXLqoJkbnD-YoDK',
      alg: 'ES512',
    },
  ])('should convert jwk to crypto key', async key => {
    const cryptoKey = await getPublicSigKeyFromIssuerJwks(
      [key] as unknown as Jwk[],
      {
        alg: key.alg,
      } as unknown as JwsHeaderParameters
    );

    expect(cryptoKey).toBeTypeOf('object');
  });
});

describe('Invalid JSON Object Scenarios', () => {
  it('should return false for null', () => {
    expect(isJsonObject(null)).toBe(false);
  });

  it('should return false for undefined', () => {
    expect(isJsonObject(undefined)).toBe(false);
  });

  it('should return false for an array', () => {
    expect(isJsonObject([])).toBe(false);
    expect(isJsonObject([1, 2, 3])).toBe(false);
  });

  it('should return false for primitive types', () => {
    expect(isJsonObject(42)).toBe(false);
    expect(isJsonObject('string')).toBe(false);
    expect(isJsonObject(true)).toBe(false);
    expect(isJsonObject(false)).toBe(false);
    expect(isJsonObject(Symbol())).toBe(false);
  });

  it('should return false for function', () => {
    expect(isJsonObject(() => {})).toBe(false);
  });
});

describe('Type Narrowing', () => {
  it('should narrow type for JSON object', () => {
    const input: unknown = { key: 'value' };

    if (isJsonObject<{ key: string }>(input)) {
      // This block should only compile if input is correctly typed
      expect(input.key).toBe('value');
    }
  });
});

describe('mergeArrays', () => {
  it('returns undefined when both inputs are undefined', () => {
    expect(mergeArrays(undefined, undefined)).toBeUndefined();
  });

  it('returns undefined when both inputs are non-arrays at runtime', () => {
    // @ts-expect-error: intentionally passing wrong runtime types
    expect(mergeArrays(123, { foo: 'bar' })).toBeUndefined();
  });

  it("returns a de-duplicated copy when only 'a' is provided", () => {
    const a = ['x', 'y', 'x', 'z', 'y'];
    expect(mergeArrays(a, undefined)).toEqual(['x', 'y', 'z']);
  });

  it("returns a de-duplicated copy when only 'b' is provided", () => {
    const b = ['a', 'a', 'b'];
    expect(mergeArrays(undefined, b)).toEqual(['a', 'b']);
  });

  it("merges two arrays, keeping order from 'a' then unique items from 'b'", () => {
    const a = ['a', 'b'];
    const b = ['b', 'c', 'a', 'd'];
    expect(mergeArrays(a, b)).toEqual(['a', 'b', 'c', 'd']);
  });

  it('handles empty arrays properly', () => {
    expect(mergeArrays([], [])).toEqual([]);
    expect(mergeArrays([], ['a', 'a'])).toEqual(['a']);
    expect(mergeArrays(['a'], [])).toEqual(['a']);
  });

  it('does not mutate the input arrays', () => {
    const a = ['a', 'b', 'a'];
    const b = ['b', 'c'];
    const aBefore = [...a];
    const bBefore = [...b];

    const result = mergeArrays(a, b);
    expect(result).toEqual(['a', 'b', 'c']);
    expect(a).toEqual(aBefore);
    expect(b).toEqual(bBefore);
  });

  it('treats empty string and whitespace as distinct values', () => {
    const a = ['', ' '];
    const b = [''];
    expect(mergeArrays(a, b)).toEqual(['', ' ']);
  });
});

describe('parseSpaceSeparated', () => {
  it('should parse space-separated strings', () => {
    expect(parseSpaceSeparated('foo bar baz')).toEqual(['foo', 'bar', 'baz']);
  });

  it('should handle multiple spaces between words', () => {
    expect(parseSpaceSeparated('foo  bar   baz')).toEqual([
      'foo',
      'bar',
      'baz',
    ]);
  });

  it('should handle tabs and newlines', () => {
    expect(parseSpaceSeparated('foo\tbar\nbaz')).toEqual(['foo', 'bar', 'baz']);
  });

  it('should trim whitespace from individual items', () => {
    expect(parseSpaceSeparated(' foo  bar  baz ')).toEqual([
      'foo',
      'bar',
      'baz',
    ]);
  });

  it('should filter out empty strings', () => {
    expect(parseSpaceSeparated('foo  bar')).toEqual(['foo', 'bar']);
  });

  it('should return undefined for undefined input', () => {
    expect(parseSpaceSeparated(undefined)).toBeUndefined();
  });

  it('should return empty array for empty string', () => {
    expect(parseSpaceSeparated('')).toEqual([]);
  });

  it('should return empty array for whitespace-only string', () => {
    expect(parseSpaceSeparated('   ')).toEqual([]);
  });

  it('should handle single word', () => {
    expect(parseSpaceSeparated('foo')).toEqual(['foo']);
  });
});

describe('parseSpaceSeparatedSet', () => {
  it('should parse space-separated strings into a Set', () => {
    const result = parseSpaceSeparatedSet('foo bar baz');
    expect(result).toBeInstanceOf(Set);
    expect(result.size).toBe(3);
    expect(result.has('foo')).toBe(true);
    expect(result.has('bar')).toBe(true);
    expect(result.has('baz')).toBe(true);
  });

  it('should handle duplicate values', () => {
    const result = parseSpaceSeparatedSet('foo bar foo baz bar');
    expect(result.size).toBe(3);
    expect(result.has('foo')).toBe(true);
    expect(result.has('bar')).toBe(true);
    expect(result.has('baz')).toBe(true);
  });

  it('should return empty Set for undefined input', () => {
    const result = parseSpaceSeparatedSet(undefined);
    expect(result).toBeInstanceOf(Set);
    expect(result.size).toBe(0);
  });

  it('should return empty Set for empty string', () => {
    const result = parseSpaceSeparatedSet('');
    expect(result).toBeInstanceOf(Set);
    expect(result.size).toBe(0);
  });

  it('should handle whitespace-only string', () => {
    const result = parseSpaceSeparatedSet('   ');
    expect(result.size).toBe(0);
  });
});

describe('setsEqual', () => {
  it('should return true for equal sets', () => {
    const a = new Set(['foo', 'bar', 'baz']);
    const b = new Set(['foo', 'bar', 'baz']);
    expect(setsEqual(a, b)).toBe(true);
  });

  it('should return true for equal sets in different order', () => {
    const a = new Set(['foo', 'bar', 'baz']);
    const b = new Set(['baz', 'foo', 'bar']);
    expect(setsEqual(a, b)).toBe(true);
  });

  it('should return false for sets with different sizes in strict mode', () => {
    const a = new Set(['foo', 'bar']);
    const b = new Set(['foo', 'bar', 'baz']);
    expect(setsEqual(a, b, true)).toBe(false);
  });

  it('should return false for sets with different values', () => {
    const a = new Set(['foo', 'bar']);
    const b = new Set(['foo', 'qux']);
    expect(setsEqual(a, b)).toBe(false);
  });

  it('should return true for empty sets', () => {
    const a = new Set<string>();
    const b = new Set<string>();
    expect(setsEqual(a, b)).toBe(true);
  });

  it('should return true when a is subset of b in non-strict mode', () => {
    const a = new Set(['foo', 'bar']);
    const b = new Set(['foo', 'bar', 'baz']);
    expect(setsEqual(a, b, false)).toBe(true);
  });

  it('should return false when a has values not in b (non-strict mode)', () => {
    const a = new Set(['foo', 'bar', 'qux']);
    const b = new Set(['foo', 'bar', 'baz']);
    expect(setsEqual(a, b, false)).toBe(false);
  });

  it('should default to strict mode when strict parameter not provided', () => {
    const a = new Set(['foo', 'bar']);
    const b = new Set(['foo', 'bar', 'baz']);
    expect(setsEqual(a, b)).toBe(false);
  });
});

describe('findToken', () => {
  const createToken = (
    resource?: string,
    requestedScopes?: string
  ): AccessToken => ({
    accessToken: 'at',
    scopes: 'any',
    accessTokenExpiration: 123,
    resource,
    requestedScopes,
  });

  it('should return undefined for empty token array', () => {
    expect(findToken([], 'resource', 'scopes')).toBeUndefined();
  });

  it('should return undefined for non-array tokens', () => {
    expect(findToken(undefined, 'resource', 'scopes')).toBeUndefined();
  });

  it('should find token without resource when no resource specified', () => {
    const tokens = [
      createToken('resource1', 'scope1'),
      createToken(undefined, 'scope2'),
    ];
    const result = findToken(tokens, undefined, 'scope2');
    expect(result).toBe(tokens[1]);
  });

  it('should match token by resource and scopes', () => {
    const tokens = [
      createToken('resource1', 'scope1 scope2'),
      createToken('resource2', 'scope3 scope4'),
    ];
    const result = findToken(tokens, 'resource2', 'scope3 scope4');
    expect(result).toBe(tokens[1]);
  });

  it('should match token with scopes in different order', () => {
    const token = createToken('resource1', 'scope1 scope2 scope3');
    const tokens = [token];
    const result = findToken(tokens, 'resource1', 'scope3 scope1 scope2');
    expect(result).toBe(token);
  });

  it('should return undefined when resource does not match', () => {
    const tokens = [createToken('resource1', 'scope1')];
    expect(findToken(tokens, 'resource2', 'scope1')).toBeUndefined();
  });

  it('should return undefined when scopes do not match', () => {
    const tokens = [createToken('resource1', 'scope1')];
    expect(findToken(tokens, 'resource1', 'scope2')).toBeUndefined();
  });

  it('should handle tokens with undefined resource and scopes', () => {
    const token = createToken(undefined, undefined);
    const tokens = [token];
    const result = findToken(tokens, undefined, undefined);
    expect(result).toBe(token);
  });

  it('should handle multiple matching tokens and return first', () => {
    const token1 = createToken('resource1', 'scope1');
    const token2 = createToken('resource1', 'scope1');
    const tokens = [token1, token2];
    const result = findToken(tokens, 'resource1', 'scope1');
    expect(result).toBe(token1);
  });

  it('should handle empty string resource and scopes', () => {
    const token = createToken('', '');
    const tokens = [token];
    const result = findToken(tokens, '', '');
    expect(result).toBe(token);
  });

  it('should match tokens with whitespace-heavy resource and scopes', () => {
    const token = createToken(
      '  resource1  resource2  ',
      '  scope1   scope2  '
    );
    const tokens = [token];
    const result = findToken(tokens, 'resource1 resource2', 'scope1 scope2');
    expect(result).toBe(token);
  });

  it('should not match when additional scopes are present in token', () => {
    const token = createToken('resource1', 'scope1 scope2 scope3');
    const tokens = [token];
    const result = findToken(tokens, 'resource1', 'scope1 scope2');
    expect(result).toBeUndefined();
  });

  it('should not match when additional scopes are requested', () => {
    const token = createToken('resource1', 'scope1 scope2');
    const tokens = [token];
    const result = findToken(tokens, 'resource1', 'scope1 scope2 scope3');
    expect(result).toBeUndefined();
  });
});
