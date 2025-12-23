/* eslint-disable import/no-extraneous-dependencies */
import { describe, expect, it, vi } from 'vitest';
import { MonoCloudOidcClient } from '../src/monocloud-oidc-client';
import { now } from '../src/utils/internal';
import { generateIdToken, idTokenPublicKey } from '@monocloud/auth-test-utils';
import { MonoCloudTokenError } from '../src';
import { assertError } from './utils';

const assertTokenError = async (
  promise: Promise<unknown>,
  error: string
): Promise<void> => await assertError(promise, MonoCloudTokenError, error);

describe('MonoCloudOidcClient.validateIdToken()', () => {
  it.each([null, ' '])('should not validate invalid idtoken', async idToken => {
    const client = new MonoCloudOidcClient('example.com', 'clientId');

    await assertTokenError(
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      client.validateIdToken(idToken!, [], 0, 0),
      'ID Token must be a valid non-empty string'
    );
  });

  it('should not validate invalid idtoken', async () => {
    const client = new MonoCloudOidcClient('example.com', 'clientId');

    await assertTokenError(
      client.validateIdToken('id_token', [], 0, 0),
      'ID Token must have a header, payload and signature'
    );
  });

  it('should not validate a idtoken without header', async () => {
    const client = new MonoCloudOidcClient('example.com', 'clientId');

    await assertTokenError(
      client.validateIdToken('.payload.signature', [], 0, 0),
      'Failed to parse JWT Header'
    );
  });

  it('should not validate a id token with invalid header', async () => {
    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.validateIdToken(
      'W3siYWxnIjogIlJTMjU2IiwgInR5cCI6ICJzdHJpbmciLCAiY3JpdCI6IFtdfV0.payload.signature',
      [],
      0,
      0
    );

    await assertTokenError(promise, 'JWT Header must be a top level object');
  });

  it('should not validate a idtoken with header containing an invalid signing algorithm', async () => {
    const client = new MonoCloudOidcClient('example.com', 'clientId', {
      idTokenSigningAlgorithm: 'ES256',
    });

    const promise = client.validateIdToken(
      'eyJhbGciOiAiUlMyNTYiLCAidHlwIjogInN0cmluZyJ9.payload.signature',
      [],
      0,
      0
    );

    await assertTokenError(promise, 'Invalid signing alg');
  });

  it('should not validate a idtoken with header containing crit parameter', async () => {
    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.validateIdToken(
      'eyJhbGciOiAiUlMyNTYiLCAidHlwIjogInN0cmluZyIsICJjcml0IjogW119.payload.signature',
      [],
      0,
      0
    );

    await assertTokenError(promise, 'Unexpected JWT "crit" header parameter');
  });

  it('should return a failed result if the id token signature is invalid', async () => {
    let idToken = await generateIdToken();
    const [header, payload] = idToken.split('.');

    idToken = `${header}.${payload}.invalidsignature`;

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.validateIdToken(idToken, [idTokenPublicKey], 0, 0);

    await assertTokenError(promise, 'JWT signature verification failed');
  });

  it('should return a failed result if the id token payload is invalid', async () => {
    const cryptoSpy = vi
      .spyOn(crypto.subtle, 'verify')
      .mockReturnValue(Promise.resolve(true));

    let idToken = await generateIdToken();
    const [header, , signature] = idToken.split('.');

    idToken = `${header}.ew.${signature}`;

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.validateIdToken(idToken, [idTokenPublicKey], 0, 0);

    cryptoSpy.mockClear();

    await assertTokenError(promise, 'Failed to parse JWT Payload');
  });

  it('should return a failed result if the id token payload is not an object', async () => {
    const cryptoSpy = vi
      .spyOn(crypto.subtle, 'verify')
      .mockReturnValue(Promise.resolve(true));

    let idToken = await generateIdToken();
    const [header, , signature] = idToken.split('.');

    idToken = `${header}.W10.${signature}`;

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.validateIdToken(idToken, [idTokenPublicKey], 0, 0);

    cryptoSpy.mockClear();

    await assertTokenError(promise, 'JWT Payload must be a top level object');
  });

  it('should return a failed result if the id token payload is not an object - 1', async () => {
    const cryptoSpy = vi
      .spyOn(crypto.subtle, 'verify')
      .mockReturnValue(Promise.resolve(true));

    const idToken = await generateIdToken({ nonce: 'nonce' });

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.validateIdToken(
      idToken,
      [idTokenPublicKey],
      0,
      0,
      undefined,
      'noncy'
    );

    cryptoSpy.mockClear();

    await assertTokenError(promise, 'Nonce mismatch');
  });

  it('should return a failed result if the id token payload is not an object - 2', async () => {
    const cryptoSpy = vi
      .spyOn(crypto.subtle, 'verify')
      .mockReturnValue(Promise.resolve(true));

    const idToken = await generateIdToken();

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.validateIdToken(
      idToken,
      [idTokenPublicKey],
      0,
      0,
      undefined,
      'nonce'
    );

    cryptoSpy.mockClear();

    await assertTokenError(promise, 'Nonce mismatch');
  });

  it('should return a failed result if the id token expiry is not a number', async () => {
    const idToken = await generateIdToken({
      claims: { exp: {} },
      nonce: 'nonce',
    });

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.validateIdToken(
      idToken,
      [idTokenPublicKey],
      0,
      0,
      undefined,
      'nonce'
    );

    await assertTokenError(
      promise,
      'Unexpected JWT "exp" (expiration time) claim type'
    );
  });

  it('should return a failed result if the id token is expired', async () => {
    const idToken = await generateIdToken({
      claims: { exp: 2 },
      nonce: 'nonce',
    });

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.validateIdToken(
      idToken,
      [idTokenPublicKey],
      0,
      0,
      undefined,
      'nonce'
    );

    await assertTokenError(
      promise,
      'Unexpected JWT "exp" (expiration time) claim value, timestamp is <= now()'
    );
  });

  it('should return a failed result if the id token issued at is not a number', async () => {
    const idToken = await generateIdToken({
      claims: { iat: {} },
      nonce: 'nonce',
    });

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.validateIdToken(
      idToken,
      [idTokenPublicKey],
      0,
      0,
      undefined,
      'nonce'
    );

    await assertTokenError(
      promise,
      'Unexpected JWT "iat" (issued at) claim type'
    );
  });

  it('should return a failed result if the id token auth time is lower than max age', async () => {
    const idToken = await generateIdToken({
      claims: { auth_time: 0 },
      nonce: 'nonce',
    });

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.validateIdToken(
      idToken,
      [idTokenPublicKey],
      0,
      0,
      1,
      'nonce'
    );

    await assertTokenError(
      promise,
      'Too much time has elapsed since the last End-User authentication'
    );
  });

  it('should return a failed result if the id token issuer is invalid', async () => {
    const idToken = await generateIdToken({
      claims: { iss: 'someoneelse' },
      nonce: 'nonce',
    });

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.validateIdToken(
      idToken,
      [idTokenPublicKey],
      0,
      0,
      undefined,
      'nonce'
    );

    await assertTokenError(promise, 'Invalid Issuer');
  });

  it('should return a failed result if the id token nbf is not a number', async () => {
    const idToken = await generateIdToken({
      claims: {
        nbf: {},
        iss: 'https://example.com',
      },
      nonce: 'nonce',
    });

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.validateIdToken(
      idToken,
      [idTokenPublicKey],
      0,
      0,
      undefined,
      'nonce'
    );

    await assertTokenError(
      promise,
      'Unexpected JWT "nbf" (not before) claim type'
    );
  });

  it('should return a failed result if the id token nbf is invalid', async () => {
    const idToken = await generateIdToken({
      claims: {
        nbf: 999999999999999,
        iss: 'https://example.com',
      },
      nonce: 'nonce',
    });

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.validateIdToken(
      idToken,
      [idTokenPublicKey],
      0,
      0,
      undefined,
      'nonce'
    );

    await assertTokenError(
      promise,
      'Unexpected JWT "nbf" (not before) claim value, timestamp is > now()'
    );
  });

  it('should return a failed result if the id token audience is invalid - 1', async () => {
    const idToken = await generateIdToken({
      claims: {
        aud: 'client',
        iss: 'https://example.com',
      },
      nonce: 'nonce',
    });

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.validateIdToken(
      idToken,
      [idTokenPublicKey],
      0,
      0,
      undefined,
      'nonce'
    );

    await assertTokenError(promise, 'Invalid audience claim');
  });

  it('should return a failed result if the id token audience is invalid - 2', async () => {
    const idToken = await generateIdToken({
      claims: {
        aud: ['client'],
        iss: 'https://example.com',
      },
      nonce: 'nonce',
    });

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.validateIdToken(
      idToken,
      [idTokenPublicKey],
      0,
      0,
      undefined,
      'nonce'
    );

    await assertTokenError(promise, 'Invalid audience claim');
  });

  it('should return a failed result if the id token audience is invalid - 3', async () => {
    const idToken = await generateIdToken({
      claims: {
        aud: ['client'],
        iss: 'https://example.com',
      },
      nonce: 'nonce',
    });

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const promise = client.validateIdToken(
      idToken,
      [idTokenPublicKey],
      0,
      0,
      undefined,
      'nonce'
    );

    await assertTokenError(promise, 'Invalid audience claim');
  });

  it('should extract claims from id tokens', async () => {
    const exp = now() + 1;
    const iat = now();

    const idToken = await generateIdToken({
      claims: {
        aud: 'clientId',
        iss: 'https://example.com',
        custom: true,
        num: 1,
        exp,
        iat,
        nbf: iat,
      },
      nonce: 'nonce',
    });

    const client = new MonoCloudOidcClient('example.com', 'clientId');

    const result = await client.validateIdToken(
      idToken,
      [idTokenPublicKey],
      0,
      0,
      undefined,
      'nonce'
    );

    expect(result).toEqual({
      num: 1,
      custom: true,
      aud: 'clientId',
      iss: 'https://example.com',
      nonce: 'nonce',
      sub: 'sub',
      sub_jwk: expect.any(Object),
      exp,
      iat,
      nbf: iat,
    });
  });

  it('should throw an error if paylaod is empty', () => {
    try {
      MonoCloudOidcClient.decodeJwt('head..signature');
      throw new Error();
    } catch (e) {
      expect(e).instanceof(MonoCloudTokenError);
      expect((e as any).message).toBe('JWT does not contain payload');
    }
  });
});
