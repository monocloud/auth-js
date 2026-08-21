/* eslint-disable import/no-extraneous-dependencies */
import { describe, expect, it, vi } from 'vitest';
import * as jose from 'jose';
import { MonoCloudOidcClient } from '../src/monocloud-oidc-client';
import { now } from '../src/utils/internal';
import {
  generateIdToken,
  idTokenPrivateKey,
  idTokenPublicKey,
} from '@monocloud/auth-test-utils';
import { MonoCloudTokenError } from '../src';
import type { IssuerMetadata, Jwks, MonoCloudOidcClientOptions } from '../src';
import { assertError } from './utils';

const assertTokenError = async (
  promise: Promise<unknown>,
  error: string
): Promise<void> => await assertError(promise, MonoCloudTokenError, error);

const backChannelLogoutEvent =
  'http://schemas.openid.net/event/backchannel-logout';

const generateLogoutToken = (
  claims: Record<string, unknown> = {},
  nonce?: string
): Promise<string> =>
  generateIdToken({
    nonce,
    claims: {
      sid: 'sid',
      events: { [backChannelLogoutEvent]: {} },
      ...claims,
    },
  });

const getClient = (options?: MonoCloudOidcClientOptions): MonoCloudOidcClient =>
  new MonoCloudOidcClient('example.com', 'clientId', {
    metadataResolver: () =>
      ({ issuer: 'https://example.com' }) as IssuerMetadata,
    jwksResolver: () => ({ keys: [idTokenPublicKey] }) as Jwks,
    ...options,
  });

describe('MonoCloudOidcClient.validateLogoutToken()', () => {
  it.each([null, ' ', true, 1])(
    'should not validate an invalid logout token',
    async logoutToken => {
      const client = getClient();

      await assertTokenError(
        client.validateLogoutToken(logoutToken as unknown as string, 0, 0),
        'Logout Token must be a valid non-empty string'
      );
    }
  );

  it('should not validate a malformed logout token', async () => {
    const client = getClient();

    await assertTokenError(
      client.validateLogoutToken('logout_token', 0, 0),
      'Logout Token must have a header, payload and signature'
    );
  });

  it('should not validate a logout token without header', async () => {
    const client = getClient();

    await assertTokenError(
      client.validateLogoutToken('.payload.signature', 0, 0),
      'Failed to parse JWT Header'
    );
  });

  it('should not validate a logout token with invalid header', async () => {
    const client = getClient();

    const promise = client.validateLogoutToken(
      'W3siYWxnIjogIlJTMjU2IiwgInR5cCI6ICJzdHJpbmciLCAiY3JpdCI6IFtdfV0.payload.signature',
      0,
      0
    );

    await assertTokenError(promise, 'JWT Header must be a top level object');
  });

  it('should not validate a logout token with header containing an invalid signing algorithm', async () => {
    const client = getClient({ idTokenSigningAlgorithm: 'ES256' });

    const promise = client.validateLogoutToken(
      'eyJhbGciOiAiUlMyNTYiLCAidHlwIjogInN0cmluZyJ9.payload.signature',
      0,
      0
    );

    await assertTokenError(promise, 'Invalid signing alg');
  });

  it('should not validate a logout token with header containing crit parameter', async () => {
    const client = getClient();

    const promise = client.validateLogoutToken(
      'eyJhbGciOiAiUlMyNTYiLCAidHlwIjogInN0cmluZyIsICJjcml0IjogW119.payload.signature',
      0,
      0
    );

    await assertTokenError(promise, 'Unexpected JWT "crit" header parameter');
  });

  it('should return a failed result if the logout token signature is invalid', async () => {
    let logoutToken = await generateLogoutToken();
    const [header, payload] = logoutToken.split('.');

    logoutToken = `${header}.${payload}.invalidsignature`;

    const client = getClient();

    const promise = client.validateLogoutToken(logoutToken, 0, 0);

    await assertTokenError(promise, 'JWT signature verification failed');
  });

  it('should return a failed result if the logout token payload is invalid', async () => {
    const cryptoSpy = vi
      .spyOn(crypto.subtle, 'verify')
      .mockReturnValue(Promise.resolve(true));

    let logoutToken = await generateLogoutToken();
    const [header, , signature] = logoutToken.split('.');

    logoutToken = `${header}.ew.${signature}`;

    const client = getClient();

    const promise = client.validateLogoutToken(logoutToken, 0, 0);

    cryptoSpy.mockClear();

    await assertTokenError(promise, 'Failed to parse JWT Payload');
  });

  it('should return a failed result if the logout token payload is not an object', async () => {
    const cryptoSpy = vi
      .spyOn(crypto.subtle, 'verify')
      .mockReturnValue(Promise.resolve(true));

    let logoutToken = await generateLogoutToken();
    const [header, , signature] = logoutToken.split('.');

    logoutToken = `${header}.W10.${signature}`;

    const client = getClient();

    const promise = client.validateLogoutToken(logoutToken, 0, 0);

    cryptoSpy.mockClear();

    await assertTokenError(promise, 'JWT Payload must be a top level object');
  });

  it('should not validate a logout token with an invalid issuer', async () => {
    const logoutToken = await generateLogoutToken({
      iss: 'https://someother.com',
    });

    const client = getClient();

    const promise = client.validateLogoutToken(logoutToken, 0, 0);

    await assertTokenError(promise, 'Invalid Issuer');
  });

  it('should validate the issuer against the issuer metadata document and not the tenant domain', async () => {
    const logoutToken = await generateLogoutToken({
      iss: 'https://custom-issuer.com',
    });

    const client = getClient({
      metadataResolver: () =>
        ({ issuer: 'https://custom-issuer.com' }) as IssuerMetadata,
    });

    const claims = await client.validateLogoutToken(logoutToken, 0, 0);

    expect(claims.iss).toBe('https://custom-issuer.com');
  });

  it('should not validate a logout token with an invalid audience', async () => {
    const logoutToken = await generateLogoutToken({ aud: 'someother' });

    const client = getClient();

    const promise = client.validateLogoutToken(logoutToken, 0, 0);

    await assertTokenError(promise, 'Invalid audience claim');
  });

  it('should validate a logout token with an audience array containing the client id', async () => {
    const logoutToken = await generateLogoutToken({
      aud: ['clientId', 'someother'],
    });

    const client = getClient();

    const claims = await client.validateLogoutToken(logoutToken, 0, 0);

    expect(claims.aud).toEqual(['clientId', 'someother']);
  });

  it('should not validate a logout token without an iat claim', async () => {
    const key = await jose.importJWK(idTokenPrivateKey);

    const logoutToken = await new jose.SignJWT({
      sub: 'sub',
      sid: 'sid',
      events: { [backChannelLogoutEvent]: {} },
    })
      .setProtectedHeader({ alg: 'RS256' })
      .setIssuer('https://example.com')
      .setAudience('clientId')
      .setExpirationTime('1m')
      .sign(key);

    const client = getClient();

    const promise = client.validateLogoutToken(logoutToken, 0, 0);

    await assertTokenError(promise, 'Missing JWT "iat" (issued at) claim');
  });

  it('should validate a logout token without an exp claim', async () => {
    const key = await jose.importJWK(idTokenPrivateKey);

    const logoutToken = await new jose.SignJWT({
      sub: 'sub',
      sid: 'sid',
      events: { [backChannelLogoutEvent]: {} },
    })
      .setProtectedHeader({ alg: 'RS256' })
      .setIssuer('https://example.com')
      .setAudience('clientId')
      .setIssuedAt()
      .sign(key);

    const client = getClient();

    const claims = await client.validateLogoutToken(logoutToken, 0, 0);

    expect(claims.exp).toBeUndefined();
    expect(claims.sid).toBe('sid');
  });

  it('should not validate a logout token with an invalid iat claim type', async () => {
    const logoutToken = await generateLogoutToken({ iat: 'invalid' });

    const client = getClient();

    const promise = client.validateLogoutToken(logoutToken, 0, 0);

    await assertTokenError(
      promise,
      'Unexpected JWT "iat" (issued at) claim type'
    );
  });

  it('should not validate a logout token with an invalid exp claim type', async () => {
    const logoutToken = await generateLogoutToken({ exp: 'invalid' });

    const client = getClient();

    const promise = client.validateLogoutToken(logoutToken, 0, 0);

    await assertTokenError(
      promise,
      'Unexpected JWT "exp" (expiration time) claim type'
    );
  });

  it('should not validate an expired logout token', async () => {
    const logoutToken = await generateLogoutToken({ exp: now() - 10 });

    const client = getClient();

    const promise = client.validateLogoutToken(logoutToken, 0, 0);

    await assertTokenError(
      promise,
      'Unexpected JWT "exp" (expiration time) claim value, timestamp is <= now()'
    );
  });

  it('should validate an expired logout token within the clock tolerance', async () => {
    const logoutToken = await generateLogoutToken({ exp: now() - 10 });

    const client = getClient();

    const claims = await client.validateLogoutToken(logoutToken, 0, 60);

    expect(claims.sid).toBe('sid');
  });

  it('should not validate a logout token with an invalid nbf claim type', async () => {
    const logoutToken = await generateLogoutToken({ nbf: 'invalid' });

    const client = getClient();

    const promise = client.validateLogoutToken(logoutToken, 0, 0);

    await assertTokenError(
      promise,
      'Unexpected JWT "nbf" (not before) claim type'
    );
  });

  it('should not validate a logout token used before the nbf claim', async () => {
    const logoutToken = await generateLogoutToken({ nbf: now() + 120 });

    const client = getClient();

    const promise = client.validateLogoutToken(logoutToken, 0, 0);

    await assertTokenError(
      promise,
      'Unexpected JWT "nbf" (not before) claim value, timestamp is > now()'
    );
  });

  it('should validate a logout token with a valid nbf claim', async () => {
    const nbf = now() - 10;

    const logoutToken = await generateLogoutToken({ nbf });

    const client = getClient();

    const claims = await client.validateLogoutToken(logoutToken, 0, 0);

    expect(claims.nbf).toBe(nbf);
    expect(claims.sid).toBe('sid');
  });

  it('should not validate a logout token without a sub and sid claim', async () => {
    const logoutToken = await generateLogoutToken({
      sub: undefined,
      sid: undefined,
    });

    const client = getClient();

    const promise = client.validateLogoutToken(logoutToken, 0, 0);

    await assertTokenError(
      promise,
      'Logout Token must contain a "sub" (subject) or "sid" (session ID) claim'
    );
  });

  it('should validate a logout token with only a sub claim', async () => {
    const logoutToken = await generateLogoutToken({ sid: undefined });

    const client = getClient();

    const claims = await client.validateLogoutToken(logoutToken, 0, 0);

    expect(claims.sub).toBe('sub');
    expect(claims.sid).toBeUndefined();
  });

  it('should validate a logout token with only a sid claim', async () => {
    const logoutToken = await generateLogoutToken({ sub: undefined });

    const client = getClient();

    const claims = await client.validateLogoutToken(logoutToken, 0, 0);

    expect(claims.sub).toBeUndefined();
    expect(claims.sid).toBe('sid');
  });

  it('should not validate a logout token containing a nonce claim', async () => {
    const logoutToken = await generateLogoutToken({}, 'nonce');

    const client = getClient();

    const promise = client.validateLogoutToken(logoutToken, 0, 0);

    await assertTokenError(
      promise,
      'Logout Token must not contain a "nonce" claim'
    );
  });

  it.each([undefined, null, 1, []])(
    'should not validate a logout token with an invalid events claim',
    async events => {
      const logoutToken = await generateLogoutToken({ events });

      const client = getClient();

      const promise = client.validateLogoutToken(logoutToken, 0, 0);

      await assertTokenError(promise, 'Invalid JWT "events" claim');
    }
  );

  it.each([undefined, null, 1, []])(
    'should not validate a logout token without the back-channel logout event',
    async event => {
      const logoutToken = await generateLogoutToken({
        events: { [backChannelLogoutEvent]: event },
      });

      const client = getClient();

      const promise = client.validateLogoutToken(logoutToken, 0, 0);

      await assertTokenError(
        promise,
        'Logout Token must contain the back-channel logout event'
      );
    }
  );

  it('should validate a valid logout token', async () => {
    const logoutToken = await generateLogoutToken({ jti: 'jti' });

    const client = getClient();

    const claims = await client.validateLogoutToken(logoutToken, 0, 0);

    expect(claims.iss).toBe('https://example.com');
    expect(claims.aud).toBe('clientId');
    expect(claims.sub).toBe('sub');
    expect(claims.sid).toBe('sid');
    expect(claims.jti).toBe('jti');
    expect(claims.iat).toEqual(expect.any(Number));
    expect(claims.events).toEqual({ [backChannelLogoutEvent]: {} });
  });
});
