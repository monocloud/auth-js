/* eslint-disable import/no-extraneous-dependencies */
import nock from 'nock';
import { expect } from 'vitest';

const idTokenPrivateKey = {
  kty: 'RSA',
  alg: 'RS256',
  n: 'rS_iO491_fxo4MEfoxcNVba0Z72XB_wuywPoXgYohSauOyXMZrzpT6qQExn4ev7cwF2qzb2k8rQjYz-2A0FjmCWCnQLfdiAxWBuzlLGJW2-6rPoRhZ16pID_Drd7X8Ra6qXnGcsI5Lwu3kj6UimuflgOiBHw2sJ2bu5HByXDN3gVNDK5mLZJLsnnKkfX13vLrhzScAP75zsaf6eOTuSO_Hbn1A-E8f4f07M3MHDoN_dnoNt4ucPPXJV0MGZv0ZrxPeDxUyiD1Qd4PHXdDiG3uIwW-s605PJ7NigxHm2L0e4vbSzHTVK1VJiF1wgUKD4XtRNguWEfPjN6CQacwgmBfw',
  e: 'AQAB',
  d: 'SEKY6dH_YMR-u_xIZ4N4SGGtnzVfPXEu0v0j6Is4P-o2Oy6XvOwoitl3OMkWwLbzQ34xhJuSpcOcmk4ccvpHBFXuS_XFaCOhgwo34Rw8W_7fzEmgovfkkpvSEAFlhD1I0-v542ywHsQX6B5Z94s1p7i1A3g83wHRaZKY5zYN4GfVNLFogY7VP71_gMb7HeYe855mHONOWBZakpMtv59L1V-lKDds1ULSSrZ_SJG8drStd4plXhg7MHIGGO7Nn_XbjMoBYTPmFxHSflKNczwTmWI-LeIFz4urN8mgwbwUHgoLp0ZsdfuA3YjS4yySfGwlN1oQekItD9bUYHV-UJwjbQ',
  p: '5xJUkmGQcb2Hpca-j8wz9qg4TZ_esdIUwxoYFLcj8mSGOHr5nd5ieyx_upxgYUghktHUPaoJNpClUUvC-xXr7Ub4O2HlYvnC6xVQl0zvIO-huKbkWaAHogxTwkwz9peYeZQusJiTAH4CA3oD69SgRRVbIpXqtC0_pcyiWeTkgr0',
  q: 'v97qBu0U5epZg1sT64ZiZfWCsCgVflQTJdIdkZ4b2YnqgqoQ-4C3X32mVKdEEca63ygIylQi5YWANUo3qm005HSIa7Cy9bBBN8itd_5KDnXDcMiq3IaCCIHxJodlUaudJAy8WdsoK1oP0rjrQflVIUY66QB8Dkw4RKShM2RiVus',
  dp: '3zO0n6VAiq3CPt7IqkxdEXCS2mCIE4pTZdZp1nDFd1mk0R_wyI7M4CAuzUpKSw4K6DBpbJs3xQ5ZsjqVgEY_m_aGx42br0yE_OGc9FlrT4xJ0fzb7LsJRH3V1oQXWaY7sYzywMDQlpQhS8xrxzyfB7xGSRU5HovqxDPzyxOvq50',
  dq: 'hhiaQQrzHxjhRJ-j1WjPXmju1IS_ONIzq6wkxD_XQPtVrcqEIfI8tn1PgTyBo1bcBdiqBBY3aWgbSaM8Ml0uqTgUnAcbnAB6JC2ZpxJO2bpORIXKfGN5f86pJn9cPW8OXUKVZMt5UIsaIfDhYvOKHr5Br9SJ30g_zyGsFAnlfM8',
  qi: 'JienPfGUZogAYXC8WJ-U-UTbRFEEvrygHilNNwI8FqTywNYcKk1Xc0m0Cdt-Use72sxQG-5-PjtwF9sZ_3TUJS9rTgw0zfn3IFMtNz4txOewbjwkOz4MjRuHjXyX1Ti5vmL9uMaIlfb_0jHrrYDN2urIzEwvYv2fECbk2x59aJE',
};

const idTokenPublicKey = {
  kty: 'RSA',
  n: 'rS_iO491_fxo4MEfoxcNVba0Z72XB_wuywPoXgYohSauOyXMZrzpT6qQExn4ev7cwF2qzb2k8rQjYz-2A0FjmCWCnQLfdiAxWBuzlLGJW2-6rPoRhZ16pID_Drd7X8Ra6qXnGcsI5Lwu3kj6UimuflgOiBHw2sJ2bu5HByXDN3gVNDK5mLZJLsnnKkfX13vLrhzScAP75zsaf6eOTuSO_Hbn1A-E8f4f07M3MHDoN_dnoNt4ucPPXJV0MGZv0ZrxPeDxUyiD1Qd4PHXdDiG3uIwW-s605PJ7NigxHm2L0e4vbSzHTVK1VJiF1wgUKD4XtRNguWEfPjN6CQacwgmBfw',
  e: 'AQAB',
};

export const createTestIdToken = async (
  claims = {},
  includeNonce = true
): Promise<{ idToken: string; sub: string }> => {
  const jose = await import('jose');

  const key = await jose.importJWK(idTokenPrivateKey);

  const sub = 'sub';
  return {
    idToken: await new jose.SignJWT({
      sub_jwk: idTokenPublicKey,
      sub,
      nonce: includeNonce ? 'nonce' : undefined,
      ...claims,
    })
      .setIssuedAt()
      .setProtectedHeader({ alg: 'RS256' })
      .setIssuer('https://op.example.com')
      .setAudience('__test_client_id__')
      .setExpirationTime('1m')
      .sign(key),
    sub,
  };
};

export const setupOp = async (
  discovery: { body?: object; status?: number } | undefined = undefined,
  enable: {
    token: boolean;
    userinfo: boolean;
  } = { token: true, userinfo: true },
  customRefreshBodyMatcher = {},
  redirectUri = 'https://example.org/api/auth/callback'
): Promise<void> => {
  nock('https://op.example.com')
    .get('/.well-known/openid-configuration')
    .reply(
      discovery?.status ?? 200,
      discovery?.body ?? {
        issuer: 'https://op.example.com',
        authorization_endpoint: 'https://op.example.com/connect/authorize',
        token_endpoint: 'https://op.example.com/connect/token',
        userinfo_endpoint: 'https://op.example.com/connect/userinfo',
        jwks_uri:
          'https://op.example.com/.well-known/openid-configuration/jwks',
        end_session_endpoint: 'https://op.example.com/connect/endsession',
      }
    );

  let idToken;

  if (enable.userinfo) {
    idToken = await createTestIdToken();

    nock('https://op.example.com')
      .matchHeader('authorization', 'Bearer at')
      .get('/connect/userinfo')
      .reply(200, {
        sub: idToken.sub,
        username: 'username',
        updated: 'false',
      });

    nock('https://op.example.com')
      .matchHeader('authorization', 'Basic at1')
      .get('/connect/userinfo')
      .reply(200, {
        sub: idToken.sub,
        username: 'username',
        updated: 'true',
        new: 'field',
      });

    nock('https://op.example.com')
      .get('/.well-known/openid-configuration/jwks')
      .reply(200, { keys: [idTokenPublicKey] });
  }

  if (enable.token) {
    nock('https://op.example.com')
      .matchHeader(
        'authorization',
        'Basic X190ZXN0X2NsaWVudF9pZF9fOl9fdGVzdF9jbGllbnRfc2VjcmV0X18='
      )
      .post('/connect/token', body => {
        return (
          body.code === 'code' &&
          body.redirect_uri === redirectUri &&
          body.code_verifier?.trim().length > 0 &&
          body.grant_type === 'authorization_code'
        );
      })
      .reply(200, {
        access_token: 'at',
        id_token: idToken?.idToken ?? 'idtoken',
        refresh_token: 'rt',
        expires_in: 999,
        scope: process.env.MONOCLOUD_AUTH_SCOPES,
        token_type: 'Bearer',
      })
      .post('/connect/token', body => {
        const matcher = Object.keys(customRefreshBodyMatcher);
        if (matcher.length > 0) {
          for (const key of matcher) {
            if (!body[key]) {
              return false;
            }
          }
        }
        return (
          body.grant_type === 'refresh_token' && body.refresh_token === 'rt'
        );
      })
      .reply(200, {
        access_token: 'at1',
        id_token: (await createTestIdToken(undefined, false)).idToken,
        refresh_token: 'rt1',
        expires_in: 999,
        scope: process.env.MONOCLOUD_AUTH_SCOPES,
        token_type: 'Bearer',
      });
  }
};

export const refreshedTokens = {
  accessToken: 'at1',
  idToken: expect.any(String),
  refreshToken: 'rt1',
};

export const defaultAppUserInfoResponse = {
  sub: 'sub',
  username: 'username',
  updated: 'false',
  sub_jwk: expect.any(Object),
};

export const defaultDiscovery = {};
export const noBodyDiscoverySuccess = { body: {} };

export const noTokenAndUserInfo = { token: false, userinfo: false };
export const tokenAndUserInfoEnabled = { token: true, userinfo: true };
