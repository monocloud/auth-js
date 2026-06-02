// eslint-disable-next-line import/no-extraneous-dependencies
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  fetchBuilder,
  generateIdToken,
  MockWindow,
} from '@monocloud/auth-test-utils';
import {
  ensureLockManagerStub,
  setSession,
  testInstance,
  VanillaJsMockStorage,
} from './utils';
import {
  MonoCloudOPError,
  MonoCloudSession,
  ResponseTypes,
} from '@monocloud/auth-core';
import { now } from '@monocloud/auth-core/internal';
import { MonoCloudJsError } from '../src';

const tabLockMocks = vi.hoisted(() => ({
  acquireLock: vi.fn(() => true),
  releaseLock: vi.fn(() => void 0),
}));

vi.mock('browser-tabs-lock', () => {
  return {
    default: class TabLockMock {
      acquireLock = tabLockMocks.acquireLock;

      releaseLock = tabLockMocks.releaseLock;
    },
  };
});

describe('instance.signInSilent() Tests', () => {
  let mockWindow: MockWindow;
  let mockStorage: VanillaJsMockStorage;

  const urlRegex =
    /^https:\/\/example\.com\/connect\/authorize\?client_id=clientId&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=[a-zA-Z0-9+_% -]+&response_type=[a-zA-Z0-9_+]+&nonce=[a-zA-Z0-9_-]+&prompt=none&code_challenge=[a-zA-Z0-9_-]+&code_challenge_method=S256&state=[a-zA-Z0-9_-]+$/;

  const mountIframe = (): { getSrc: () => string } => {
    const iframe = window.document.createElement('iframe');
    vi.spyOn(window.document, 'createElement').mockReturnValue(iframe);
    vi.spyOn(iframe, 'contentWindow', 'get').mockReturnValue(
      window as unknown as Window
    );
    let iframeSrc = '';
    vi.spyOn(iframe, 'setAttribute').mockImplementation(
      (name: string, value: string) => {
        if (name === 'src') iframeSrc = value;
      }
    );
    return { getSrc: () => iframeSrc };
  };

  beforeEach(() => {
    mockWindow = new MockWindow();
    mockStorage = new VanillaJsMockStorage();
    ensureLockManagerStub();
  });

  afterEach(() => {
    mockWindow.restore();
    window.localStorage.clear();
    window.sessionStorage.clear();
  });

  const dispatchSoftError = (state: string | null): void => {
    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-web-js',
          url: `http://localhost:3000/callback?error=login_required&state=${encodeURIComponent(
            state ?? ''
          )}`,
        },
        source: window,
        origin: 'http://localhost:3000',
      })
    );
  };

  it('should issue a prompt=none authorize request via a hidden iframe', async () => {
    fetchBuilder().configureMetadata().configureJwks().createSpy();

    mockWindow.assert();
    const { getSrc } = mountIframe();

    const instance = testInstance({ storage: mockStorage });

    const promise = instance.signInSilent();

    await vi.waitFor(() => {
      expect(getSrc()).toMatch(urlRegex);
    });

    const url = new URL(getSrc());
    expect(url.searchParams.get('prompt')).toBe('none');

    dispatchSoftError(url.searchParams.get('state'));
    await promise.catch(() => {});
  });

  it('should establish a new session on success (Authorization Code)', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureJwks()
      .createSpy();

    mockWindow.assert();
    const { getSrc } = mountIframe();

    const instance = testInstance({ storage: mockStorage });

    const promise = instance.signInSilent();

    await vi.waitFor(() => {
      expect(getSrc()).toMatch(urlRegex);
    });

    const authorizeUrl = new URL(getSrc());
    const generatedState = authorizeUrl.searchParams.get('state');
    const generatedNonce = authorizeUrl.searchParams.get('nonce');

    const idToken = await generateIdToken({
      nonce: generatedNonce ?? undefined,
      claims: { email: 'test@example.com' },
    });

    fetchSpy
      .configureTokenEndpoint({
        accessToken: 'newAt',
        refreshToken: 'newRt',
        idToken,
      })
      .configureUserinfo({
        accessToken: 'newAt',
        claims: { sub: 'sub', email: 'test@example.com' },
      });

    const callbackUrl = `http://localhost:3000/callback?code=auth-code&state=${encodeURIComponent(
      generatedState ?? ''
    )}`;

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-web-js',
          url: callbackUrl,
        },
        source: window,
        origin: 'http://localhost:3000',
      })
    );

    const result = await promise;

    expect(result).toEqual(
      expect.objectContaining({
        refreshToken: 'newRt',
        idToken: expect.any(String),
        accessTokens: [
          expect.objectContaining({
            accessToken: 'newAt',
            accessTokenExpiration: expect.any(Number),
          }),
        ],
        user: expect.objectContaining({
          sub: 'sub',
          email: 'test@example.com',
        }),
      })
    );

    await vi.waitFor(async () => {
      const saved = await instance.getSession();
      expect(saved).toEqual(result);
      fetchSpy.assert();
    });
  });

  it("should establish a new session on success (Hybrid - 'code id_token')", async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureJwks()
      .createSpy();

    mockWindow.assert();
    const { getSrc } = mountIframe();

    const instance = testInstance({
      storage: mockStorage,
      defaultAuthParams: { responseType: 'code id_token' as ResponseTypes },
    });

    const promise = instance.signInSilent();

    await vi.waitFor(() => {
      expect(getSrc()).toMatch(urlRegex);
    });

    const authorizeUrl = new URL(getSrc());
    const generatedState = authorizeUrl.searchParams.get('state');
    const generatedNonce = authorizeUrl.searchParams.get('nonce');

    const idToken = await generateIdToken({
      nonce: generatedNonce ?? undefined,
    });

    fetchSpy
      .configureTokenEndpoint({
        accessToken: 'newAt',
        refreshToken: 'newRt',
        idToken,
      })
      .configureUserinfo({ accessToken: 'newAt' });

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-web-js',
          url: `http://localhost:3000/callback#state=${encodeURIComponent(
            generatedState ?? ''
          )}&code=auth-code&id_token=${encodeURIComponent(idToken)}`,
        },
        source: window,
        origin: 'http://localhost:3000',
      })
    );

    const result = await promise;

    expect(result).toEqual(
      expect.objectContaining({
        refreshToken: 'newRt',
        accessTokens: [expect.objectContaining({ accessToken: 'newAt' })],
      })
    );

    fetchSpy.assert();
  });

  it('should establish a new session on success (Implicit)', async () => {
    const fetchSpy = fetchBuilder().configureMetadata().createSpy();

    mockWindow.assert();
    const { getSrc } = mountIframe();

    const instance = testInstance({
      storage: mockStorage,
      fetchUserinfo: false,
      defaultAuthParams: {
        scopes: 'api',
        responseType: 'token' as ResponseTypes,
      },
    });

    const promise = instance.signInSilent();

    await vi.waitFor(() => {
      expect(getSrc()).toMatch(urlRegex);
    });

    const generatedState = new URL(getSrc()).searchParams.get('state');

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-web-js',
          url: `http://localhost:3000/callback#access_token=newAt&scope=api&expires_in=600&state=${encodeURIComponent(
            generatedState ?? ''
          )}`,
        },
        source: window,
        origin: 'http://localhost:3000',
      })
    );

    const result = await promise;

    expect(result).toEqual(
      expect.objectContaining({
        authorizedScopes: 'api',
        accessTokens: [
          {
            accessToken: 'newAt',
            scopes: 'api',
            requestedScopes: 'api',
            accessTokenExpiration: expect.any(Number),
          },
        ],
      })
    );

    fetchSpy.assert();
  });

  it.each([
    'login_required',
    'interaction_required',
    'consent_required',
    'account_selection_required',
  ])(
    'should reject with MonoCloudOPError when the authorization server returns %s',
    async errorCode => {
      fetchBuilder().configureMetadata().createSpy();

      mockWindow.assert();
      const { getSrc } = mountIframe();

      const instance = testInstance({ storage: mockStorage });

      const promise = instance.signInSilent();

      await vi.waitFor(() => {
        expect(getSrc()).toMatch(urlRegex);
      });

      const generatedState = new URL(getSrc()).searchParams.get('state');

      const errorCallbackUrl =
        `http://localhost:3000/callback` +
        `?error=${errorCode}` +
        `&error_description=${encodeURIComponent('not signed in')}` +
        `&state=${encodeURIComponent(generatedState ?? '')}`;

      window.dispatchEvent(
        new MessageEvent('message', {
          data: {
            source: 'monocloud-auth-web-js',
            url: errorCallbackUrl,
          },
          source: window,
          origin: 'http://localhost:3000',
        })
      );

      const error = await promise.catch(e => e);

      expect(error).toBeInstanceOf(MonoCloudOPError);
      expect(error).toMatchObject({
        error: errorCode,
        errorDescription: 'not signed in',
      });

      expect(await instance.getSession()).toBeUndefined();
    }
  );

  it('should preserve any existing session when the silent sign-in fails', async () => {
    fetchBuilder().configureMetadata().createSpy();

    mockWindow.assert();
    const { getSrc } = mountIframe();

    const existingSession: MonoCloudSession = {
      user: { sub: 'sub' },
      refreshToken: 'rt',
      accessTokens: [
        {
          accessToken: 'at',
          accessTokenExpiration: now() + 1000,
          scopes: 'openid offline_access',
          requestedScopes: 'openid',
        },
      ],
      authorizedScopes: 'openid',
    };
    setSession(mockStorage, existingSession);

    const instance = testInstance({ storage: mockStorage });

    const promise = instance.signInSilent();

    await vi.waitFor(() => {
      expect(getSrc()).toMatch(urlRegex);
    });

    const generatedState = new URL(getSrc()).searchParams.get('state');

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-web-js',
          url:
            `http://localhost:3000/callback?error=login_required` +
            `&state=${encodeURIComponent(generatedState ?? '')}`,
        },
        source: window,
        origin: 'http://localhost:3000',
      })
    );

    await expect(promise).rejects.toBeInstanceOf(MonoCloudOPError);
    expect(await instance.getSession()).toEqual(existingSession);
  });

  it('should reject with MonoCloudOPError for other authorization errors', async () => {
    fetchBuilder().configureMetadata().createSpy();

    mockWindow.assert();
    const { getSrc } = mountIframe();

    const instance = testInstance({ storage: mockStorage });

    const promise = instance.signInSilent();

    await vi.waitFor(() => {
      expect(getSrc()).toMatch(urlRegex);
    });

    const generatedState = new URL(getSrc()).searchParams.get('state');

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-web-js',
          url:
            `http://localhost:3000/callback?error=server_error` +
            `&error_description=${encodeURIComponent('boom')}` +
            `&state=${encodeURIComponent(generatedState ?? '')}`,
        },
        source: window,
        origin: 'http://localhost:3000',
      })
    );

    const error = await promise.catch(e => e);

    expect(error).toBeInstanceOf(MonoCloudOPError);
    expect(error).toMatchObject({
      error: 'server_error',
      errorDescription: 'boom',
    });
  });

  it('should reject if the iframe times out', async () => {
    fetchBuilder().configureMetadata().createSpy();

    mockWindow.assert();
    const { getSrc } = mountIframe();

    const instance = testInstance({
      storage: mockStorage,
      authWindowTimeout: 0.1,
    });

    const promise = instance.signInSilent();

    await vi.waitFor(() => {
      expect(getSrc()).toMatch(urlRegex);
    });

    await expect(promise).rejects.toBeInstanceOf(MonoCloudJsError);
    await expect(promise).rejects.toThrow('Authentication window timed out');
  });

  it('should throw if the window is cross-origin isolated', async () => {
    const instance = testInstance({ storage: mockStorage });

    Object.defineProperty(window, 'crossOriginIsolated', {
      value: true,
      configurable: true,
    });

    const error = await instance.signInSilent().catch(e => e);

    expect(error).toBeInstanceOf(MonoCloudJsError);
    expect(error.message).toBe(
      'Cannot create iframe in a cross-origin-isolated context'
    );

    Object.defineProperty(window, 'crossOriginIsolated', {
      value: false,
      configurable: true,
    });
  });

  it('should forward maxAge, loginHint, and acrValues to the authorize request', async () => {
    fetchBuilder().configureMetadata().createSpy();
    mockWindow.assert();
    const { getSrc } = mountIframe();

    const instance = testInstance({ storage: mockStorage });

    const promise = instance.signInSilent({
      maxAge: 60,
      loginHint: 'user@example.com',
      acrValues: ['mfa', 'urn:level:high'],
    });

    await vi.waitFor(() => {
      expect(getSrc()).toContain('https://example.com/connect/authorize');
    });

    const url = new URL(getSrc());
    expect(url.searchParams.get('max_age')).toBe('60');
    expect(url.searchParams.get('login_hint')).toBe('user@example.com');
    expect(url.searchParams.get('acr_values')).toBe('mfa urn:level:high');
    expect(url.searchParams.get('prompt')).toBe('none');

    dispatchSoftError(url.searchParams.get('state'));
    await promise.catch(() => {});
  });

  it('should merge per-call scopes and resource with the configured defaults', async () => {
    fetchBuilder().configureMetadata().createSpy();
    mockWindow.assert();
    const { getSrc } = mountIframe();

    const instance = testInstance({
      storage: mockStorage,
      resources: [{ resource: 'api://inventory', scopes: 'inv:read' }],
    });

    const promise = instance.signInSilent({
      scopes: 'orders:write',
      resource: 'api://orders',
    });

    await vi.waitFor(() => {
      expect(getSrc()).toContain('https://example.com/connect/authorize');
    });

    const url = new URL(getSrc());

    const resources = url.searchParams.getAll('resource');
    expect(resources).toContain('api://orders');
    expect(resources).toContain('api://inventory');

    const scopes = url.searchParams.get('scope')?.split(' ') ?? [];
    expect(scopes).toContain('orders:write');
    expect(scopes).toContain('inv:read');

    dispatchSoftError(url.searchParams.get('state'));
    await promise.catch(() => {});
  });

  it('should pass appState to the onSessionCreating hook', async () => {
    const fetchSpy = fetchBuilder()
      .configureMetadata()
      .configureJwks()
      .createSpy();

    mockWindow.assert();
    const { getSrc } = mountIframe();

    const onSessionCreating = vi.fn();

    const instance = testInstance({
      storage: mockStorage,
      onSessionCreating,
    });

    const promise = instance.signInSilent({
      appState: { redirectAfter: '/dashboard' },
    });

    await vi.waitFor(() => {
      expect(getSrc()).toMatch(urlRegex);
    });

    const authorizeUrl = new URL(getSrc());
    const generatedState = authorizeUrl.searchParams.get('state');
    const generatedNonce = authorizeUrl.searchParams.get('nonce');

    const idToken = await generateIdToken({
      nonce: generatedNonce ?? undefined,
    });

    fetchSpy.configureTokenEndpoint({ idToken }).configureUserinfo();

    window.dispatchEvent(
      new MessageEvent('message', {
        data: {
          source: 'monocloud-auth-web-js',
          url: `http://localhost:3000/callback?code=auth-code&state=${encodeURIComponent(
            generatedState ?? ''
          )}`,
        },
        source: window,
        origin: 'http://localhost:3000',
      })
    );

    await promise;

    expect(onSessionCreating).toHaveBeenCalledWith(
      expect.any(Object),
      expect.any(Object),
      expect.any(Object),
      { redirectAfter: '/dashboard' }
    );
  });
});
