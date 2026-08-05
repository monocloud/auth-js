/* eslint-disable import/no-extraneous-dependencies */
/* eslint-disable @typescript-eslint/no-non-null-assertion */
import { decrypt, encryptAuthState } from '@monocloud/auth-core/utils';
import { sha256 } from '@monocloud/auth-core/internal';
import { describe, expect, it, vi } from 'vitest';
import { getOptions } from '../src/options/get-options';
import { MonoCloudStateService } from '../src/monocloud-state-service';
import { MonoCloudOptions, MonoCloudState, SameSiteValues } from '../src/types';
import { TestReq, TestRes } from './test-helpers';

const defaultConfig: MonoCloudOptions = {
  cookieSecret: '__test_session_secret__',
  clientId: '__test_client_id__',
  clientSecret: '__test_client_secret__',
  tenantDomain: 'https://op.example.com',
  appUrl: 'https://example.org',
  defaultAuthParams: {
    responseType: 'code',
    scopes: 'openid profile read:customer',
  },
};

const cookieOptions = {
  domain: 'example.com',
  httpOnly: true,
  name: 'cookie_name',
  path: 'cookie_path',
  sameSite: 'lax' as SameSiteValues,
  secure: true,
};

const getService = (
  params: MonoCloudOptions = {}
): Promise<MonoCloudStateService> => {
  return Promise.resolve(
    new MonoCloudStateService(getOptions({ ...defaultConfig, ...params }))
  );
};

const getState = (state = 'state_key'): MonoCloudState => ({
  appState: 'client_state',
  nonce: 'nonce',
  state,
  scopes: 'openid',
});

const cookieName = async (state: string, name = 'state'): Promise<string> =>
  `${name}.${await sha256(state)}`;

describe('State Service', () => {
  it('should set the state cookie with configured options', async () => {
    const service = await getService({ state: { cookie: cookieOptions } });

    const res = new TestRes();

    const authState = getState();

    await service.setState(new TestReq(), res, authState);

    const name = await cookieName('state_key', cookieOptions.name);

    const decrypted = JSON.parse(
      (await decrypt(res.cookies[name].value, defaultConfig.cookieSecret!))!
    );

    expect(decrypted.authState).toEqual(authState);
    expect(typeof decrypted.expiresAt).toBe('number');

    expect(res.cookies[name].options).toEqual({
      domain: cookieOptions.domain,
      httpOnly: cookieOptions.httpOnly,
      sameSite: cookieOptions.sameSite,
      secure: cookieOptions.secure,
      path: cookieOptions.path,
      maxAge: 900,
    });
  });

  it('should set the state cookie max age from the configured duration', async () => {
    const service = await getService({ state: { duration: 1800 } });

    const res = new TestRes();

    await service.setState(new TestReq(), res, getState());

    const name = await cookieName('state_key');

    expect(res.cookies[name].options.maxAge).toBe(1800);
  });

  it('should set the state cookie with same site none when passed in', async () => {
    const service = await getService({ state: { cookie: cookieOptions } });

    const res = new TestRes();

    await service.setState(new TestReq(), res, getState(), 'none');

    const name = await cookieName('state_key', cookieOptions.name);

    expect(res.cookies[name].value).toBeDefined();
    expect(res.cookies[name].options.sameSite).toBe('none');
  });

  it('should be able to get the state from the cookies', async () => {
    const service = await getService();

    const cookies = {};

    const state = getState();

    await service.setState(new TestReq(), new TestRes(cookies), state);

    const response = await service.getState(
      new TestReq({ cookies }),
      new TestRes(cookies),
      state.state
    );

    expect(response).toEqual(state);
  });

  it('should return undefined when getting the state from request with no state cookie', async () => {
    const service = await getService();

    const response = await service.getState(
      new TestReq(),
      new TestRes(),
      'state_key'
    );

    expect(response).toBeUndefined();
  });

  it('should return undefined and remove the cookie when getting an invalid state', async () => {
    const service = await getService();

    const name = await cookieName('state_key');

    const cookies = { [name]: { value: 'yoohoo' } } as any;

    const res = new TestRes(cookies);

    const response = await service.getState(
      new TestReq({ cookies }),
      res,
      'state_key'
    );

    expect(response).toBeUndefined();
    expect(cookies[name].value).toBe('');
    expect(cookies[name].options.expires).toEqual(new Date(0));
  });

  it('should return undefined when the state has expired', async () => {
    const service = await getService();

    const name = await cookieName('state_key');

    const cookies = {
      [name]: {
        value: await encryptAuthState(
          getState(),
          defaultConfig.cookieSecret!,
          -1
        ),
      },
    } as any;

    const response = await service.getState(
      new TestReq({ cookies }),
      new TestRes(cookies),
      'state_key'
    );

    expect(response).toBeUndefined();
  });

  it('should remove the state cookie after the first get', async () => {
    const service = await getService({ state: { cookie: cookieOptions } });

    const cookies = {};

    const state = getState();

    await service.setState(new TestReq(), new TestRes(cookies), state);

    expect(Object.entries(cookies).length).toBe(1);

    const response = await service.getState(
      new TestReq({ cookies }),
      new TestRes(cookies),
      state.state
    );

    const name = await cookieName('state_key', cookieOptions.name);

    expect(response).toEqual(state);
    expect(Object.entries(cookies).length).toBe(1);
    expect((cookies as any)[name].options.expires).toEqual(new Date(0));
    expect((cookies as any)[name].options.maxAge).toBeUndefined();
    expect((cookies as any)[name].value).toBe('');
  });

  it('should keep concurrent sign in transactions isolated', async () => {
    const service = await getService();

    const cookies = {};

    const first = getState('first_state');
    const second = getState('second_state');

    await service.setState(
      new TestReq({ cookies }),
      new TestRes(cookies),
      first
    );
    await service.setState(
      new TestReq({ cookies }),
      new TestRes(cookies),
      second
    );

    expect(Object.entries(cookies).length).toBe(2);

    // Completing the first transaction must not disturb the second one.
    const firstResponse = await service.getState(
      new TestReq({ cookies }),
      new TestRes(cookies),
      first.state
    );

    expect(firstResponse).toEqual(first);

    const secondResponse = await service.getState(
      new TestReq({ cookies }),
      new TestRes(cookies),
      second.state
    );

    expect(secondResponse).toEqual(second);
  });

  it('should not consume the unsuffixed cookie set by a previous version', async () => {
    const service = await getService();

    const state = getState();

    const cookies = {
      state: {
        value: await encryptAuthState(state, defaultConfig.cookieSecret!),
      },
    } as any;

    const response = await service.getState(
      new TestReq({ cookies }),
      new TestRes(cookies),
      state.state
    );

    // The transaction cannot be identified, and the cookie is left for the
    // cleanup paths rather than consumed on behalf of another transaction.
    expect(response).toBeUndefined();
    expect(cookies.state.value).not.toBe('');
  });

  describe('concurrent transaction limit', () => {
    it('should evict the earliest transaction beyond the limit', async () => {
      const service = await getService();

      const cookies: any = {};

      for (let i = 0; i < 5; i++) {
        await service.setState(
          new TestReq({ cookies }),
          new TestRes(cookies),
          getState(`state_${i}`)
        );
      }

      expect(Object.entries(cookies).length).toBe(5);

      await service.setState(
        new TestReq({ cookies }),
        new TestRes(cookies),
        getState('state_5')
      );

      const evicted = await cookieName('state_0');

      expect(cookies[evicted].value).toBe('');
      expect(cookies[evicted].options.expires).toEqual(new Date(0));

      // The remaining transactions are still completable.
      for (let i = 1; i <= 5; i++) {
        expect(cookies[await cookieName(`state_${i}`)].value).not.toBe('');
      }
    });

    it('should evict the transactions which can no longer be used', async () => {
      const service = await getService();

      const cookies: any = {
        [await cookieName('garbage')]: { value: 'not_a_state' },
      };

      for (let i = 0; i < 3; i++) {
        await service.setState(
          new TestReq({ cookies }),
          new TestRes(cookies),
          getState(`state_${i}`)
        );
      }

      await service.setState(
        new TestReq({ cookies }),
        new TestRes(cookies),
        getState('state_3')
      );

      expect(cookies[await cookieName('garbage')].value).toBe('');

      // Nothing valid was evicted to make room.
      for (let i = 0; i <= 3; i++) {
        expect(cookies[await cookieName(`state_${i}`)].value).not.toBe('');
      }
    });

    it('should not let the request dictate how many transactions are decrypted', async () => {
      const service = await getService();

      const cookies: any = {};

      // A request can carry any number of transactions, so inspecting all of them
      // would let it choose how many key derivations the sign in performs. The
      // junk must be long enough to pass the ciphertext length check, so that
      // inspecting it actually costs a key derivation.
      const junk = 'A'.repeat(96);

      for (let i = 0; i < 50; i++) {
        cookies[await cookieName(`junk_${i}`)] = { value: junk };
      }

      const deriveKey = vi.spyOn(crypto.subtle, 'deriveKey');

      await service.setState(
        new TestReq({ cookies }),
        new TestRes(cookies),
        getState()
      );

      // At most one derivation per retained transaction, plus the one being written.
      expect(deriveKey.mock.calls.length).toBeLessThanOrEqual(5);

      // Every surplus transaction is still cleared.
      for (let i = 0; i < 50; i++) {
        expect(cookies[await cookieName(`junk_${i}`)].value).toBe('');
      }

      deriveKey.mockRestore();
    });

    it('should ignore the cookies which merely share the state prefix', async () => {
      const service = await getService();

      // A name which cannot be serialized back into a Set-Cookie header.
      const cookies: any = { 'state.é': { value: 'not_a_state' } };

      await service.setState(
        new TestReq({ cookies }),
        new TestRes(cookies),
        getState()
      );

      expect(cookies['state.é'].value).toBe('not_a_state');
      expect(cookies[await cookieName('state_key')].value).not.toBe('');
    });

    it('should not count the transaction being overwritten towards the limit', async () => {
      const service = await getService();

      const cookies: any = {};

      for (let i = 0; i < 5; i++) {
        await service.setState(
          new TestReq({ cookies }),
          new TestRes(cookies),
          getState(`state_${i}`)
        );
      }

      // Re-starting an existing transaction reuses its slot, so the earliest
      // transaction must not be evicted to make room for it.
      await service.setState(
        new TestReq({ cookies }),
        new TestRes(cookies),
        getState('state_2')
      );

      for (let i = 0; i < 5; i++) {
        expect(cookies[await cookieName(`state_${i}`)].value).not.toBe('');
      }
    });

    it('should honor a configured maxConcurrent limit', async () => {
      const service = await getService({ state: { maxConcurrent: 2 } });

      const cookies: any = {};

      for (let i = 0; i < 2; i++) {
        await service.setState(
          new TestReq({ cookies }),
          new TestRes(cookies),
          getState(`state_${i}`)
        );
      }

      await service.setState(
        new TestReq({ cookies }),
        new TestRes(cookies),
        getState('state_2')
      );

      expect(cookies[await cookieName('state_0')].value).toBe('');
      expect(cookies[await cookieName('state_1')].value).not.toBe('');
      expect(cookies[await cookieName('state_2')].value).not.toBe('');
    });

    it('should prune to a configured maxConcurrent when removing stale states', async () => {
      const service = await getService({ state: { maxConcurrent: 2 } });

      const cookies: any = {};
      for (let i = 0; i < 3; i++) {
        cookies[await cookieName(`state_${i}`)] = {
          value: await encryptAuthState(
            getState(`state_${i}`),
            defaultConfig.cookieSecret!
          ),
        };
      }

      await service.removeStaleStates(
        new TestReq({ cookies }),
        new TestRes(cookies)
      );

      expect(cookies[await cookieName('state_0')].value).toBe('');
      expect(cookies[await cookieName('state_1')].value).not.toBe('');
      expect(cookies[await cookieName('state_2')].value).not.toBe('');
    });
  });

  describe('cleanup', () => {
    it('should remove only the unusable states when removing stale states', async () => {
      const service = await getService();

      // Seed the jar directly so the clearing can only come from the sweep
      // itself, and not from the eviction a setState would perform.
      const cookies: any = {
        unrelated: { value: 'keep_me' },
        [await cookieName('garbage')]: { value: 'not_a_state' },
        state: {
          value: await encryptAuthState(
            getState(),
            defaultConfig.cookieSecret!,
            -1
          ),
        },
        [await cookieName('valid_state')]: {
          value: await encryptAuthState(
            getState('valid_state'),
            defaultConfig.cookieSecret!
          ),
        },
      };

      await service.removeStaleStates(
        new TestReq({ cookies }),
        new TestRes(cookies)
      );

      expect(cookies[await cookieName('garbage')].value).toBe('');
      expect(cookies.state.value).toBe('');
      expect(cookies.unrelated.value).toBe('keep_me');
      expect(cookies[await cookieName('valid_state')].value).not.toBe('');
    });

    it('should remove every state when removing all states', async () => {
      const service = await getService();

      const cookies: any = {
        unrelated: { value: 'keep_me' },
        state: { value: 'legacy' },
      };

      await service.setState(
        new TestReq({ cookies }),
        new TestRes(cookies),
        getState('valid_state')
      );

      await service.removeAllStates(
        new TestReq({ cookies }),
        new TestRes(cookies)
      );

      expect(cookies.state.value).toBe('');
      expect(cookies[await cookieName('valid_state')].value).toBe('');
      expect(cookies.unrelated.value).toBe('keep_me');
    });
  });
});
