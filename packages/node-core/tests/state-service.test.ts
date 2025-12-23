/* eslint-disable import/no-extraneous-dependencies */
/* eslint-disable @typescript-eslint/no-non-null-assertion */
import { decrypt } from '@monocloud/auth-core/utils';
import { describe, expect, it } from 'vitest';
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

const getService = (
  params: MonoCloudOptions = {}
): Promise<MonoCloudStateService> => {
  return Promise.resolve(
    new MonoCloudStateService(getOptions({ ...defaultConfig, ...params }))
  );
};

describe('State Service', () => {
  it('should set the state cookie with configured options', async () => {
    const cookieOptions = {
      domain: 'example.com',
      httpOnly: true,
      name: 'cookie_name',
      path: 'cookie_path',
      persistent: true,
      sameSite: 'lax' as SameSiteValues,
      secure: true,
    };

    const service = await getService({
      state: {
        cookie: cookieOptions,
      },
    });

    const res = new TestRes();

    const authState: MonoCloudState = {
      appState: 'client_state',
      nonce: 'nonce',
      state: 'state_key',
      scopes: 'openid',
    };

    await service.setState(res, authState);

    expect(
      await decrypt(res.cookies.cookie_name.value, defaultConfig.cookieSecret!)
    ).toBe(JSON.stringify({ authState }));

    expect(res.cookies.cookie_name.options).toEqual({
      domain: cookieOptions.domain,
      httpOnly: cookieOptions.httpOnly,
      sameSite: cookieOptions.sameSite,
      secure: cookieOptions.secure,
      path: cookieOptions.path,
    });
  });

  it('should set the state cookie with same site none when passed in', async () => {
    const cookieOptions = {
      domain: 'example.com',
      httpOnly: true,
      name: 'cookie_name',
      path: 'cookie_path',
      persistent: true,
      sameSite: 'lax' as SameSiteValues,
      secure: true,
    };

    const service = await getService({
      state: {
        cookie: cookieOptions,
      },
    });

    const res = new TestRes();

    const state: MonoCloudState = {
      appState: 'client_state',
      nonce: 'nonce',
      state: 'state_key',
      scopes: 'openid',
    };

    await service.setState(res, state, 'none');

    expect(res.cookies.cookie_name.value).toBeDefined();
    expect(res.cookies.cookie_name.options.sameSite).toBe('none');
  });

  it('should be able to get the state from the cookies', async () => {
    const service = await getService();

    const cookies = {};

    const state: MonoCloudState = {
      appState: 'client_state',
      nonce: 'nonce',
      state: 'state_key',
      scopes: 'openid',
    };
    await service.setState(new TestRes(cookies), state);
    const response = await service.getState(
      new TestReq({ cookies }),
      new TestRes(cookies)
    );

    expect(response).toEqual(state);
  });

  it('should return undefined when getting the state from request with no state cookie', async () => {
    const service = await getService();

    const cookies = {};

    const response = await service.getState(
      new TestReq(cookies),
      new TestRes()
    );

    expect(response).toBeUndefined();
  });

  it('should return undefined when getting an invalid state', async () => {
    const service = await getService();

    const cookies = { state: { value: 'yoohoo' } } as any;

    const response = await service.getState(
      new TestReq(cookies),
      new TestRes()
    );

    expect(response).toBeUndefined();
  });

  it('should remove the state cookie after the first get', async () => {
    const cookieOptions = {
      domain: 'example.com',
      httpOnly: true,
      name: 'cookie_name',
      path: 'cookie_path',
      persistent: true,
      sameSite: 'lax' as SameSiteValues,
      secure: true,
    };

    const service = await getService({
      state: {
        cookie: cookieOptions,
      },
    });

    const cookies = {};

    const state: MonoCloudState = {
      appState: 'client_state',
      nonce: 'nonce',
      state: 'state_key',
      scopes: 'openid',
    };

    await service.setState(new TestRes(cookies), state);

    expect(Object.entries(cookies).length).toBe(1);

    const response = await service.getState(
      new TestReq({ cookies }),
      new TestRes(cookies)
    );

    expect(response).toEqual(state);
    expect(Object.entries(cookies).length).toBe(1);
    expect((cookies as any).cookie_name.options.expires).toEqual(new Date(0));
    expect((cookies as any).cookie_name.value).toBe('');
  });
});
