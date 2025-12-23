/* eslint-disable react/display-name */
/* eslint-disable import/no-extraneous-dependencies */
import React, { JSX } from 'react';
import { SWRConfig } from 'swr';
import { vi, expect } from 'vitest';

export const wrapper = ({ children }: any): JSX.Element => (
  <SWRConfig value={{ provider: () => new Map() }}>{children}</SWRConfig>
);

export const Component =
  (assertUser = true) =>
  ({ user }: any): JSX.Element => {
    if (assertUser) {
      expect(user).toEqual({ sub: 'sub', email: 'a@b.com' });
    }
    return <p>Great Success!!!</p>;
  };

export const fetch500 = (): void => {
  (global as any).fetch = vi.fn((url: string) => {
    expect(url).toBe('/api/auth/userinfo');
    return {
      status: 500,
      ok: false,
    };
  });
};

export const fetchOk = (
  expectedUrl?: string,
  user: unknown = {
    sub: 'sub',
    email: 'a@b.com',
  }
): void => {
  (global as any).fetch = vi.fn((url: string) => {
    expect(url).toBe(expectedUrl ?? '/api/auth/userinfo');
    return {
      status: 200,
      ok: true,
      json: (): Promise<any> => Promise.resolve(user),
    };
  });
};

export const fetchOkGroups = (): void => {
  (global as any).fetch = vi.fn((url: string) => {
    expect(url).toBe('/api/auth/userinfo');
    return {
      status: 200,
      ok: true,
      json: (): Promise<any> =>
        Promise.resolve({
          sub: 'sub',
          email: 'a@b.com',
          groups: [{ id: 'testId', name: 'testName' }],
          CUSTOM_GROUPS: [{ id: 'testId', name: 'testName' }],
        }),
    };
  });
};

export const fetchNoContent = (expectedUrl = '/api/auth/userinfo'): void => {
  (global as any).fetch = vi.fn((url: string) => {
    expect(url).toBe(expectedUrl);
    return {
      status: 204,
      ok: true,
    };
  });
};
