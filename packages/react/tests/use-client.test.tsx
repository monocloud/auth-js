/* eslint-disable import/no-extraneous-dependencies */
import { renderHook } from '@testing-library/react';
import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { MonoCloudJsError } from '@monocloud/auth-web-js';
import { MonoCloudAuthProvider } from '../src/monocloud-auth-provider';
import { useClient } from '../src/use-client';
import { makeMockClient, setMockClient, type MockClient } from './utils';

describe('useClient', () => {
  let client: MockClient;

  beforeEach(() => {
    client = makeMockClient();
    setMockClient(client);
  });

  it('throws when used outside of a provider', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});

    expect(() => renderHook(() => useClient())).toThrow(MonoCloudJsError);

    spy.mockRestore();
  });

  it('returns the underlying client when used inside a provider', () => {
    const wrapper = ({
      children,
    }: {
      children: React.ReactNode;
    }): React.JSX.Element => (
      <MonoCloudAuthProvider
        tenantDomain="https://tenant.us.monocloud.com"
        clientId="client-id"
        autoProcessCallback={false}
      >
        {children}
      </MonoCloudAuthProvider>
    );

    const { result } = renderHook(() => useClient(), { wrapper });

    expect(result.current).toBe(client);
  });
});
