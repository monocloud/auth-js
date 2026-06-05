/* eslint-disable import/no-extraneous-dependencies */
import { render, screen, waitFor } from '@testing-library/react';
import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { MonoCloudJsError } from '@monocloud/auth-web-js';
import { useAuth } from '../src/use-auth';
import {
  AuthProbe,
  aSession,
  makeMockClient,
  renderWithProvider,
  setMockClient,
  type MockClient,
} from './utils';

const Consumer = (): React.JSX.Element => {
  useAuth();
  return <div />;
};

describe('useAuth', () => {
  it('throws a MonoCloudJsError when used outside a provider', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});

    expect(() => render(<Consumer />)).toThrow(MonoCloudJsError);

    spy.mockRestore();
  });

  describe('inside a provider', () => {
    let client: MockClient;

    beforeEach(() => {
      client = makeMockClient();
      setMockClient(client);
    });

    it('returns the authentication context value', async () => {
      client.getSession.mockResolvedValue(aSession());

      renderWithProvider(<AuthProbe />, { autoProcessCallback: false });

      await waitFor(() =>
        expect(screen.getByTestId('authenticated').textContent).toBe('true')
      );
    });
  });
});
