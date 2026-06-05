/* eslint-disable import/no-extraneous-dependencies */
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import React, { StrictMode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { MonoCloudAuthProvider } from '../src/monocloud-auth-provider';
import {
  ActionControls,
  AuthProbe,
  aSession,
  getClientOptions,
  makeMockClient,
  renderWithProvider,
  setMockClient,
  type MockClient,
} from './utils';

describe('MonoCloudAuthProvider', () => {
  let client: MockClient;

  beforeEach(() => {
    client = makeMockClient();
    setMockClient(client);
  });

  it('auto-processes the callback on mount and hydrates an authenticated session', async () => {
    client.getSession.mockResolvedValue(aSession());

    renderWithProvider(<AuthProbe />);

    await waitFor(() =>
      expect(screen.getByTestId('authenticated').textContent).toBe('true')
    );
    expect(client.processCallback).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId('user').textContent).toBe('user-1');
    expect(screen.getByTestId('loading').textContent).toBe('false');
  });

  it('derives isAuthenticated from session presence, without consulting tokens', async () => {
    client.getSession.mockResolvedValue(aSession());

    renderWithProvider(<AuthProbe />);

    await waitFor(() =>
      expect(screen.getByTestId('authenticated').textContent).toBe('true')
    );
    expect(client.getTokens).not.toHaveBeenCalled();
  });

  it('hydrates as unauthenticated when there is no session', async () => {
    client.getSession.mockResolvedValue(undefined);

    renderWithProvider(<AuthProbe />);

    await waitFor(() =>
      expect(screen.getByTestId('loading').textContent).toBe('false')
    );
    expect(screen.getByTestId('authenticated').textContent).toBe('false');
    expect(screen.getByTestId('user').textContent).toBe('');
  });

  it('sets the error state when callback processing fails', async () => {
    client.processCallback.mockRejectedValue(new Error('bad state'));

    renderWithProvider(<AuthProbe />);

    await waitFor(() =>
      expect(screen.getByTestId('error').textContent).toBe('bad state')
    );
    expect(screen.getByTestId('authenticated').textContent).toBe('false');
  });

  it('skips processCallback but still hydrates when autoProcessCallback is false', async () => {
    client.getSession.mockResolvedValue(aSession());

    renderWithProvider(<AuthProbe />, { autoProcessCallback: false });

    await waitFor(() =>
      expect(screen.getByTestId('authenticated').textContent).toBe('true')
    );
    expect(client.processCallback).not.toHaveBeenCalled();
  });

  it('does not double-process the callback under StrictMode', async () => {
    client.getSession.mockResolvedValue(aSession());

    render(
      <StrictMode>
        <MonoCloudAuthProvider
          tenantDomain="https://tenant.us.monocloud.com"
          clientId="client-id"
        >
          <AuthProbe />
        </MonoCloudAuthProvider>
      </StrictMode>
    );

    await waitFor(() =>
      expect(screen.getByTestId('authenticated').textContent).toBe('true')
    );
    expect(client.processCallback).toHaveBeenCalledTimes(1);
  });

  it('re-syncs the session after popup-style actions', async () => {
    client.getSession.mockResolvedValue(undefined);

    renderWithProvider(
      <>
        <AuthProbe />
        <ActionControls />
      </>,
      { autoProcessCallback: false }
    );
    await waitFor(() =>
      expect(screen.getByTestId('loading').textContent).toBe('false')
    );

    client.getSession.mockResolvedValue(aSession());

    fireEvent.click(screen.getByText('refresh'));
    await waitFor(() =>
      expect(screen.getByTestId('authenticated').textContent).toBe('true')
    );
    expect(client.refreshSession).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByText('refetch'));
    await waitFor(() =>
      expect(client.refetchUserInfo).toHaveBeenCalledTimes(1)
    );

    fireEvent.click(screen.getByText('silent'));
    await waitFor(() => expect(client.signInSilent).toHaveBeenCalledTimes(1));

    fireEvent.click(screen.getByText('tokens'));
    await waitFor(() => expect(client.getTokens).toHaveBeenCalled());

    fireEvent.click(screen.getByText('signin'));
    await waitFor(() => expect(client.signIn).toHaveBeenCalledTimes(1));

    fireEvent.click(screen.getByText('signout'));
    await waitFor(() => expect(client.signOut).toHaveBeenCalledTimes(1));
  });

  it('captures the error state when signIn fails', async () => {
    client.getSession.mockResolvedValue(undefined);
    client.signIn.mockRejectedValue(new Error('popup blocked'));

    renderWithProvider(
      <>
        <AuthProbe />
        <ActionControls />
      </>,
      { autoProcessCallback: false }
    );
    await waitFor(() =>
      expect(screen.getByTestId('loading').textContent).toBe('false')
    );

    fireEvent.click(screen.getByText('signin'));
    await waitFor(() =>
      expect(screen.getByTestId('error').textContent).toBe('popup blocked')
    );
  });

  it('captures the error state when signOut fails', async () => {
    client.getSession.mockResolvedValue(undefined);
    client.signOut.mockRejectedValue(new Error('signout failed'));

    renderWithProvider(
      <>
        <AuthProbe />
        <ActionControls />
      </>,
      { autoProcessCallback: false }
    );
    await waitFor(() =>
      expect(screen.getByTestId('loading').textContent).toBe('false')
    );

    fireEvent.click(screen.getByText('signout'));
    await waitFor(() =>
      expect(screen.getByTestId('error').textContent).toBe('signout failed')
    );
  });

  it('passes a consumer-provided postCallback straight through to the client', () => {
    const postCallback = vi.fn();

    renderWithProvider(<AuthProbe />, {
      autoProcessCallback: false,
      postCallback,
    });

    expect(getClientOptions().postCallback).toBe(postCallback);
  });

  it('does not inject a postCallback when none is provided (web-js default applies)', () => {
    renderWithProvider(<AuthProbe />, { autoProcessCallback: false });

    expect(getClientOptions().postCallback).toBeUndefined();
  });
});
