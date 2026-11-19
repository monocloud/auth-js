/* eslint-disable import/no-extraneous-dependencies */
import type {
  MonoCloudSession,
  SessionChangeListener,
} from '@monocloud/auth-web-js';
import {
  act,
  render,
  screen,
  fireEvent,
  waitFor,
} from '@testing-library/react';
import React, { StrictMode, useEffect } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ProcessCallback } from '../src/components/process-callback';
import { MonoCloudAuthProvider } from '../src/monocloud-auth-provider';
import { useAuth } from '../src/use-auth';
import {
  ActionControls,
  AuthProbe,
  aSession,
  deferred,
  flush,
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

  it('forwards each action to the client', async () => {
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

    fireEvent.click(screen.getByText('refresh'));
    fireEvent.click(screen.getByText('refetch'));
    fireEvent.click(screen.getByText('silent'));
    fireEvent.click(screen.getByText('tokens'));
    fireEvent.click(screen.getByText('signin'));
    fireEvent.click(screen.getByText('signout'));

    await waitFor(() =>
      expect(screen.getByTestId('loading').textContent).toBe('false')
    );
    expect(client.refreshSession).toHaveBeenCalledTimes(1);
    expect(client.refetchUserInfo).toHaveBeenCalledTimes(1);
    expect(client.signInSilent).toHaveBeenCalledTimes(1);
    expect(client.getTokens).toHaveBeenCalledTimes(1);
    expect(client.signIn).toHaveBeenCalledWith({ mode: 'popup' });
    expect(client.signOut).toHaveBeenCalledWith({ mode: 'popup' });
  });

  it('mirrors every session change the client notifies and clears a previous error', async () => {
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

    act(() => client.emit(aSession()));

    expect(screen.getByTestId('authenticated').textContent).toBe('true');
    expect(screen.getByTestId('user').textContent).toBe('user-1');
    expect(screen.getByTestId('error').textContent).toBe('');

    act(() => client.emit(undefined));

    expect(screen.getByTestId('authenticated').textContent).toBe('false');
    expect(screen.getByTestId('user').textContent).toBe('');
  });

  it('keeps the newest session when overlapping actions finish reading out of order', async () => {
    const older = aSession({ user: { sub: 'older' } });
    const newer = aSession({ user: { sub: 'newer' } });

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

    const olderRead = deferred<MonoCloudSession>();
    const newerRead = deferred<MonoCloudSession>();
    client.getSession
      .mockReturnValueOnce(olderRead.promise)
      .mockReturnValueOnce(newerRead.promise);
    client.refreshSession.mockImplementation(() => {
      client.emit(older);
      return Promise.resolve();
    });
    client.refetchUserInfo.mockImplementation(() => {
      client.emit(newer);
      return Promise.resolve();
    });

    fireEvent.click(screen.getByText('refresh'));
    fireEvent.click(screen.getByText('refetch'));

    await act(async () => {
      await flush();
      newerRead.resolve(newer);
      await flush();
      olderRead.resolve(older);
      await flush();
    });

    expect(screen.getByTestId('user').textContent).toBe('newer');
  });

  it('stays loading and signed out while <ProcessCallback> exchanges the code', async () => {
    const exchange = deferred();
    client.processCallback.mockReturnValue(exchange.promise);

    let notify: SessionChangeListener = () => {};
    client.onSessionChange.mockImplementation(
      (listener: SessionChangeListener): (() => void) => {
        notify = listener;
        return () => {};
      }
    );

    renderWithProvider(
      <>
        <AuthProbe />
        <ProcessCallback loading={<span>exchanging</span>}>
          done
        </ProcessCallback>
      </>,
      { autoProcessCallback: false }
    );

    await act(async () => {
      await flush();
    });

    expect(screen.getByTestId('loading').textContent).toBe('true');
    expect(screen.getByTestId('authenticated').textContent).toBe('false');
    expect(screen.getByText('exchanging')).toBeTruthy();

    await act(async () => {
      notify(aSession());
      exchange.resolve();
      await flush();
    });

    expect(screen.getByTestId('loading').textContent).toBe('false');
    expect(screen.getByTestId('authenticated').textContent).toBe('true');
    expect(screen.getByText('done')).toBeTruthy();
  });

  it('records the error but keeps the session when processCallback fails', async () => {
    client.getSession.mockResolvedValue(aSession());
    client.processCallback.mockRejectedValue(new Error('bad state'));

    renderWithProvider(<AuthProbe />);

    await waitFor(() =>
      expect(screen.getByTestId('error').textContent).toBe('bad state')
    );
    expect(screen.getByTestId('loading').textContent).toBe('false');
    expect(screen.getByTestId('authenticated').textContent).toBe('true');
    expect(screen.getByTestId('user').textContent).toBe('user-1');
  });

  it('ends loading when an action settles without changing the session', async () => {
    const signIn = deferred();
    client.signIn.mockReturnValue(signIn.promise);

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
    expect(screen.getByTestId('loading').textContent).toBe('true');

    await act(async () => {
      signIn.resolve();
      await flush();
    });

    expect(screen.getByTestId('loading').textContent).toBe('false');
    expect(screen.getByTestId('authenticated').textContent).toBe('false');
  });

  it('does not loop when an effect calls getTokens() and nothing is refreshed', async () => {
    client.getSession.mockImplementation(() => Promise.resolve(aSession()));

    const TokenConsumer = (): React.JSX.Element => {
      const { session, getTokens } = useAuth();

      useEffect(() => {
        if (session) {
          void getTokens();
        }
      }, [session, getTokens]);

      return <span data-testid="sub">{session?.user.sub ?? ''}</span>;
    };

    renderWithProvider(<TokenConsumer />, { autoProcessCallback: false });

    await waitFor(() => expect(client.getTokens).toHaveBeenCalled());
    await act(async () => {
      await flush();
    });

    expect(screen.getByTestId('sub').textContent).toBe('user-1');
    expect(client.getTokens).toHaveBeenCalledTimes(1);
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
