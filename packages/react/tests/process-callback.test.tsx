/* eslint-disable import/no-extraneous-dependencies */
import { render, screen, waitFor } from '@testing-library/react';
import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { MonoCloudJsError } from '@monocloud/auth-web-js';
import { ProcessCallback } from '../src/components/process-callback';
import {
  aSession,
  makeMockClient,
  renderWithProvider,
  setMockClient,
  type MockClient,
} from './utils';

describe('ProcessCallback', () => {
  let client: MockClient;

  beforeEach(() => {
    client = makeMockClient();
    setMockClient(client);
  });

  it('throws when rendered outside of a provider', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});

    expect(() => render(<ProcessCallback />)).toThrow(MonoCloudJsError);

    spy.mockRestore();
  });

  it('renders the loading slot while the callback is being processed', () => {
    client.processCallback.mockReturnValue(new Promise(() => {}));

    renderWithProvider(
      <ProcessCallback loading={<span>loading</span>}>done</ProcessCallback>,
      { autoProcessCallback: false }
    );

    expect(screen.getByText('loading')).toBeTruthy();
    expect(screen.queryByText('done')).toBeNull();
  });

  it('processes the callback once and renders children on success', async () => {
    client.getSession.mockResolvedValue(aSession());

    renderWithProvider(
      <ProcessCallback loading={<span>loading</span>}>done</ProcessCallback>,
      { autoProcessCallback: false }
    );

    await waitFor(() => expect(screen.getByText('done')).toBeTruthy());
    expect(client.processCallback).toHaveBeenCalledTimes(1);
  });

  it('renders the error render-function on failure', async () => {
    client.processCallback.mockRejectedValue(new Error('boom'));

    renderWithProvider(
      <ProcessCallback
        loading={<span>loading</span>}
        error={e => <span>error:{e.message}</span>}
      />,
      { autoProcessCallback: false }
    );

    await waitFor(() => expect(screen.getByText('error:boom')).toBeTruthy());
  });

  it('renders the error node on failure', async () => {
    client.processCallback.mockRejectedValue(new Error('boom'));

    renderWithProvider(<ProcessCallback error={<span>failed</span>} />, {
      autoProcessCallback: false,
    });

    await waitFor(() => expect(screen.getByText('failed')).toBeTruthy());
  });

  it('renders nothing on failure when no error slot is provided', async () => {
    client.processCallback.mockRejectedValue(new Error('boom'));

    const { container } = renderWithProvider(<ProcessCallback />, {
      autoProcessCallback: false,
    });

    await waitFor(() => expect(client.processCallback).toHaveBeenCalled());
    await waitFor(() => expect(container.textContent).toBe(''));
  });
});
