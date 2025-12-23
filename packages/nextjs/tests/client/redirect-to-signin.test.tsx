/* eslint-disable import/no-extraneous-dependencies */
import { render, waitFor } from '@testing-library/react';
import { describe, it, expect, beforeAll, vi } from 'vitest';
import React, { JSX } from 'react';
import { fetchNoContent, wrapper } from '../client-helper';
import { RedirectToSignIn } from '../../src/components/client/redirect-to-signin';
import { useMonoCloudAuth } from '../../src/client/use-monocloud-auth';

export const Component = (): JSX.Element => {
  const { user } = useMonoCloudAuth();
  if (!user) {
    return <RedirectToSignIn />;
  }
  return <p>Great Success!!!</p>;
};

describe('<RedirectToSignIn/>', () => {
  beforeAll(() => {
    Object.defineProperty(window, 'location', {
      writable: true,
      value: {
        assign: vi.fn(),
        toString: () => 'https://example.org',
      },
    });
  });

  it('should redirect to the sign in endpoint', async () => {
    const ogFetch = global.fetch;

    fetchNoContent();

    const { container } = render(<Component />, { wrapper });

    await waitFor(() => {
      expect(window.location.assign).toHaveBeenCalledWith(
        '/api/auth/signin?return_url=https%3A%2F%2Fexample.org'
      );
      expect(container.textContent).not.toContain('Great Success!!!');
    });

    global.fetch = ogFetch;
  });
});
