/* eslint-disable import/no-extraneous-dependencies */
import { renderHook, waitFor } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { useMonoCloudAuth } from '../../src/client';
import { fetchOk, wrapper } from '../client-helper';

describe('useMonoCloudAuth() - Base Path', () => {
  it('should pickup base path from __NEXT_ROUTER_BASEPATH', async () => {
    // eslint-disable-next-line no-underscore-dangle
    process.env.__NEXT_ROUTER_BASEPATH = '/test';

    fetchOk('/test/api/auth/userinfo');

    const { result } = renderHook(() => useMonoCloudAuth(), {
      wrapper,
    });

    await waitFor(() => {
      expect(result.current).toEqual({
        error: undefined,
        user: { sub: 'sub', email: 'a@b.com' },
        isAuthenticated: true,
        isLoading: false,
        refetch: expect.any(Function),
      });
    });
  });
});
