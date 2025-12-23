/* eslint-disable import/no-extraneous-dependencies */
import { renderHook, waitFor } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { useAuth } from '../../src/client';
import { fetchOk, wrapper } from '../client-helper';

describe('useAuth() - NEXT_PUBLIC_MONOCLOUD_AUTH_USER_INFO_URL', () => {
  it('should get the user from a custom endpoint set through env', async () => {
    process.env.NEXT_PUBLIC_MONOCLOUD_AUTH_USER_INFO_URL = '/test';

    fetchOk('/test');

    const { result } = renderHook(() => useAuth(), {
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
