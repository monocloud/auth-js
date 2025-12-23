/* eslint-disable import/no-extraneous-dependencies */
import { renderHook, waitFor } from '@testing-library/react';
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { useMonoCloudAuth } from '../../src/client';
import { fetch500, fetchNoContent, fetchOk, wrapper } from '../client-helper';

describe('useMonoCloudAuth()', () => {
  let ogFetch: any;
  beforeEach(() => {
    ogFetch = global.fetch;
  });

  afterEach(() => {
    global.fetch = ogFetch;
  });

  it('should return error if the server responded with an error', async () => {
    fetch500();

    const { result } = renderHook(() => useMonoCloudAuth(), {
      wrapper,
    });

    await waitFor(() => {
      expect(result.current.error).toBeInstanceOf(Error);
      expect(result.current.error?.message).toBe('Failed to fetch user');
    });
  });

  it('should get the user when the server responds with a success', async () => {
    fetchOk();

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

  it('should return unauthenticated if response from userinfo is 204', async () => {
    fetchNoContent();

    const { result } = renderHook(() => useMonoCloudAuth(), {
      wrapper,
    });

    await waitFor(() => {
      expect(result.current).toEqual({
        error: undefined,
        user: undefined,
        isAuthenticated: false,
        isLoading: false,
        refetch: expect.any(Function),
      });
    });
  });

  it('should be able to update the user using the refetch function from useMonoCloudAuth hook', async () => {
    fetchOk();

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

    fetchOk(undefined, {
      sub: 'sub',
      email: 'a@b.com',
      address: 'userAddress',
    });

    result.current.refetch?.();

    await waitFor(() => {
      expect(result.current).toEqual({
        error: undefined,
        user: { sub: 'sub', email: 'a@b.com', address: 'userAddress' },
        isAuthenticated: true,
        isLoading: false,
        refetch: expect.any(Function),
      });
    });
  });

  it('can refetch even if there is an error in the initial fetch', async () => {
    fetch500();

    const { result } = renderHook(() => useMonoCloudAuth(), { wrapper });

    await waitFor(() => {
      expect(result.current.error).toBeInstanceOf(Error);
      expect(result.current.isAuthenticated).toBe(false);
    });

    fetchOk(undefined, { sub: 'user-id', name: 'John Doe' });

    result.current.refetch?.();

    await waitFor(() => {
      expect(result.current.isAuthenticated).toBe(true);
    });
  });

  it('should call API only once even if useMonoCloudAuth hook calls multiple times', async () => {
    const mockFetch = vi.fn(() => {
      return {
        status: 200,
        ok: true,
        json: (): Promise<any> =>
          Promise.resolve({
            sub: 'sub',
            email: 'a@b.com',
          }),
      };
    });
    (global as any).fetch = mockFetch;

    const { result: resultOne } = renderHook(() => useMonoCloudAuth());

    await waitFor(() => {
      expect(resultOne.current.isAuthenticated).toBe(true);
    });

    const { result: resultTwo } = renderHook(() => useMonoCloudAuth());

    await waitFor(() => {
      expect(resultTwo.current.isAuthenticated).toBe(true);
      expect(mockFetch).toBeCalledTimes(1);
    });
  });
});
