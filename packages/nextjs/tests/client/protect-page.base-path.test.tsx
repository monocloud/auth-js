/* eslint-disable import/no-extraneous-dependencies */
import { render, waitFor } from '@testing-library/react';
import { describe, it, expect, beforeAll, vi } from 'vitest';
import React from 'react';
import { Component, fetchNoContent, wrapper } from '../client-helper';
import { protectPage } from '../../src/client';

describe('protectPage() - CSR - Base Path', () => {
  beforeAll(() => {
    Object.defineProperty(window, 'location', {
      writable: true,
      value: {
        assign: vi.fn(),
        toString: () => 'https://example.org',
      },
    });
  });

  it('should pickup base path from __NEXT_ROUTER_BASEPATH', async () => {
    // eslint-disable-next-line no-underscore-dangle
    process.env.__NEXT_ROUTER_BASEPATH = '/test';

    fetchNoContent('/test/api/auth/userinfo');

    const ProtectedComponent = protectPage(Component());

    const { container } = render(<ProtectedComponent />, { wrapper });

    await waitFor(() => {
      expect(window.location.assign).toHaveBeenCalledWith(
        '/test/api/auth/signin?return_url=https%3A%2F%2Fexample.org'
      );
      expect(container.textContent).not.toContain('Great Success!!!');
    });
  });
});
