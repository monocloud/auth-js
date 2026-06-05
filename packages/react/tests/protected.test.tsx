/* eslint-disable import/no-extraneous-dependencies */
import { render, screen } from '@testing-library/react';
import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { MonoCloudUser } from '@monocloud/auth-web-js';
import { Protected } from '../src/components/protected';

const { useAuthMock } = vi.hoisted(() => ({ useAuthMock: vi.fn() }));

vi.mock('../src/use-auth', () => ({ useAuth: useAuthMock }));

const user = (claims: Record<string, unknown> = {}): MonoCloudUser =>
  ({ sub: 'user-1', email: 'user@example.com', ...claims }) as MonoCloudUser;

const authedAs = (claims: Record<string, unknown> = {}): void => {
  useAuthMock.mockReturnValue({
    isLoading: false,
    isAuthenticated: true,
    user: user(claims),
    error: undefined,
  });
};

describe('Protected', () => {
  beforeEach(() => useAuthMock.mockReset());

  it('renders nothing while loading', () => {
    useAuthMock.mockReturnValue({ isLoading: true, isAuthenticated: false });

    const { container } = render(
      <Protected fallback={<span>fallback</span>}>secret</Protected>
    );

    expect(container.textContent).toBe('');
  });

  it('renders the fallback when there is an error', () => {
    useAuthMock.mockReturnValue({
      isLoading: false,
      isAuthenticated: true,
      user: user(),
      error: new Error('boom'),
    });

    render(<Protected fallback={<span>fallback</span>}>secret</Protected>);

    expect(screen.getByText('fallback')).toBeTruthy();
    expect(screen.queryByText('secret')).toBeNull();
  });

  it('renders the fallback when unauthenticated', () => {
    useAuthMock.mockReturnValue({
      isLoading: false,
      isAuthenticated: false,
      user: undefined,
      error: undefined,
    });

    render(<Protected fallback={<span>fallback</span>}>secret</Protected>);

    expect(screen.getByText('fallback')).toBeTruthy();
  });

  it('renders the fallback when authenticated but the user is missing', () => {
    useAuthMock.mockReturnValue({
      isLoading: false,
      isAuthenticated: true,
      user: undefined,
      error: undefined,
    });

    render(<Protected fallback={<span>fallback</span>}>secret</Protected>);

    expect(screen.getByText('fallback')).toBeTruthy();
  });

  it('renders null when unauthenticated and no fallback is provided', () => {
    useAuthMock.mockReturnValue({
      isLoading: false,
      isAuthenticated: false,
      user: undefined,
      error: undefined,
    });

    const { container } = render(<Protected>secret</Protected>);

    expect(container.textContent).toBe('');
  });

  it('renders children when authenticated with no group requirement', () => {
    authedAs();

    render(<Protected>secret</Protected>);

    expect(screen.getByText('secret')).toBeTruthy();
  });

  it('renders children when the user is in any of the required groups', () => {
    authedAs({ groups: ['admin'] });

    render(<Protected groups={['admin', 'billing']}>secret</Protected>);

    expect(screen.getByText('secret')).toBeTruthy();
  });

  it('renders the onGroupAccessDenied content when the group does not match', () => {
    authedAs({ groups: ['member'] });

    render(
      <Protected
        groups={['admin']}
        onGroupAccessDenied={u => <span>denied:{u.sub}</span>}
      >
        secret
      </Protected>
    );

    expect(screen.getByText('denied:user-1')).toBeTruthy();
    expect(screen.queryByText('secret')).toBeNull();
  });

  it('renders nothing when the group does not match and no handler is provided', () => {
    authedAs({ groups: ['member'] });

    const { container } = render(
      <Protected groups={['admin']}>secret</Protected>
    );

    expect(container.textContent).toBe('');
  });

  it('requires all groups when matchAllGroups is set', () => {
    authedAs({ groups: ['admin'] });

    const { rerender } = render(
      <Protected groups={['admin', 'billing']} matchAllGroups>
        secret
      </Protected>
    );
    expect(screen.queryByText('secret')).toBeNull();

    authedAs({ groups: ['admin', 'billing'] });
    rerender(
      <Protected groups={['admin', 'billing']} matchAllGroups>
        secret
      </Protected>
    );
    expect(screen.getByText('secret')).toBeTruthy();
  });

  it('supports a custom groups claim', () => {
    authedAs({ roles: ['admin'] });

    render(
      <Protected groups={['admin']} groupsClaim="roles">
        secret
      </Protected>
    );

    expect(screen.getByText('secret')).toBeTruthy();
  });
});
