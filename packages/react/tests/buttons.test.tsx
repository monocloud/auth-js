/* eslint-disable import/no-extraneous-dependencies */
import { fireEvent, render, screen } from '@testing-library/react';
import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { SignIn } from '../src/components/signin';
import { SignOut } from '../src/components/signout';
import { SignUp } from '../src/components/signup';

const { useAuthMock } = vi.hoisted(() => ({ useAuthMock: vi.fn() }));

vi.mock('../src/use-auth', () => ({ useAuth: useAuthMock }));

const signIn = vi.fn();
const signOut = vi.fn();

describe('button components', () => {
  beforeEach(() => {
    signIn.mockReset();
    signOut.mockReset();
    useAuthMock.mockReturnValue({ signIn, signOut });
  });

  it('SignIn triggers signIn with the given options and forwards button props', () => {
    render(
      <SignIn authenticatorHint="google" className="x">
        Sign In
      </SignIn>
    );

    const button = screen.getByText('Sign In') as HTMLButtonElement;
    expect(button.className).toBe('x');
    expect(button.type).toBe('button');

    fireEvent.click(button);

    expect(signIn).toHaveBeenCalledWith(
      expect.objectContaining({ authenticatorHint: 'google' })
    );
  });

  it('forwards the native disabled attribute to the button', () => {
    render(<SignIn disabled>Sign In</SignIn>);

    expect((screen.getByText('Sign In') as HTMLButtonElement).disabled).toBe(
      true
    );
  });

  it('SignUp triggers signIn with signUp set to true', () => {
    render(<SignUp returnUrl="/welcome">Create account</SignUp>);

    fireEvent.click(screen.getByText('Create account'));

    expect(signIn).toHaveBeenCalledWith(
      expect.objectContaining({ signUp: true, returnUrl: '/welcome' })
    );
  });

  it('SignOut triggers signOut with the given options', () => {
    render(
      <SignOut federatedSignOut returnUrl="/bye">
        Sign Out
      </SignOut>
    );

    fireEvent.click(screen.getByText('Sign Out'));

    expect(signOut).toHaveBeenCalledWith(
      expect.objectContaining({ federatedSignOut: true, returnUrl: '/bye' })
    );
  });
});
