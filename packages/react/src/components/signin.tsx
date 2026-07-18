'use client';

import type { SignInOptions } from '@monocloud/auth-web-js';
import React from 'react';
import { useAuth } from '../use-auth';

/**
 * Props for the `<SignIn />` component.
 *
 * @category Types
 */
export interface SignInProps
  extends
    Omit<SignInOptions, 'signUp'>,
    React.ButtonHTMLAttributes<HTMLButtonElement> {
  /**
   * Content rendered inside the button.
   */
  children: React.ReactNode;
}

/**
 * `<SignIn>` renders a button that starts the sign-in flow when clicked.
 *
 * @example Basic Usage
 *
 * ```tsx:src/SignInButton.tsx tab="Basic Usage" tab-group="SignIn"
 * "use client";
 *
 * import { SignIn } from "@monocloud/auth-react";
 *
 * export default function Home() {
 *   return <SignIn>Sign In</SignIn>;
 * }
 * ```
 *
 * @example Customized
 *
 * ```tsx:src/SignInButton.tsx tab="Customized" tab-group="SignIn"
 * "use client";
 *
 * import { SignIn } from "@monocloud/auth-react";
 *
 * export default function Home() {
 *   return (
 *     <SignIn authenticatorHint="google">
 *       Sign in with Google
 *     </SignIn>
 *   );
 * }
 * ```
 *
 * @param props - Sign-in options.
 * @returns A button that triggers sign-in on click.
 *
 * @category Components
 */
export const SignIn = ({
  children,
  authenticatorHint,
  maxAge,
  loginHint,
  uiLocales,
  mode,
  acrValues,
  display,
  prompt,
  resource,
  audience,
  idTokenHint,
  returnUrl,
  scopes,
  appState,
  ...props
}: SignInProps): React.JSX.Element => {
  const { signIn } = useAuth();

  return (
    <button
      {...props}
      type="button"
      onClick={() => {
        void signIn({
          authenticatorHint,
          maxAge,
          loginHint,
          uiLocales,
          mode,
          acrValues,
          display,
          prompt,
          resource,
          audience,
          idTokenHint,
          returnUrl,
          scopes,
          appState,
        });
      }}
    >
      {children}
    </button>
  );
};
