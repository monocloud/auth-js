'use client';

import type { SignInOptions } from '@monocloud/auth-web-js';
import React from 'react';
import { useAuth } from '../use-auth';

/**
 * Props for the `<SignUp />` component.
 *
 * @category Types
 */
export interface SignUpProps
  extends
    Omit<
      SignInOptions,
      'signUp' | 'authenticatorHint' | 'loginHint' | 'prompt'
    >,
    React.ButtonHTMLAttributes<HTMLButtonElement> {
  /**
   * Content rendered inside the button.
   */
  children: React.ReactNode;
}

/**
 * `<SignUp>` renders a button that starts the sign-up (registration) flow when
 * clicked.
 *
 * @example Basic Usage
 *
 * ```tsx:src/SignUpButton.tsx tab="Basic Usage" tab-group="SignUp"
 * "use client";
 *
 * import { SignUp } from "@monocloud/auth-react";
 *
 * export default function Home() {
 *   return <SignUp>Create account</SignUp>;
 * }
 * ```
 *
 * @example Customized
 *
 * ```tsx:src/SignUpButton.tsx tab="Customized" tab-group="SignUp"
 * "use client";
 *
 * import { SignUp } from "@monocloud/auth-react";
 *
 * export default function Home() {
 *   return (
 *     <SignUp returnUrl="/welcome">
 *       Sign-up now
 *     </SignUp>
 *   );
 * }
 * ```
 *
 * @param props - Sign-up options.
 * @returns A button that triggers sign-up on click.
 *
 * @category Components
 */
export const SignUp = ({
  children,
  maxAge,
  uiLocales,
  mode,
  acrValues,
  display,
  resource,
  audience,
  idTokenHint,
  returnUrl,
  scopes,
  appState,
  ...props
}: SignUpProps): React.JSX.Element => {
  const { signIn } = useAuth();

  return (
    <button
      {...props}
      type="button"
      onClick={() => {
        void signIn({
          signUp: true,
          maxAge,
          uiLocales,
          mode,
          acrValues,
          display,
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
