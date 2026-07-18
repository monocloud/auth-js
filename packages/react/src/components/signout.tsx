'use client';

import type { SignOutOptions } from '@monocloud/auth-web-js';
import React from 'react';
import { useAuth } from '../use-auth';

/**
 * Props for the `<SignOut />` component.
 *
 * @category Types
 */
export interface SignOutProps
  extends SignOutOptions, React.ButtonHTMLAttributes<HTMLButtonElement> {
  /**
   * Content rendered inside the button.
   */
  children: React.ReactNode;
}

/**
 * `<SignOut>` renders a button that starts the sign-out flow when clicked.
 *
 * @example Basic Usage
 *
 * ```tsx:src/SignOutButton.tsx tab="Basic Usage" tab-group="SignOut"
 * "use client";
 *
 * import { SignOut } from "@monocloud/auth-react";
 *
 * export default function Home() {
 *   return <SignOut>Sign Out</SignOut>;
 * }
 * ```
 *
 * @example Customized
 *
 * ```tsx:src/SignOutButton.tsx tab="Customized" tab-group="SignOut"
 * "use client";
 *
 * import { SignOut } from "@monocloud/auth-react";
 *
 * export default function Home() {
 *   return (
 *     <SignOut federatedSignOut>
 *       Log out
 *     </SignOut>
 *   );
 * }
 * ```
 *
 * @param props - Sign-out options.
 * @returns A button that triggers sign-out on click.
 *
 * @category Components
 */
export const SignOut = ({
  children,
  idTokenHint,
  postLogoutRedirectUri,
  mode,
  federatedSignOut,
  returnUrl,
  ...props
}: SignOutProps): React.JSX.Element => {
  const { signOut } = useAuth();

  return (
    <button
      {...props}
      type="button"
      onClick={() => {
        void signOut({
          idTokenHint,
          postLogoutRedirectUri,
          mode,
          federatedSignOut,
          returnUrl,
        });
      }}
    >
      {children}
    </button>
  );
};
