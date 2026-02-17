import React from 'react';

/**
 * Props for the `<SignOut />` component.
 *
 * @category Types
 */
export interface SignOutProps {
  /** Content rendered inside the link (for example, button text). */
  children: React.ReactNode;

  /** URL to redirect the user to after they have been signed out. */
  postLogoutUrl?: string;

  /** If `true`, also signs the user out of the MonoCloud server session, ensuring the user is fully logged out of MonoCloud and not just your application. */
  federated?: boolean;
}

/**
 * `<SignOut>` renders a link that initiates the MonoCloud sign-out flow.
 *
 * It can be used in both **App Router** and **Pages Router**, and may be rendered from either **Server** or **Client Components**.
 *
 * @example Basic usage
 *
 * ```tsx title="Basic Usage"
 * import { SignOut } from "@monocloud/auth-nextjs/components";
 *
 * export default function Home() {
 *   return <SignOut>Sign Out</SignOut>;
 * }
 * ```
 *
 * @example Customize the sign-out request
 *
 * ```tsx title="Customize the sign-out request"
 * import { SignOut } from "@monocloud/auth-nextjs/components";
 *
 * export default function Home() {
 *   return <SignOut federated postLogoutUrl="/goodbye">Sign Out</SignOut>;
 * }
 * ```
 *
 * @param props - Properties for the SignOut component.
 * @returns An anchor element that links to the sign-out endpoint.
 *
 * @category Components
 */
export const SignOut = ({
  children,
  postLogoutUrl,
  federated,
  ...props
}: SignOutProps &
  React.AnchorHTMLAttributes<HTMLAnchorElement>): React.ReactNode => {
  const signOutUrl =
    process.env.NEXT_PUBLIC_MONOCLOUD_AUTH_SIGNOUT_URL ??
    // eslint-disable-next-line no-underscore-dangle
    `${process.env.__NEXT_ROUTER_BASEPATH ?? ''}/api/auth/signout`;

  const query = new URLSearchParams();

  if (postLogoutUrl) {
    query.set('post_logout_url', postLogoutUrl);
  }

  if (typeof federated === 'boolean') {
    query.set('federated', federated.toString());
  }

  return (
    <a
      href={`${signOutUrl}${query.size ? `?${query.toString()}` : ''}`}
      {...props}
    >
      {children}
    </a>
  );
};
