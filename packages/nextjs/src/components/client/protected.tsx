import { isUserInGroup } from '@monocloud/auth-node-core/utils';
import React, { JSX } from 'react';
import { useAuth } from '../../client';

export interface ProtectedComponentProps {
  /**
   * Components that should be rendered if the user is authenticated.
   */
  children: React.ReactNode;

  /**
   * A list of group names or IDs to which the user must belong to. The user should belong to atleast one of the specified groups.
   */
  groups?: string[];

  /**
   * Name of the claim of user's groups. default: `groups`.
   */
  groupsClaim?: string;

  /**
   * Flag indicating if all groups specified should be present in the users profile. default: false.
   */
  matchAllGroups?: boolean;

  /**
   * A fallback component that should render if the user is not authenticated.
   */
  fallback?: React.ReactNode;

  /**
   * A fallback component that should render if the user is authenticated but does not belong to the required groups.
   */
  groupFallback?: React.ReactNode;
}

/**
 * A wrapper component that conditionally renders its children based on the user's authentication
 * status and group membership.
 *
 * **Note⚠️: The component is hidden from view. The data is present in the browser. Use server side `protectPage()` for protecting components before that data is sent to the client.**
 *
 * @param props - Props for customizing the Protected component.
 *
 * @returns The children if authorized, the `fallback` or `groupFallback` content if unauthenticated or unauthorized,
 * or `null` while loading.
 *
 * @example App Router
 *
 * ```tsx
 * "use client";
 *
 * import { Protected } from "@monocloud/auth-nextjs/components/client";
 *
 * export default function Home() {
 *   return (
 *     <Protected fallback={<>Sign in to view the message.</>}>
 *       <>You are breathtaking</>
 *     </Protected>
 *   );
 * }
 * ```
 *
 * @example App Router with group options
 *
 * See {@link ProtectedComponentProps}.
 *
 * ```tsx
 * "use client";
 *
 * import { Protected } from "@monocloud/auth-nextjs/components/client";
 *
 * export default function Home() {
 *   return (
 *     <Protected
 *       groupFallback={<>Only admins are allowed.</>}
 *       groups={["admin"]}
 *     >
 *       <>Signed in as admin</>
 *     </Protected>
 *   );
 * }
 * ```
 *
 * @example Pages Router
 *
 * ```tsx
 * import { Protected } from "@monocloud/auth-nextjs/components/client";
 *
 * export default function Home() {
 *   return (
 *     <Protected fallback={<>Sign in to view the message.</>}>
 *       <>You are breathtaking</>
 *     </Protected>
 *   );
 * }
 * ```
 *
 * @example Pages Router with group options
 *
 * See {@link ProtectedComponentProps}.
 *
 * ```tsx
 * import { Protected } from "@monocloud/auth-nextjs/components/client";
 *
 * export default function Home() {
 *   return (
 *     <Protected
 *       groupFallback={<>Only admins are allowed.</>}
 *       groups={["admin"]}
 *     >
 *       <>Signed in as admin</>
 *     </Protected>
 *   );
 * }
 * ```
 *
 */
export const Protected = ({
  children,
  groups,
  groupsClaim,
  matchAllGroups = false,
  fallback = null,
  groupFallback = null,
}: ProtectedComponentProps): JSX.Element | null => {
  const { isLoading, error, isAuthenticated, user } = useAuth();

  if (isLoading) {
    return null;
  }

  if (error || !isAuthenticated || !user) {
    if (fallback) {
      return <>{fallback}</>;
    }

    return null;
  }

  return (
    <>
      {!groups ||
      isUserInGroup(
        user,
        groups,
        groupsClaim ?? process.env.NEXT_PUBLIC_MONOCLOUD_AUTH_GROUPS_CLAIM,
        matchAllGroups
      )
        ? children
        : groupFallback}
    </>
  );
};
