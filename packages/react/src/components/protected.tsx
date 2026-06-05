'use client';

import { isUserInGroup } from '@monocloud/auth-web-js/utils';
import React from 'react';
import type { MonoCloudUser } from '@monocloud/auth-web-js';
import { useAuth } from '../use-auth';

/**
 * Props for the `<Protected />` component.
 *
 * @category Types
 */
export interface ProtectedComponentProps {
  /**
   * Content to render when access is allowed.
   */
  children: React.ReactNode;

  /**
   * Groups required to view the protected content. By default, the user must belong to **any** of the specified groups.
   */
  groups?: string[];

  /**
   * Name of the claim that contains groups in the user profile.
   * @defaultValue 'groups'
   */
  groupsClaim?: string;

  /**
   * If `true`, the user must belong to **all** specified `groups` (instead of any).
   * @defaultValue false
   */
  matchAllGroups?: boolean;

  /**
   * Content to render when the user is not authenticated.
   */
  fallback?: React.ReactNode;

  /**
   * Rendered when the user is authenticated but does not meet the `groups` requirement. If omitted, nothing is rendered (or `fallback` is used only for unauthenticated users).
   */
  onGroupAccessDenied?: (user: MonoCloudUser) => React.ReactNode;
}

/**
 * `<Protected>` conditionally renders its children based on the user’s authentication state and (optionally) group membership.
 *
 * > `<Protected>` runs on the client and only affects what is rendered. It does **not** prevent data from being sent to the browser. Always enforce authorization on your APIs as well.
 *
 * @example Basic Usage
 *
 * ```tsx:src/Home.tsx tab="Basic Usage" tab-group="Protected"
 * "use client";
 *
 * import { Protected } from "@monocloud/auth-react";
 *
 * export default function Home() {
 *   return (
 *     <Protected fallback={<>Sign in to view the message.</>}>
 *       <>This is the protected content.</>
 *     </Protected>
 *   );
 * }
 * ```
 *
 * @example With Groups
 *
 * ```tsx:src/Home.tsx tab="With Groups" tab-group="Protected"
 * "use client";
 *
 * import { Protected } from "@monocloud/auth-react";
 *
 * export default function Home() {
 *   return (
 *     <Protected
 *       groups={["admin"]}
 *       onGroupAccessDenied={(user) => <>User {user.email} is not allowed to access admin content.</>}
 *     >
 *       <>Signed in as admin</>
 *     </Protected>
 *   );
 * }
 * ```
 *
 * @example Requiring all groups
 *
 * ```tsx:src/Home.tsx tab="Requiring all groups" tab-group="Protected"
 * "use client";
 *
 * import { Protected } from "@monocloud/auth-react";
 *
 * export default function Home() {
 *   return (
 *     <Protected
 *       groups={["admin", "billing"]}
 *       matchAllGroups
 *       onGroupAccessDenied={(user) => <>User {user.email} is not allowed to access billing content.</>}
 *     >
 *       <>Sensitive settings</>
 *     </Protected>
 *   );
 * }
 * ```
 *
 * @param props - Props for customizing the Protected component.
 * @returns The children if authorized, the `fallback` or `onGroupAccessDenied` content if unauthenticated or unauthorized, or `null` while loading.
 *
 * @category Components
 */
export const Protected = ({
  children,
  groups,
  groupsClaim,
  matchAllGroups = false,
  fallback = null,
  onGroupAccessDenied = (): React.ReactNode => <></>,
}: ProtectedComponentProps): React.ReactNode | null => {
  const { isLoading, error, isAuthenticated, user } = useAuth();

  if (isLoading) {
    return null;
  }

  if (error || !isAuthenticated || !user) {
    if (fallback) {
      return fallback;
    }

    return null;
  }

  return (
    <>
      {!groups || isUserInGroup(user, groups, groupsClaim, matchAllGroups)
        ? children
        : onGroupAccessDenied(user)}
    </>
  );
};
