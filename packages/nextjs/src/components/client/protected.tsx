import { isUserInGroup } from '@monocloud/auth-node-core/utils';
import React, { JSX } from 'react';
import { useMonoCloudAuth } from '../../client';

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
  onAccessDenied?: React.ReactNode;
}

/**
 * A wrapper component that conditionally renders its children based on the user's authentication
 * status and group membership.
 *
 * @param props - The properties for the Protected component.
 *
 * @returns The children if authorized, the `onAccessDenied` content if unauthorized,
 * or `null` while loading.
 */
export const Protected = ({
  children,
  groups,
  groupsClaim,
  matchAllGroups = false,
  onAccessDenied = null,
}: ProtectedComponentProps): JSX.Element | null => {
  const { isLoading, error, isAuthenticated, user } = useMonoCloudAuth();

  if (isLoading) {
    return null;
  }

  if (error || !isAuthenticated || !user) {
    if (onAccessDenied) {
      return <>{onAccessDenied}</>;
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
        : onAccessDenied}
    </>
  );
};
