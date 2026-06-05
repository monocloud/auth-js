'use client';

import { MonoCloudJsError } from '@monocloud/auth-web-js';
import type { MonoCloudWebJSClient } from '@monocloud/auth-web-js';
import { useContext } from 'react';
import { MonoCloudClientContext } from './context';
import type { MonoCloudAuthProvider } from './monocloud-auth-provider';
import type { useAuth } from './use-auth';

/**
 * `useClient()` returns the underlying {@link MonoCloudWebJSClient} created by
 * {@link MonoCloudAuthProvider}.
 *
 * @remarks
 * This is intended for advanced, lower-level operations that
 * {@link useAuth} does not cover - for example token revocation via
 * `client.oidcClient`. Most applications only need {@link useAuth}.
 *
 * @example Revoking the access token
 *
 * ```tsx title="Revoking the access token"
 * "use client";
 *
 * import { useAuth, useClient } from "@monocloud/auth-react";
 *
 * export default function RevokeButton() {
 *   const { getTokens } = useAuth();
 *   const client = useClient();
 *
 *   const revoke = async () => {
 *     const tokens = await getTokens();
 *     await client.oidcClient.revokeToken(tokens.accessToken);
 *   };
 *
 *   return <button onClick={() => revoke()}>Revoke</button>;
 * }
 * ```
 *
 * @returns The underlying {@link MonoCloudWebJSClient} instance.
 *
 * @category Hooks
 */
export const useClient = (): MonoCloudWebJSClient => {
  const client = useContext(MonoCloudClientContext);

  if (!client) {
    throw new MonoCloudJsError(
      'useClient() can only be used inside a <MonoCloudAuthProvider>...</MonoCloudAuthProvider>.'
    );
  }

  return client;
};
