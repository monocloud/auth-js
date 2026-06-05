import type {
  GetTokensOptions,
  MonoCloudSession,
  MonoCloudTokens,
  MonoCloudUser,
  MonoCloudWebJSClientOptions,
  RefreshOptions,
  SignInOptions,
  SignInSilentOptions,
  SignOutOptions,
} from '@monocloud/auth-web-js';
import type { ReactNode } from 'react';

/**
 * The current authentication state.
 *
 * @category Types
 */
export interface AuthState {
  /**
   * Flag indicating if the authentication state is still loading.
   */
  isLoading: boolean;

  /**
   * Flag indicating if the user is authenticated.
   */
  isAuthenticated: boolean;

  /**
   * Error encountered during authentication, if any.
   */
  error?: Error;

  /**
   * The authenticated user's information, if available.
   */
  user?: MonoCloudUser;

  /**
   * The current session, including tokens and the user, if available.
   */
  session?: MonoCloudSession;
}

/**
 * The current authentication state and the authentication actions.
 *
 * @category Types
 */
export interface MonoCloudAuth extends AuthState {
  /**
   * Initiates the sign-in flow.
   */
  signIn: (signInOptions?: SignInOptions) => Promise<void>;

  /**
   * Initiates the sign-out flow.
   */
  signOut: (signOutOptions?: SignOutOptions) => Promise<void>;

  /**
   * Attempts to silently restore the session via a hidden iframe (`prompt=none`).
   */
  signInSilent: (
    signInSilentOptions?: SignInSilentOptions
  ) => Promise<MonoCloudSession>;

  /**
   * Refreshes the current session using the Refresh Token Grant.
   */
  refreshSession: (refreshOptions?: RefreshOptions) => Promise<void>;

  /**
   * Refetches the user's profile from the UserInfo endpoint and updates the session.
   */
  refetchUserInfo: () => Promise<void>;

  /**
   * Retrieves the active tokens, refreshing them if they have expired.
   */
  getTokens: (options?: GetTokensOptions) => Promise<MonoCloudTokens>;
}

/**
 * Props for `<MonoCloudAuthProvider />`.
 *
 * @category Types
 */
export interface MonoCloudAuthProviderProps extends MonoCloudWebJSClientOptions {
  /**
   * The application tree that should have access to the authentication context.
   */
  children: ReactNode;

  /**
   * When `true` (the default), the provider processes the OIDC callback
   * automatically when it mounts. Set it to `false` when you handle the callback
   * yourself with `<ProcessCallback />` on a dedicated route.
   *
   * @defaultValue true
   */
  autoProcessCallback?: boolean;
}

/**
 * Props for the `<ProcessCallback />` component.
 *
 * @category Types
 */
export interface ProcessCallbackProps {
  /**
   * Content rendered while the callback is being processed.
   *
   * @defaultValue null
   */
  loading?: ReactNode;

  /**
   * Content rendered when callback processing fails.
   */
  error?: ReactNode | ((error: Error) => ReactNode);

  /**
   * Content rendered after the callback has been processed successfully.
   *
   * @defaultValue null
   */
  children?: ReactNode;
}
