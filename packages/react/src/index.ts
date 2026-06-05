'use client';

export { MonoCloudAuthProvider } from './monocloud-auth-provider';
export { useAuth } from './use-auth';
export { useClient } from './use-client';

export {
  Protected,
  type ProtectedComponentProps,
} from './components/protected';
export { ProcessCallback } from './components/process-callback';
export { SignIn, type SignInProps } from './components/signin';
export { SignUp, type SignUpProps } from './components/signup';
export { SignOut, type SignOutProps } from './components/signout';

export type {
  AuthState,
  MonoCloudAuth,
  MonoCloudAuthProviderProps,
  ProcessCallbackProps,
} from './types';

export {
  MonoCloudWebJSClient,
  LocalStorage,
  MemoryStorage,
  SessionStorage,
  MonoCloudAuthBaseError,
  MonoCloudJsError,
  MonoCloudOPError,
  MonoCloudValidationError,
  MonoCloudTokenError,
  MonoCloudHttpError,
} from '@monocloud/auth-web-js';

export type {
  MonoCloudWebJSClientOptions,
  IStorage,
  Indicator,
  DefaultAuthParams,
  AuthorizationParams,
  Jwk,
  SignInOptions,
  SignInSilentOptions,
  SignOutOptions,
  RefreshOptions,
  RefreshGrantOptions,
  GetTokensOptions,
  MonoCloudSession,
  MonoCloudTokens,
  AccessToken,
  MonoCloudUser,
  UserinfoResponse,
  IdTokenClaims,
  Address,
  CallbackState,
  ApplicationState,
  PostCallback,
  OnSessionCreating,
  InteractionMode,
  Authenticators,
  ClientAuthMethod,
  Prompt,
  DisplayOptions,
  ResponseTypes,
  ResponseModes,
  CodeChallengeMethod,
  SecurityAlgorithms,
  Group,
} from '@monocloud/auth-web-js';
