import type {
  Authenticators,
  AuthorizationParams,
  DisplayOptions,
  MonoCloudUser,
  Prompt,
} from '@monocloud/auth-node-core';
import type { NextFetchEvent, NextRequest, NextResponse } from 'next/server';
import type {
  GetServerSideProps,
  GetServerSidePropsContext,
  GetServerSidePropsResult,
  NextApiRequest,
  NextApiResponse,
} from 'next/types';
import type { ParsedUrlQuery } from 'node:querystring';
import { JSX } from 'react';

/**
 * Context object passed to App Router API route handlers.
 * Contains the dynamic route parameters.
 */
export interface AppRouterContext {
  params: Record<string, string | string[]>;
}

/**
 * Return type of `monoCloudAuth()` handler.
 */
export type MonoCloudAuthHandler = (
  req: Request | NextRequest | NextApiRequest,
  resOrCtx?:
    | Response
    | NextResponse<any>
    | NextApiResponse<any>
    | AppRouterContext
) => Promise<Response | NextResponse | void | any>;

/** Return type of Next.js middleware/proxy */
export type NextMiddlewareResult =
  | NextResponse
  | Response
  | null
  | undefined
  | void;

/**
 * Handler function triggered when a user is denied access in Next.js Middleware.
 *
 * @param request - The incoming Next.js request.
 * @param event - The Next.js fetch event.
 * @param user - The authenticated user object (if available).
 * @returns A `NextMiddlewareResult` (e.g., a redirect or rewrite) or a Promise resolving to one.
 */
type NextMiddlewareOnAccessDenied = (
  request: NextRequest,
  event: NextFetchEvent,
  user?: MonoCloudUser
) => NextMiddlewareResult | Promise<NextMiddlewareResult>;

/**
 *
 * ProtectedRouteMatcher can be a combination of the following types.
 *
 * - `string` : Relative route that should be protected.
 * - `RegExp` : A regular expression used to match relative routes that should be protected.
 * - `{ routes: string[]; groups: string[] }` : Users belonging to any of the group names or IDs listed in groups are granted access to the route paths specified in routes.
 */
type ProtectedRouteMatcher =
  | string
  | RegExp
  | {
      /**
       * Routes accessible by the users of specified groups
       */
      routes: (string | RegExp)[];
      /**
       * A list of group IDs or names specifying the groups the user must belong for accessing the routes.
       */
      groups: string[];
    };

/**
 * A function to be executed that determines whether the route is protected.
 */
type CustomProtectedRouteMatcher = (
  req: NextRequest
) => Promise<boolean> | boolean;

/**
 * @param req - The Next.js request object.
 * @param ctx - App Router context that contains dynamic route values.
 * @param error - Error occured during execution of the endpoint.
 * @returns A promise of the response
 */
type AppOnError<T = any> = (
  req: NextRequest,
  ctx: T,
  error: Error
) => Promise<NextResponse | void> | NextResponse | void;

/**
 * @param req - The Next.js API request object.
 * @param res - The Next.js API response object.
 * @param error - Error occured during execution of the endpoint.
 * @returns A promise of void
 */
type PageOnError = (
  req: NextApiRequest,
  res: NextApiResponse,
  error: Error
) => Promise<void> | void;

/**
 * A route handler function used to handle errors that occur during the signin, callback, signout and userinfo endpoint execution.
 *
 * `Note` - In the app router error handler, failing to return a `NextResponse` or throw an error will cause the request to hang. Same happens in the page router if you don't call `res.send()` or `res.json()` after you handle the error.
 */
type OnError = AppOnError | PageOnError;

/**
 * Options for `monoCloudAuth()`.
 */
export interface MonoCloudAuthOptions {
  /**
   * Error handler for signin, callback, signout and userinfo endpoints.
   */
  onError?: OnError;
}

/**
 * Configuration for protected routes.
 */
type ProtectedRoutes = ProtectedRouteMatcher[] | CustomProtectedRouteMatcher;

/**
 * Options for configuring MonoCloud authentication middleware.
 */
export interface MonoCloudMiddlewareOptions {
  /**
   * Error handler for signin, callback, signout and userinfo endpoints.
   *
   * @param req - The Next.js request object.
   * @param evt - The Next.js FetchEvent.
   * @param error - Error occured during execution of the endpoint.
   * @returns A promise of the response or void
   */
  onError?: (
    req: NextRequest,
    evt: NextFetchEvent,
    error: Error
  ) => Promise<NextResponse | void> | NextResponse | void;

  /**
   * Specifies the routes that require authentication. @see ProtectedRoutes
   *
   * If an empty array is passed as the value for the protected routes configuration, no routes will be protected.
   */
  protectedRoutes?: ProtectedRoutes;

  /**
   * The name of the groups claim in the user profile. Default: `groups`.
   */
  groupsClaim?: string;

  /**
   * If true, user must be a member of all groups. Default: false.
   */
  matchAll?: boolean;

  /**
   * A middleware function called when the user is not authenticated or is not a member of the specified groups.
   */
  onAccessDenied?: NextMiddlewareOnAccessDenied;
}

/**
 * A subset of authorization parameters used on client side functions
 */
export type ExtraAuthParams = Pick<
  AuthorizationParams,
  | 'scopes'
  | 'resource'
  | 'prompt'
  | 'display'
  | 'uiLocales'
  | 'acrValues'
  | 'authenticatorHint'
  | 'maxAge'
  | 'loginHint'
>;

/**
 * Represents a Next.js App Router React Server Component.
 *
 * @param props - The props object containing `params` and `searchParams`.
 *
 * @returns A JSX Element or a Promise resolving to one.
 */
export type AppRouterPageHandler = (props: {
  params?: Record<string, string | string[]>;
  searchParams?: Record<string, string | string[] | undefined>;
}) => Promise<JSX.Element> | JSX.Element;

/** App Router API Route Handler */
export type AppRouterApiHandlerFn = (
  req: NextRequest | Request,
  ctx: AppRouterContext
) => Promise<Response | NextResponse> | Response | NextResponse;

/**
 * Options for configuring `protectPage()` in the App Router.
 */
export type ProtectAppPageOptions = {
  /**
   * The URL to return to after authentication.
   */
  returnUrl?: string;

  /**
   * Alternate page handler called when the user is not authenticated or is not a member of the specified groups.
   */
  onAccessDenied?: (props: {
    user?: MonoCloudUser;
    params?: Record<string, string | string[]>;
    searchParams?: Record<string, string | string[] | undefined>;
  }) => Promise<JSX.Element> | JSX.Element;

  /**
   * Authorization parameters to be used during authentication.
   */
  authParams?: ExtraAuthParams;
} & GroupOptions;

/**
 * Options for configuring `protectPage()` in the Pages Router.
 *
 * @typeParam P - The type of the props returned by `getServerSideProps`.
 * @typeParam Q - The type of the parsed query object.
 */
export type ProtectPagePageOptions<
  P extends Record<string, any> = Record<string, any>,
  Q extends ParsedUrlQuery = ParsedUrlQuery,
> = {
  /**
   * Function to fetch server-side props for the protected page handler.
   * If provided, this function will be called before rendering the protected page.
   *
   * @param context - The Next.js context object, including the request and response objects.
   * @returns Server-side props for the protected page.
   */
  getServerSideProps?: GetServerSideProps<P, Q>;

  /**
   * Specifies the URL to redirect to after authentication.
   */
  returnUrl?: string;

  /**
   * Alternate `getServerSideProps` function called when the user is not authenticated or is not a member of the specified groups.
   */
  onAccessDenied?: ProtectPagePageOnAccessDeniedType<P, Q>;

  /**
   * Authorization parameters to be used during authentication.
   */
  authParams?: ExtraAuthParams;
} & GroupOptions;

/**
 * Handler function triggered when a user is denied access in a Pages Router `getServerSideProps` flow.
 *
 * @typeParam P - The type of the props.
 * @typeParam Q - The type of the parsed query object.
 *
 * @param context - The server-side props context extended with the optional user object.
 *
 * @returns The result for `getServerSideProps`.
 */
export type ProtectPagePageOnAccessDeniedType<
  P,
  Q extends ParsedUrlQuery = ParsedUrlQuery,
> = (
  context: GetServerSidePropsContext<Q> & { user?: MonoCloudUser }
) => Promise<GetServerSidePropsResult<P>> | GetServerSidePropsResult<P>;

/**
 * The return type of the `protectPage()` wrapper for Pages Router.
 * It returns a function compatible with `getServerSideProps` that injects the user into props.
 *
 * @typeParam P - The type of the props.
 * @typeParam Q - The type of the parsed query object.
 *
 * @returns `GetServerSidePropsResult` with user injected
 */
export type ProtectPagePageReturnType<
  P,
  Q extends ParsedUrlQuery = ParsedUrlQuery,
> = (
  context: GetServerSidePropsContext<Q>
) => Promise<
  GetServerSidePropsResult<P & { user: MonoCloudUser; accessDenied?: boolean }>
>;

/**
 * The App Router server component that protectPage wraps and secures
 */
export type ProtectedAppServerComponent = (props: {
  user: MonoCloudUser;
  params?: Record<string, string | string[]>;
  searchParams?: Record<string, string | string[] | undefined>;
}) => Promise<JSX.Element> | JSX.Element;

/**
 * Handler function triggered when a user is denied access in an App Router API route.
 *
 * @param req - The incoming Next.js request.
 * @param ctx - The App Router context.
 *
 * @param user - The authenticated user object (if available).
 *
 * @returns A Response/NextResponse or Promise resolving to one.
 */
export type AppRouterApiOnAccessDeniedHandler = (
  req: NextRequest,
  ctx: AppRouterContext,
  user?: MonoCloudUser
) => Promise<Response> | Response;

/** Options for App Router `protectApi()` */
export type ProtectApiAppOptions = {
  /**
   * Alternate app router api handler called when the user is not authenticated or is not a member of the specified groups.
   */
  onAccessDenied?: AppRouterApiOnAccessDeniedHandler;
} & GroupOptions;

/**
 * Handler function triggered when a user is denied access in a Pages Router API route.
 *
 * @param req - The incoming Next.js API request.
 * @param res - The Next.js API response.
 * @param user - The authenticated user object (if available).
 *
 * @returns
 */
export type PageRouterApiOnAccessDeniedHandler = (
  req: NextApiRequest,
  res: NextApiResponse<any>,
  user?: MonoCloudUser
) => Promise<unknown> | unknown;

/** Options for Page Router `protectApi()` */
export type ProtectApiPageOptions = {
  /**
   * Alternate page router api handler called when the user is not authenticated or is not a member of the specified groups.
   */
  onAccessDenied?: PageRouterApiOnAccessDeniedHandler;
} & GroupOptions;

/**
 * Options for the `protect()` helper function.
 */
export type ProtectOptions = {
  /**
   * The url where the user will be redirected to after sign in.
   */
  returnUrl?: string;

  /**
   * Authorization parameters to be used during authentication.
   */
  authParams?: ExtraAuthParams;
} & GroupOptions;

/**
 * Configuration options for checking if a user belongs to specific groups.
 */
export interface IsUserInGroupOptions {
  /**
   * The name of the groups claim in the user profile. Default: `groups`.
   */
  groupsClaim?: string;

  /**
   * If true, user must be a member of all groups. Default: false.
   */
  matchAll?: boolean;
}

/**
 * Extended configuration options that include a list of required groups.
 */
export interface GroupOptions extends IsUserInGroupOptions {
  /**
   * A list of group IDs or names specifying the groups the user must belong to.
   */
  groups?: string[];
}

/**
 * Options for `redirectToSignIn()`
 */
export interface RedirectToSignInOptions {
  /**
   * The URL to which the user should be redirected after successful sign-in.
   */
  returnUrl?: string;
  /**
   * Maximum allowed time in seconds since the last End-User authentication.
   */
  maxAge?: number;
  /**
   * A hint to the authorization server about the desired authenticator the client wishes to authenticate the user with
   */
  authenticatorHint?: Authenticators;
  /**
   * An array of scopes requested from the authorization server
   */
  scopes?: string[];
  /**
   * List of resources the access token should be scoped to
   */
  resource?: string[];
  /**
   * User's preferred languages and scripts for the user interface
   */
  uiLocales?: string;
  /**
   * The desired user interface mode
   */
  display?: DisplayOptions;
  /**
   * An array of authentication context class references (ACRs).
   */
  acrValues?: string[];
  /**
   *  A hint to the authorization server about the user's identifier
   */
  loginHint?: string;
  /**
   * The desired authentication behaviour.
   * - `none`: User is not prompted to sign in.
   * - `login`: Prompt the user to log in even if the user is already authenticated.
   * - `consent`: Prompt the user for consent.
   * - `select_account`: Prompt the user to sign in.
   * - `create`: Prompt the user to sign up.
   */
  prompt?: Prompt;
}

/**
 * Options for `redirectToSignOut()`
 */
export interface RedirectToSignOutOptions {
  /**
   * The url authorization server should redirect the user to after a successful sign out. This url has to be registered in the client's sign out url section.
   */
  postLogoutRedirectUri?: string;

  /** Whether to also sign out the user from MonoCloud */
  federated?: boolean;
}
