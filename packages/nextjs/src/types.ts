import type {
  AuthorizationParams,
  MonoCloudUser,
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
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore TS6192: Imported only to resolve TypeDoc `{@link ...}` references in this file.
import type {
  authMiddleware,
  monoCloudAuth,
  protect,
  protectApi,
  protectPage,
  redirectToSignIn,
  redirectToSignOut,
} from './initialize';

/**
 * Context object provided to App Router route handlers.
 *
 * Contains dynamic route parameters resolved from the matched route segment (for example, `[id]` or `[...slug]`).
 *
 * In streaming or async environments, `params` may be provided as a Promise.
 *
 * @category Types
 */
export interface AppRouterContext {
  /**
   * Dynamic route parameters extracted from the request URL.
   */
  params:
    | Record<string, string | string[]>
    | Promise<Record<string, string | string[]>>;
}

/**
 * Handler function returned by {@link monoCloudAuth | monoCloudAuth()}.
 *
 * This handler processes authentication routes such as sign-in, callback, sign-out, and userinfo across supported Next.js runtimes (App Router, Pages Router, and API routes).
 *
 * @category Types (Handler)
 */
export type MonoCloudAuthHandler = (
  /**
   * Incoming request object.
   */
  req: Request | NextRequest | NextApiRequest,

  /**
   * Response object or App Router context.
   */
  resOrCtx?:
    | Response
    | NextResponse<any>
    | NextApiResponse<any>
    | AppRouterContext
) => Promise<Response | NextResponse | void | any>;

/**
 * Possible return values from a Next.js middleware or proxy handler.
 *
 * @category Types
 */
export type NextMiddlewareResult =
  | NextResponse
  | Response
  | null
  | undefined
  | void;

/**
 * Handler invoked when access is denied during Next.js middleware execution.
 *
 * This callback allows you to customize how unauthenticated or unauthorized requests are handled, for example by redirecting, rewriting, or returning a custom response.
 *
 * @category Types (Handler)
 *
 * @param request The incoming Next.js request.
 * @param event The associated Next.js fetch event.
 * @returns A middleware result that determines how the request should proceed.
 */
export type NextMiddlewareOnAccessDenied = (
  request: NextRequest,
  event: NextFetchEvent
) => NextMiddlewareResult | Promise<NextMiddlewareResult>;

/**
 * Handler invoked when an authenticated user is denied access during Next.js middleware execution due to group authorization rules.
 *
 * This callback allows you to customize how authorization failures are handled, for example by redirecting, rewriting, or returning a custom response.
 *
 * @category Types (Handler)
 *
 * @param request The incoming Next.js request.
 * @param event The associated Next.js fetch event.
 * @param user The authenticated user who failed the group authorization check.
 * @returns A middleware result that determines how the request should proceed.
 */
export type NextMiddlewareOnGroupAccessDenied = (
  request: NextRequest,
  event: NextFetchEvent,
  user: MonoCloudUser
) => NextMiddlewareResult | Promise<NextMiddlewareResult>;

/**
 *
 * Defines how routes are matched and protected by authentication and optional group-based authorization.
 *
 * @category Types
 *
 */
export type ProtectedRouteMatcher =
  /** A single relative route path to protect. */
  | string
  /** A regular expression used to match routes to protect. */
  | RegExp
  /** An object with fine-grained control over routes and group-based access. */
  | {
      /**
       * Route patterns that should be protected. Each entry may be a relative route path or a regular expression used to match routes.
       */
      routes: (string | RegExp)[];

      /**
       * Optional group-based access control.
       *
       * When provided, only users belonging to **at least one** of the specified group IDs or names are allowed access.
       */
      groups: string[];
    };

/**
 * Function used to dynamically determine whether a request should be treated as a protected route.
 *
 * @category Types (Handler)
 *
 * @param req The incoming Next.js request.
 * @returns Return `true` to require authentication for the request, or `false` to allow it to continue without protection.
 */
export type CustomProtectedRouteMatcher = (
  req: NextRequest
) => Promise<boolean> | boolean;

/**
 * Handler invoked when an error occurs during execution of an App Router endpoint.
 *
 * Allows custom error handling such as logging, transforming the response, or returning a custom `NextResponse`
 *
 * @category Types (Handler)
 *
 * @param req The incoming Next.js request.
 * @param ctx The App Router context containing dynamic route parameters.
 * @typeParam T The type of the App Router context passed to the handler.
 * @param error The error thrown during endpoint execution.
 * @returns Returns a `NextResponse` or `void`.
 */
export type AppOnError<T = any> = (
  req: NextRequest,
  ctx: T,
  error: Error
) => Promise<NextResponse | void> | NextResponse | void;

/**
 * Handler invoked when an error occurs during execution of a Pages Router API endpoint.
 *
 * Allows custom error handling such as logging, modifying the response, or sending a custom error payload.
 *
 * @category Types (Handler)
 *
 * @param req The incoming Next.js API request.
 * @param res The outgoing Next.js API response.
 * @param error The error thrown during endpoint execution.
 * @returns Returns `void` or a Promise that resolves when error handling is complete.
 */
export type PageOnError = (
  req: NextApiRequest,
  res: NextApiResponse,
  error: Error
) => Promise<void> | void;

/**
 * Error handler invoked when an exception occurs during execution of the sign-in, callback, sign-out, or userinfo endpoints.
 *
 * > - In the **App Router**, you must either return a `NextResponse` or throw an error. Otherwise, the request will remain unresolved.
 * > - In the **Pages Router**, you must send a response (for example, `res.send()` or `res.json()`) after handling the error, or the request will hang.
 *
 * @category Types (Handler)
 */
export type OnError = AppOnError | PageOnError;

/**
 * Options for {@link monoCloudAuth | monoCloudAuth()}.
 *
 * @category Types
 */
export interface MonoCloudAuthOptions {
  /**
   * Optional error handler invoked when an exception occurs during execution of the sign-in, callback, sign-out, or userinfo endpoints.
   */
  onError?: OnError;
}

/**
 * Configuration used to determine which routes require authentication.
 *
 * You can provide:
 *
 * - An array of {@link ProtectedRouteMatcher} values to declaratively define protected routes.
 * - A {@link CustomProtectedRouteMatcher} function for fully dynamic protection logic.
 *
 * @category Types
 */
export type ProtectedRoutes =
  | ProtectedRouteMatcher[]
  | CustomProtectedRouteMatcher;

/**
 * Options for configuring {@link authMiddleware | authMiddleware()}.
 *
 * These options control which routes are protected and how authentication and authorization failures are handled during request processing.
 *
 * @category Types
 */
export interface MonoCloudMiddlewareOptions {
  /**
   * Error handler invoked when an error occurs during execution of authentication endpoints handled by the middleware.
   *
   * @param req The incoming Next.js request.
   * @param evt The associated Next.js fetch event.
   * @param error The error thrown during execution.
   * @returns Returns a response to continue the middleware chain, or `void`.
   */
  onError?: (
    req: NextRequest,
    evt: NextFetchEvent,
    error: Error
  ) => Promise<NextResponse | void> | NextResponse | void;

  /**
   * Defines which routes require authentication.
   *
   * Accepts either an array of {@link ProtectedRouteMatcher} or a {@link CustomProtectedRouteMatcher}.
   * If omitted, all routes matched by the middleware config are protected.
   * If an empty array is provided, no routes are protected.
   */
  protectedRoutes?: ProtectedRoutes;

  /**
   * Name of the claim in the user profile that contains group memberships.
   *
   * @defaultValue 'groups'
   */
  groupsClaim?: string;

  /**
   * When `true`, the user must belong to **all** specified groups for authorization to succeed. Otherwise, membership in any one group is sufficient.
   *
   * @defaultValue false
   */
  matchAll?: boolean;

  /**
   * Middleware handler invoked when the user is not authenticated.
   */
  onAccessDenied?: NextMiddlewareOnAccessDenied;

  /**
   * Middleware handler invoked when the user is authenticated but does not satisfy group authorization requirements.
   */
  onGroupAccessDenied?: NextMiddlewareOnGroupAccessDenied;
}

/**
 * A subset of authorization parameters supported by client-side helpers.
 *
 * @category Types
 */
// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export interface ExtraAuthParams extends Pick<
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
> {}

/**
 * Represents a Next.js App Router page component (Server Component).
 *
 * @category Types (Handler)
 *
 * @param props Page props provided by Next.js, including dynamic route parameters and URL search parameters.
 * @returns A JSX element, or a Promise resolving to one.
 */
export type AppRouterPageHandler = (props: {
  /**
   * Dynamic route parameters extracted from the URL.
   */
  params?: Record<string, string | string[]>;

  /**
   * URL search parameters (`?key=value`) parsed by Next.js.
   */
  searchParams?: Record<string, string | string[] | undefined>;
}) => Promise<JSX.Element> | JSX.Element;

/**
 * Represents a Next.js App Router Route Handler function.
 *
 * @category Types (Handler)
 *
 * @param req The incoming request object.
 * @param ctx Route context containing dynamic route parameters.
 * @returns A `Response` or `NextResponse`, or a Promise resolving to one.
 */
export type AppRouterApiHandlerFn = (
  req: NextRequest | Request,
  ctx: AppRouterContext
) => Promise<Response | NextResponse> | Response | NextResponse;

/**
 * Options for configuring {@link protectPage | protectPage()} in the App Router.
 *
 * @category Types
 */
export interface ProtectAppPageOptions extends GroupOptions {
  /**
   * The URL the user should be returned to after successful authentication.
   *
   * Defaults to the current request URL.
   */
  returnUrl?: string;

  /**
   * Alternate Server Component rendered when the user is **not authenticated**.
   *
   * If not provided, the default behavior redirects the user to the sign-in flow.
   */
  onAccessDenied?: (props: {
    params?: Record<string, string | string[]>;
    searchParams?: Record<string, string | string[] | undefined>;
  }) => Promise<JSX.Element> | JSX.Element;

  /**
   * Alternate Server Component rendered when the user is authenticated but does **not** belong to the required groups.
   *
   * Receives the resolved authenticated user.
   */
  onGroupAccessDenied?: (props: {
    user: MonoCloudUser;
    params?: Record<string, string | string[]>;
    searchParams?: Record<string, string | string[] | undefined>;
  }) => Promise<JSX.Element> | JSX.Element;

  /**
   * Additional authorization parameters applied when redirecting the user to authenticate.
   */
  authParams?: ExtraAuthParams;
}

/**
 * Options for configuring {@link protectPage | protectPage()} in the Pages Router.
 *
 * @category Types
 *
 * @typeParam P Props returned from `getServerSideProps`.
 * @typeParam Q Query parameters parsed from the URL.
 */
export interface ProtectPagePageOptions<
  P extends Record<string, any> = Record<string, any>,
  Q extends ParsedUrlQuery = ParsedUrlQuery,
> extends GroupOptions {
  /**
   * An optional `getServerSideProps` implementation that runs after authentication (and group checks, if configured). Use this to compute additional props for the page.
   */
  getServerSideProps?: GetServerSideProps<P, Q>;

  /**
   * The URL the user should be returned to after successful authentication.
   *
   * Defaults to the current request URL.
   */
  returnUrl?: string;

  /**
   * Called when no valid session exists.
   *
   * If not provided, the default behavior redirects the user to the sign-in flow.
   */
  onAccessDenied?: ProtectPagePageOnAccessDeniedType<P, Q>;

  /**
   * Called when the user is authenticated but does not satisfy the group requirements.
   *
   * If not provided, the default behavior continues rendering and sets `groupAccessDenied` in the returned props, or applies the SDK’s default access-denied behavior.
   */
  onGroupAccessDenied?: ProtectPagePageOnGroupAccessDeniedType<P, Q>;

  /**
   * Additional authorization parameters applied when redirecting the user to authenticate.
   */
  authParams?: ExtraAuthParams;
}

/**
 * Handler invoked when no valid session exists while running a Pages Router `getServerSideProps` protected by {@link protectPage | protectPage()}.
 *
 * @category Types (Handler)
 *
 * @typeParam P Props returned from `getServerSideProps`.
 * @typeParam Q Query parameters parsed from the URL.
 * @param context The Next.js `getServerSideProps` context.
 * @returns A `getServerSideProps` result.
 */
export type ProtectPagePageOnAccessDeniedType<
  P,
  Q extends ParsedUrlQuery = ParsedUrlQuery,
> = (
  context: GetServerSidePropsContext<Q>
) => Promise<GetServerSidePropsResult<P>> | GetServerSidePropsResult<P>;

/**
 * Next.js `getServerSideProps` context extended with the authenticated user when using {@link protectPage | protectPage()}.
 *
 * @category Types (Handler)
 *
 */
export interface ProtectPageGetServerSidePropsContext<
  Q extends ParsedUrlQuery = ParsedUrlQuery,
> extends GetServerSidePropsContext<Q> {
  /**
   * The authenticated user resolved from the current session.
   */
  user: MonoCloudUser;
}

/**
 * Handler invoked when an authenticated user does not satisfy the required group restrictions while running a Pages Router `getServerSideProps` protected by {@link protectPage | protectPage()}.
 *
 * @category Types (Handler)
 *
 * @typeParam P Props returned from `getServerSideProps`.
 * @typeParam Q Query parameters parsed from the URL.
 * @param context The Next.js `getServerSideProps` context.
 * @returns A `getServerSideProps` result.
 */
export type ProtectPagePageOnGroupAccessDeniedType<
  P,
  Q extends ParsedUrlQuery = ParsedUrlQuery,
> = (
  context: ProtectPageGetServerSidePropsContext<Q>
) => Promise<GetServerSidePropsResult<P>> | GetServerSidePropsResult<P>;

/**
 * Return type produced by the {@link protectPage | protectPage()} wrapper for the Pages Router.
 *
 * Represents a `getServerSideProps` compatible function that resolves authentication before executing page logic and injects the authenticated `user` into the returned props.
 *
 * @category Types (Handler)
 *
 * @typeParam P Props returned from `getServerSideProps`.
 * @typeParam Q Query parameters parsed from the URL.
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
 * Props injected into an App Router Server Component wrapped by {@link protectPage | protectPage()}.
 *
 * Includes the authenticated `user` and optional route/search parameters provided by Next.js.
 *
 * @category Types (Handler)
 */
export interface ProtectedAppServerComponentProps {
  /**
   * The authenticated user resolved from the current session.
   */
  user: MonoCloudUser;

  /**
   * Dynamic route parameters provided by the App Router.
   */
  params?: Record<string, string | string[]>;

  /**
   * URL search parameters provided by the App Router.
   */
  searchParams?: Record<string, string | string[] | undefined>;
}

/**
 * App Router Server Component wrapped by {@link protectPage | protectPage()}.
 *
 * This component is only executed after authentication (and optional authorization) succeeds. The authenticated `user` is injected into the component props automatically.
 *
 * @param props - The component props, including the authenticated user and any additional page props.
 *
 * @category Types (Handler)
 */
export type ProtectedAppServerComponent = (
  props: ProtectedAppServerComponentProps
) => Promise<JSX.Element> | JSX.Element;

/**
 * Handler invoked when a request is denied because the user is not authenticated in an App Router API route.
 *
 * @category Types (Handler)
 *
 * @param req The incoming Next.js request.
 * @param ctx The App Router context containing dynamic route parameters.
 *
 * @returns Returns a `Response` (or `NextResponse`) or a Promise resolving to one.
 */
export type AppRouterApiOnAccessDeniedHandler = (
  req: NextRequest,
  ctx: AppRouterContext
) => Promise<Response> | Response;

/**
 * Handler invoked when a request is denied because the authenticated user does not satisfy the required group restrictions in an App Router API route.
 *
 * @category Types (Handler)
 *
 * @param req The incoming Next.js request.
 * @param ctx The App Router context containing dynamic route parameters.
 * @param user The authenticated user associated with the request.
 *
 * @returns Returns a `Response` (or `NextResponse`) or a Promise resolving to one.
 */
export type AppRouterApiOnGroupAccessDeniedHandler = (
  req: NextRequest,
  ctx: AppRouterContext,
  user: MonoCloudUser
) => Promise<Response> | Response;

/**
 * Options for configuring {@link protectApi | protectApi()} in the App Router.
 *
 * @category Types
 */
export interface ProtectApiAppOptions extends GroupOptions {
  /**
   * Alternate API route handler invoked when the request is not authenticated.
   */
  onAccessDenied?: AppRouterApiOnAccessDeniedHandler;

  /**
   * Alternate API route handler invoked when the request is authenticated but the user does not satisfy the required group restrictions.
   */
  onGroupAccessDenied?: AppRouterApiOnGroupAccessDeniedHandler;
}

/**
 * Handler function invoked when a request is not authenticated in a Pages Router API route.
 *
 * @category Types (Handler)
 *
 * @param req The incoming Next.js API request.
 * @param res The Next.js API response object used to send the custom response.
 * @returns The handler should send a response using `res` (for example, `res.status(...).json(...)`). Returning a value does not automatically end the request.
 */
export type PageRouterApiOnAccessDeniedHandler = (
  req: NextApiRequest,
  res: NextApiResponse<any>
) => Promise<unknown> | unknown;

/**
 * Handler function invoked when an authenticated user is denied access in a Pages Router API route due to group authorization restrictions.
 *
 * @category Types (Handler)
 *
 * @param req The incoming Next.js API request.
 * @param res The Next.js API response object used to send the custom response.
 * @returns The handler should send a response using `res` (for example, `res.status(...).json(...)`). Returning a value does not automatically end the request.
 *
 * @returns
 */
export type PageRouterApiOnGroupAccessDeniedHandler = (
  req: NextApiRequest,
  res: NextApiResponse<any>,
  user: MonoCloudUser
) => Promise<unknown> | unknown;

/**
 * Options for configuring {@link protectApi | protectApi()} in the Pages Router.
 *
 * @category Types
 */
export interface ProtectApiPageOptions extends GroupOptions {
  /**
   * Alternate API handler invoked when the request is unauthenticated.
   */
  onAccessDenied?: PageRouterApiOnAccessDeniedHandler;

  /**
   * Alternate API handler invoked when the user is authenticated but does not satisfy the configured group authorization rules.
   */
  onGroupAccessDenied?: PageRouterApiOnGroupAccessDeniedHandler;
}

/**
 * Options for configuring {@link protect | protect()}.
 *
 * @category Types
 */
export interface ProtectOptions extends GroupOptions {
  /**
   * The URL to return to after successful authentication.
   *
   * If not provided, the current request URL is used.
   */
  returnUrl?: string;

  /**
   * Additional authorization parameters to include when redirecting the user to the sign-in flow.
   */
  authParams?: ExtraAuthParams;
}

/**
 * Configuration options for evaluating user group membership.
 *
 * @category Types
 */
export interface IsUserInGroupOptions {
  /**
   * The name of the claim in the user profile that contains group information. This value is read from the authenticated user's session.
   *
   * @defaultValue 'groups'
   */
  groupsClaim?: string;

  /**
   * Determines how multiple groups are evaluated. When `true`, the user must belong to **all** specified groups for authorization to succeed. Otherwise, membership in any one group is sufficient.
   *
   * @defaultValue false
   */
  matchAll?: boolean;
}

/**
 * Configuration options that require the user to belong to specific groups.
 *
 * @category Types
 */
export interface GroupOptions extends IsUserInGroupOptions {
  /**
   * A list of group IDs or group names the authenticated user must belong to.
   *
   * Group membership is evaluated using the configured `groupsClaim` from the user session.
   */
  groups?: string[];
}

/**
 * Options for {@link redirectToSignIn | redirectToSignIn()}.
 *
 * @category Types
 */
export interface RedirectToSignInOptions extends ExtraAuthParams {
  /**
   * URL to return the user to after successful authentication. Must be a relative application URL.
   */
  returnUrl?: string;
}

/**
 * Options for {@link redirectToSignOut | redirectToSignOut()}.
 *
 * @category Types
 */
export interface RedirectToSignOutOptions {
  /**
   * URL where the authorization server should redirect the user after a successful sign-out.
   *
   * This value must match one of the registered Sign-out Redirect URLs configured for the application.
   */
  postLogoutRedirectUri?: string;

  /**
   * When enabled, the user is also signed out from MonoCloud (Single Sign-Out).
   */
  federated?: boolean;
}
