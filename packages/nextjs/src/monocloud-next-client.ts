/* eslint-disable import/extensions */
/* eslint-disable @typescript-eslint/no-non-null-assertion */
import {
  NextFetchEvent,
  NextRequest,
  NextResponse,
  NextMiddleware,
  NextProxy,
} from 'next/server.js';
import type {
  NextApiHandler,
  NextApiRequest,
  NextApiResponse,
} from 'next/types';
import {
  ensureLeadingSlash,
  isAbsoluteUrl,
} from '@monocloud/auth-node-core/internal';
import { isUserInGroup } from '@monocloud/auth-node-core/utils';
import type {
  GetTokensOptions,
  IMonoCloudCookieRequest,
  IMonoCloudCookieResponse,
  MonoCloudOptions,
  MonoCloudRequest,
  MonoCloudResponse,
  MonoCloudTokens,
  MonoCloudSession,
  OnError,
} from '@monocloud/auth-node-core';
import {
  MonoCloudCoreClient,
  MonoCloudValidationError,
  MonoCloudOidcClient,
} from '@monocloud/auth-node-core';
import {
  AppRouterApiHandlerFn,
  AppRouterContext,
  AppRouterPageHandler,
  IsUserInGroupOptions,
  MonoCloudAuthHandler,
  MonoCloudAuthOptions,
  MonoCloudMiddlewareOptions,
  NextMiddlewareResult,
  ProtectApiAppOptions,
  ProtectApiPageOptions,
  ProtectAppPageOptions,
  ProtectedAppServerComponent,
  ProtectOptions,
  ProtectPagePageOptions,
  ProtectPagePageReturnType,
  RedirectToSignInOptions,
  RedirectToSignOutOptions,
} from './types';
import {
  getMonoCloudCookieReqRes,
  getNextRequest,
  getNextResponse,
  isAppRouter,
  isMonoCloudRequest,
  isMonoCloudResponse,
  mergeResponse,
} from './utils';
import MonoCloudCookieRequest from './requests/monocloud-cookie-request';
import MonoCloudCookieResponse from './responses/monocloud-cookie-response';
import MonoCloudAppRouterRequest from './requests/monocloud-app-router-request';
import MonoCloudAppRouterResponse from './responses/monocloud-app-router-response';
import { JSX } from 'react';
import { ParsedUrlQuery } from 'node:querystring';
import { IncomingMessage, ServerResponse } from 'node:http';
import MonoCloudPageRouterRequest from './requests/monocloud-page-router-request';
import MonoCloudPageRouterResponse from './responses/monocloud-page-router-response';

/**
 * The MonoCloud Next.js Client.
 *
 * @example Using Environment Variables (Recommended)
 *
 * 1. Add following variables to your `.env`.
 *
 * ```bash
 * MONOCLOUD_AUTH_TENANT_DOMAIN=<tenant-domain>
 * MONOCLOUD_AUTH_CLIENT_ID=<client-id>
 * MONOCLOUD_AUTH_CLIENT_SECRET=<client-secret>
 * MONOCLOUD_AUTH_SCOPES=openid profile email # Default
 * MONOCLOUD_AUTH_APP_URL=http://localhost:3000
 * MONOCLOUD_AUTH_COOKIE_SECRET=<cookie-secret>
 * ```
 *
 * 2. Instantiate the client in a shared file (e.g., lib/monocloud.ts)
 *
 * ```typescript
 * import { MonoCloudNextClient } from '@monocloud/auth-nextjs';
 *
 * export const monoCloud = new MonoCloudNextClient();
 * ```
 *
 * 3. Add MonoCloud middleware/proxy
 *
 * ```typescript
 * import { monoCloud } from "@/lib/monocloud";
 *
 * export default monoCloud.authMiddleware();
 *
 * export const config = {
 *   matcher: [
 *     "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)",
 *   ],
 * };
 * ```
 *
 * @example Using Constructor Options
 *
 * ⚠️ Security Note: Never commit your credentials to version control. Load them from environment variables.
 *
 * 1. Instantiate the client in a shared file (e.g., lib/monocloud.ts)
 *
 * ```typescript
 * import { MonoCloudNextClient } from '@monocloud/auth-nextjs';
 *
 * export const monoCloud = new MonoCloudNextClient({
 *  tenantDomain: '<tenant-domain>',
 *  clientId: '<client-id>',
 *  clientSecret: '<client-secret>',
 *  scopes: 'openid profile email', // Default
 *  appUrl: 'http://localhost:3000',
 *  cookieSecret: '<cookie-secret>'
 * });
 * ```
 * 2. Add MonoCloud middleware/proxy
 *
 * ```typescript
 * import { monoCloud } from "@/lib/monocloud";
 *
 * export default monoCloud.authMiddleware();
 *
 * export const config = {
 *   matcher: [
 *     "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)",
 *   ],
 * };
 * ```
 *
 * <details>
 * <summary>All Environment Variables</summary>
 *  <h4>Core Configuration (Required)</h4>
 *
 *  <ul>
 *    <li><strong>MONOCLOUD_AUTH_CLIENT_ID : </strong>Unique identifier for your application/client.</li>
 *    <li><strong>MONOCLOUD_AUTH_CLIENT_SECRET : </strong>Application/client secret.</li>
 *    <li><strong>MONOCLOUD_AUTH_TENANT_DOMAIN : </strong>The domain of your MonoCloud tenant (e.g., https://your-tenant.us.monocloud.com).</li>
 *    <li><strong>MONOCLOUD_AUTH_APP_URL : </strong>The base URL where your application is hosted.</li>
 *    <li><strong>MONOCLOUD_AUTH_COOKIE_SECRET : </strong>A long, random string used to encrypt and sign session cookies.</li>
 *  </ul>
 *
 *  <h4>Authentication &amp; Security</h4>
 *
 *  <ul>
 *    <li><strong>MONOCLOUD_AUTH_SCOPES : </strong>A space-separated list of OIDC scopes to request (e.g., openid profile email).</li>
 *    <li><strong>MONOCLOUD_AUTH_RESOURCE : </strong>The default resource/audience identifier for access tokens.</li>
 *    <li><strong>MONOCLOUD_AUTH_USE_PAR : </strong>Enables Pushed Authorization Requests.</li>
 *    <li><strong>MONOCLOUD_AUTH_CLOCK_SKEW : </strong>The allowed clock drift in seconds when validating token timestamps.</li>
 *    <li><strong>MONOCLOUD_AUTH_FEDERATED_SIGNOUT : </strong>If true, signs the user out of MonoCloud (SSO sign-out) when they sign out of the app.</li>
 *    <li><strong>MONOCLOUD_AUTH_RESPONSE_TIMEOUT : </strong>The maximum time in milliseconds to wait for a response.</li>
 *    <li><strong>MONOCLOUD_AUTH_ALLOW_QUERY_PARAM_OVERRIDES : </strong>Allows dynamic overrides of auth parameters via URL query strings.</li>
 *    <li><strong>MONOCLOUD_AUTH_POST_LOGOUT_REDIRECT_URI : </strong>The URL users are sent to after a successful logout.</li>
 *    <li><strong>MONOCLOUD_AUTH_USER_INFO : </strong>Determines if user profile data from the UserInfo endpoint should be fetched after authorization code exchange.</li>
 *    <li><strong>MONOCLOUD_AUTH_REFETCH_USER_INFO : </strong>If true, re-fetches user information on every request to userinfo endpoint or when calling getTokens()</li>
 *    <li><strong>MONOCLOUD_AUTH_ID_TOKEN_SIGNING_ALG : </strong>The expected algorithm for signing ID tokens (e.g., RS256).</li>
 *    <li><strong>MONOCLOUD_AUTH_FILTERED_ID_TOKEN_CLAIMS : </strong>A space-separated list of claims to exclude from the session object.</li>
 *  </ul>
 *
 *  <h4>Routes</h4>
 *
 *   <aside>
 *     <strong>⚠️ Important: Modifying Default Routes</strong>
 *     <p>If you choose to customize any of the default route paths, you must adhere to the following requirements:</p>
 *     <ul>
 *       <li>
 *         <strong>Client-Side Synchronization:</strong> You must also define a corresponding <code>NEXT_PUBLIC_</code> version of the environment variable (e.g., <code>NEXT_PUBLIC_MONOCLOUD_AUTH_CALLBACK_URL</code>). This ensures that client-side components like <code>&lt;SignIn /&gt;</code>, <code>&lt;SignOut /&gt;</code>, and the <code>useAuth()</code> hook can correctly identify your custom endpoints.
 *       </li>
 *       <li>
 *         <strong>Dashboard Configuration:</strong> Changing these URLs will alter the endpoints required by MonoCloud. You must update the <strong>Application URLs</strong> section in your MonoCloud Dashboard to match these new paths.
 *       </li>
 *     </ul>
 *     <p><em>Example:</em></p>
 *     <code>
 *       MONOCLOUD_AUTH_CALLBACK_URL=/api/custom_callback<br />
 *       NEXT_PUBLIC_MONOCLOUD_AUTH_CALLBACK_URL=/api/custom_callback
 *     </code>
 *     <p>In this case, the Redirect URI in your dashboard should be set to: <code>http://localhost:3000/api/custom_callback</code> (assuming local development).</p>
 *   </aside>
 *
 *  <ul>
 *    <li><strong>MONOCLOUD_AUTH_CALLBACK_URL : </strong>The application path where MonoCloud sends the user after authentication.</li>
 *    <li><strong>MONOCLOUD_AUTH_SIGNIN_URL : </strong>The internal route path to trigger the sign-in.</li>
 *    <li><strong>MONOCLOUD_AUTH_SIGNOUT_URL : </strong>The internal route path to trigger the sign-out.</li>
 *    <li><strong>MONOCLOUD_AUTH_USER_INFO_URL : </strong>The route that exposes the current user's profile from userinfo endpoint.</li>
 *  </ul>
 *
 *  <h4>Session Cookie Settings</h4>
 *
 *  <ul>
 *    <li><strong>MONOCLOUD_AUTH_SESSION_COOKIE_NAME : </strong>The name of the cookie used to store the user session.</li>
 *    <li><strong>MONOCLOUD_AUTH_SESSION_COOKIE_PATH : </strong>The scope path for the session cookie.</li>
 *    <li><strong>MONOCLOUD_AUTH_SESSION_COOKIE_DOMAIN : </strong>The domain scope for the session cookie.</li>
 *    <li><strong>MONOCLOUD_AUTH_SESSION_COOKIE_HTTP_ONLY : </strong>Prevents client-side scripts from accessing the session cookie.</li>
 *    <li><strong>MONOCLOUD_AUTH_SESSION_COOKIE_SECURE : </strong>Ensures the session cookie is only sent over HTTPS.</li>
 *    <li><strong>MONOCLOUD_AUTH_SESSION_COOKIE_SAME_SITE : </strong>The SameSite policy for the session cookie (Lax, Strict, or None).</li>
 *    <li><strong>MONOCLOUD_AUTH_SESSION_COOKIE_PERSISTENT : </strong>If true, the session survives browser restarts.</li>
 *    <li><strong>MONOCLOUD_AUTH_SESSION_SLIDING : </strong>If true, the session will be a sliding session instead of absolute.</li>
 *    <li><strong>MONOCLOUD_AUTH_SESSION_DURATION : </strong>The session lifetime in seconds.</li>
 *    <li><strong>MONOCLOUD_AUTH_SESSION_MAX_DURATION : </strong>The absolute maximum lifetime of a session in seconds.</li>
 *  </ul>
 *
 *  <h4>State Cookie Settings</h4>
 *
 *  <ul>
 *    <li><strong>MONOCLOUD_AUTH_STATE_COOKIE_NAME : </strong>The name of the cookie used to store OpenID state/nonce.</li>
 *    <li><strong>MONOCLOUD_AUTH_STATE_COOKIE_PATH : </strong>The scope path for the state cookie.</li>
 *    <li><strong>MONOCLOUD_AUTH_STATE_COOKIE_DOMAIN : </strong>The domain scope for the state cookie.</li>
 *    <li><strong>MONOCLOUD_AUTH_STATE_COOKIE_SECURE : </strong>Ensures the state cookie is only sent over HTTPS</li>
 *    <li><strong>MONOCLOUD_AUTH_STATE_COOKIE_SAME_SITE : </strong>The SameSite policy for the state cookie.</li>
 *    <li><strong>MONOCLOUD_AUTH_STATE_COOKIE_PERSISTENT : </strong>Whether the state cookie is persistent.</li>
 *  </ul>
 *
 *  <h4>Caching</h4>
 *
 *  <ul>
 *    <li><strong>MONOCLOUD_AUTH_JWKS_CACHE_DURATION : </strong>Duration in seconds to cache the JSON Web Key Set.</li>
 *    <li><strong>MONOCLOUD_AUTH_METADATA_CACHE_DURATION : </strong>Duration in seconds to cache the OpenID discovery metadata.</li>
 *  </ul>
 * </details>
 *
 *
 */
export class MonoCloudNextClient {
  /**
   * The underlying MonoCloud Node Core Client instance.
   *
   * This property exposes the framework-agnostic node core client used by the Next.js client.
   * You can access this to use low-level methods not directly exposed by the Next.js wrapper.
   *
   * @example Manually destroy session
   * ```typescript
   * // req and res must implement IMonoCloudCookieRequest/Response
   * await monoCloud.coreClient.destroySession(request, response);
   * ```
   */
  public readonly coreClient: MonoCloudCoreClient;

  /**
   * The underlying OIDC client instance used for low-level OpenID Connect operations.
   *
   * @example
   * // Manually revoke an access token
   * await client.oidcClient.revokeToken(accessToken, 'access_token');
   */
  public get oidcClient(): MonoCloudOidcClient {
    return this.coreClient.oidcClient;
  }

  /**
   * @param options Configuration options including domain, client ID, and secret.
   */
  constructor(options?: MonoCloudOptions) {
    const opt = {
      ...(options ?? {}),
      userAgent: options?.userAgent ?? `${SDK_NAME}@${SDK_VERSION}`,
      debugger: options?.debugger ?? SDK_DEBUGGER_NAME,
    };

    this.registerPublicEnvVariables();
    this.coreClient = new MonoCloudCoreClient(opt);
  }

  /**
   * Creates a **Next.js API route handler** (for both Pages Router and App Router)
   * that processes all MonoCloud authentication endpoints
   * (`/signin`, `/callback`, `/userinfo`, `/signout`).
   *
   * @param options Authentication configuration routes.
   *
   * **Note:** If you are already using `authMiddleware()`, you typically do **not**
   * need this API route handler. This function is intended for applications where
   * middleware cannot be used—such as statically generated (SSG) deployments that still
   * require server-side authentication flows.
   *
   * @example App Router
   *
   * ```typescript
   * // app/api/auth/[...monocloud]/route.ts
   *
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export const GET = monoCloud.monoCloudAuth();
   *```
   *
   * @example App Router with Response
   *
   * ```typescript
   * import { monoCloud } from "@/lib/monocloud";
   * import { NextRequest, NextResponse } from "next/server";
   *
   * export const GET = (req: NextRequest) => {
   *   const authHandler = monoCloud.monoCloudAuth();
   *
   *   const res = new NextResponse();
   *
   *   res.cookies.set("last_auth_requested", `${Date.now()}`);
   *
   *   return authHandler(req, res);
   * };
   * ```
   *
   * @example Pages Router
   *
   * ```typescript
   * // pages/api/auth/[...monocloud].ts
   *
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export default monoCloud.monoCloudAuth();
   *```
   *
   * @example Page Router with Response
   *
   * ```typescript
   * import { monoCloud } from "@/lib/monocloud";
   * import { NextApiRequest, NextApiResponse } from "next";
   *
   * export default function handler(req: NextApiRequest, res: NextApiResponse) {
   *   const authHandler = monoCloud.monoCloudAuth();
   *
   *   res.setHeader("last_auth_requested", `${Date.now()}`);
   *
   *   return authHandler(req, res);
   * }
   * ```
   *
   */
  public monoCloudAuth(options?: MonoCloudAuthOptions): MonoCloudAuthHandler {
    return (req, resOrCtx) => {
      const { routes, appUrl } = this.getOptions();

      let { url = '' } = req;

      if (!isAbsoluteUrl(url)) {
        url = new URL(url, appUrl).toString();
      }

      const route = new URL(url);

      let onError;
      if (typeof options?.onError === 'function') {
        onError = (
          error: Error
        ): void | NextResponse | Promise<void | NextResponse<unknown>> =>
          options.onError!(req as any, resOrCtx as any, error);
      }

      let request: MonoCloudRequest;
      let response: MonoCloudResponse;

      if (isAppRouter(req)) {
        request = new MonoCloudAppRouterRequest(getNextRequest(req as Request));
        response = new MonoCloudAppRouterResponse(
          getNextResponse(resOrCtx as Response)
        );
      } else {
        request = new MonoCloudPageRouterRequest(req as NextApiRequest);
        response = new MonoCloudPageRouterResponse(resOrCtx as NextApiResponse);
      }

      return this.handleAuthRoutes(
        request,
        response,
        route.pathname,
        routes,
        onError
      );
    };
  }

  /**
   *
   * ## App Router
   *
   * Restricts access to server-rendered pages in your Next.js App Router application, ensures that only authenticated (and optionally authorized) users can view the page.
   *
   * **Note⚠️ - When using groups to protect a page, 'Access Denied' is rendered by default when the user does not belong to the groups.
   *  To display a custom component, pass the `onGroupAccessDenied` parameter.**
   *
   * @param component The App Router server component that protectPage wraps and secures
   * @param options App Router `protectPage()` configuration options
   *
   * @returns A protected page handler.
   *
   * @example
   *
   * ```typescript
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export default monoCloud.protectPage(async function Home({ user }) {
   *  return <>Hi {user.email}. You accessed a protected page.</>;
   * });
   * ```
   *
   * @example App Router with options
   *
   * ```typescript
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export default monoCloud.protectPage(
   *   async function Home({ user }) {
   *     return <>Hi {user.email}. You accessed a protected page.</>;
   *   },
   *   {
   *     returnUrl: "/dashboard",
   *     groups: ["admin"],
   *   }
   * );
   * ```
   */
  protectPage(
    component: ProtectedAppServerComponent,
    options?: ProtectAppPageOptions
  ): AppRouterPageHandler;

  /**
   * ## Pages Router
   *
   * Restricts access to server-rendered pages in your Next.js Pages Router application, ensures that only authenticated (and optionally authorized) users can view the page.
   *
   * **Note⚠️ - When using groups to protect a page, the page will be rendered even if the user does not belong to the groups.
   * You should check the props for `groupAccessDenied` boolean value to determine whether the user is
   * allowed to access the page. Alternatively, you can pass `onGroupAccessDenied` parameter to return custom props.**
   *
   * @param options Pages Router `protectPage()` configuration options
   *
   * @typeParam P - The type of parameters accepted by the page handler.
   * @typeParam Q - The type of query parameters parsed from the URL.
   *
   * @returns A protected page handler.
   *
   * @example
   *
   * ```typescript
   * import { monoCloud } from "@/lib/monocloud";
   * import { InferGetServerSidePropsType } from "next";
   *
   * export default function Home({
   *   user,
   * }: InferGetServerSidePropsType<typeof getServerSideProps>) {
   *   return <>Hi {user.email}. You accessed a protected page.</>;
   * }
   *
   * export const getServerSideProps = monoCloud.protectPage();
   * ```
   *
   * @example Pages Router with options
   *
   * ```typescript
   * import { monoCloud } from "@/lib/monocloud";
   * import { GetServerSidePropsContext, InferGetServerSidePropsType } from "next";
   *
   * export default function Home({
   *   user,
   *   url,
   * }: InferGetServerSidePropsType<typeof getServerSideProps>) {
   *   console.log(url);
   *   return <div>Hi {user?.email}. You accessed a protected page.</div>;
   * }
   *
   * export const getServerSideProps = monoCloud.protectPage({
   *   returnUrl: "/dashboard",
   *   groups: ["admin"],
   *   getServerSideProps: async (context: GetServerSidePropsContext) => ({
   *     props: { url: context.resolvedUrl },
   *   }),
   * });
   * ```
   */
  protectPage<
    P extends Record<string, any> = Record<string, any>,
    Q extends ParsedUrlQuery = ParsedUrlQuery,
  >(options?: ProtectPagePageOptions<P, Q>): ProtectPagePageReturnType<P, Q>;

  public protectPage(...args: unknown[]): any {
    if (typeof args[0] === 'function') {
      return this.protectAppPage(
        args[0] as AppRouterPageHandler,
        args[1] as ProtectAppPageOptions
      ) as any;
    }

    return this.protectPagePage(
      args[0] as ProtectPagePageOptions
    ) as ProtectPagePageReturnType<any, any>;
  }

  private protectAppPage(
    component: ProtectedAppServerComponent,
    options?: ProtectAppPageOptions
  ): AppRouterPageHandler {
    return async params => {
      const session = await this.getSession();

      if (!session) {
        if (options?.onAccessDenied) {
          return options.onAccessDenied({ ...params });
        }

        const { routes, appUrl } = this.getOptions();

        // @ts-expect-error Cannot find module 'next/headers'
        const { headers } = await import('next/headers');

        const path = (await headers()).get('x-monocloud-path');

        const signInRoute = new URL(
          `${appUrl}${ensureLeadingSlash(routes!.signIn)}`
        );

        signInRoute.searchParams.set(
          'return_url',
          options?.returnUrl ?? path ?? '/'
        );

        if (options?.authParams?.scopes) {
          signInRoute.searchParams.set('scope', options.authParams.scopes);
        }
        if (options?.authParams?.resource) {
          signInRoute.searchParams.set('resource', options.authParams.resource);
        }

        if (options?.authParams?.acrValues) {
          signInRoute.searchParams.set(
            'acr_values',
            options.authParams.acrValues.join(' ')
          );
        }

        if (options?.authParams?.display) {
          signInRoute.searchParams.set('display', options.authParams.display);
        }

        if (options?.authParams?.prompt) {
          signInRoute.searchParams.set('prompt', options.authParams.prompt);
        }

        if (options?.authParams?.authenticatorHint) {
          signInRoute.searchParams.set(
            'authenticator_hint',
            options.authParams.authenticatorHint
          );
        }

        if (options?.authParams?.uiLocales) {
          signInRoute.searchParams.set(
            'ui_locales',
            options.authParams.uiLocales
          );
        }

        if (options?.authParams?.maxAge) {
          signInRoute.searchParams.set(
            'max_age',
            options.authParams.maxAge.toString()
          );
        }

        if (options?.authParams?.loginHint) {
          signInRoute.searchParams.set(
            'login_hint',
            options.authParams.loginHint
          );
        }

        // @ts-expect-error Cannot find module 'next/navigation'
        const { redirect } = await import('next/navigation');

        return redirect(signInRoute.toString());
      }

      if (
        options?.groups &&
        !isUserInGroup(
          session.user,
          options.groups,
          options.groupsClaim ?? process.env.MONOCLOUD_AUTH_GROUPS_CLAIM,
          options.matchAll
        )
      ) {
        if (options.onGroupAccessDenied) {
          return options.onGroupAccessDenied({
            ...params,
            user: session.user,
          });
        }

        return 'Access Denied' as unknown as JSX.Element;
      }

      return component({ ...params, user: session.user });
    };
  }

  private protectPagePage<
    P extends Record<string, any> = Record<string, any>,
    Q extends ParsedUrlQuery = ParsedUrlQuery,
  >(options?: ProtectPagePageOptions<P, Q>): ProtectPagePageReturnType<P, Q> {
    return async context => {
      const session = await this.getSession(
        context.req as any,
        context.res as any
      );

      if (!session) {
        if (options?.onAccessDenied) {
          const customProps: any = await options.onAccessDenied({
            ...context,
          });

          const props = {
            ...(customProps ?? {}),
            props: { ...(customProps?.props ?? {}) },
          };

          return props;
        }

        const { routes, appUrl } = this.getOptions();

        const signInRoute = new URL(
          `${appUrl}${ensureLeadingSlash(routes!.signIn)}`
        );

        signInRoute.searchParams.set(
          'return_url',
          options?.returnUrl ?? context.resolvedUrl
        );

        if (options?.authParams?.scopes) {
          signInRoute.searchParams.set('scope', options.authParams.scopes);
        }
        if (options?.authParams?.resource) {
          signInRoute.searchParams.set('resource', options.authParams.resource);
        }

        if (options?.authParams?.acrValues) {
          signInRoute.searchParams.set(
            'acr_values',
            options.authParams.acrValues.join(' ')
          );
        }

        if (options?.authParams?.display) {
          signInRoute.searchParams.set('display', options.authParams.display);
        }

        if (options?.authParams?.prompt) {
          signInRoute.searchParams.set('prompt', options.authParams.prompt);
        }

        if (options?.authParams?.authenticatorHint) {
          signInRoute.searchParams.set(
            'authenticator_hint',
            options.authParams.authenticatorHint
          );
        }

        if (options?.authParams?.uiLocales) {
          signInRoute.searchParams.set(
            'ui_locales',
            options.authParams.uiLocales
          );
        }

        if (options?.authParams?.maxAge) {
          signInRoute.searchParams.set(
            'max_age',
            options.authParams.maxAge.toString()
          );
        }

        if (options?.authParams?.loginHint) {
          signInRoute.searchParams.set(
            'login_hint',
            options.authParams.loginHint
          );
        }

        return {
          redirect: {
            destination: signInRoute.toString(),
            permanent: false,
          },
        };
      }

      if (
        options?.groups &&
        !isUserInGroup(
          session.user,
          options.groups,
          options.groupsClaim ?? process.env.MONOCLOUD_AUTH_GROUPS_CLAIM,
          options.matchAll
        )
      ) {
        const customProps: any = (await options.onGroupAccessDenied?.({
          ...context,
          user: session.user,
        })) ?? { props: { groupAccessDenied: true } };

        const props = {
          ...customProps,
          props: { ...(customProps.props ?? {}) },
        };

        return props;
      }

      const customProps: any = options?.getServerSideProps
        ? await options.getServerSideProps(context)
        : {};

      const promiseProp = customProps.props;

      if (promiseProp instanceof Promise) {
        return {
          ...customProps,
          props: promiseProp.then((props: any) => ({
            user: session.user,
            ...props,
          })),
        };
      }

      return {
        ...customProps,
        props: { user: session.user, ...customProps.props },
      };
    };
  }

  /**
   * ## App Router
   *
   * Secures Next.js App Router APIs. It ensures only authenticated (and optionally authorized) requests can access the route.
   *
   * @param handler The api route handler function to protect
   * @param options App Router `protectApi()` configuration options
   *
   * @returns Protected route handler
   *
   * @example
   *
   * ```typescript
   * import { monoCloud } from "@/lib/monocloud";
   * import { NextResponse } from "next/server";
   *
   * export const GET = monoCloud.protectApi(async () => {
   *   return NextResponse.json({
   *     message: "You accessed a protected endpoint",
   *   });
   * });
   * ```
   */
  protectApi(
    handler: AppRouterApiHandlerFn,
    options?: ProtectApiAppOptions
  ): AppRouterApiHandlerFn;

  /**
   * ## Pages Router
   *
   * Secures Next.js Pages Router APIs. It ensures only authenticated (and optionally authorized) requests can access the route.
   *
   * @param handler The api route handler function to protect
   * @param options Pages Router `protectApi()` configuration options
   *
   * @returns Protected route handler
   *
   * @example
   *
   * ```typescript
   * import { monoCloud } from "@/lib/monocloud";
   * import type { NextApiRequest, NextApiResponse } from "next";
   *
   * export default monoCloud.protectApi(
   *   async (req: NextApiRequest, res: NextApiResponse) => {
   *     return res.json({
   *       message: "You accessed a protected endpoint",
   *     });
   *   }
   * );
   * ```
   */
  protectApi(
    handler: NextApiHandler,
    options?: ProtectApiPageOptions
  ): NextApiHandler;

  public protectApi(
    handler: AppRouterApiHandlerFn | NextApiHandler,
    options?: ProtectApiAppOptions | ProtectApiPageOptions
  ): AppRouterApiHandlerFn | NextApiHandler {
    return (
      req: NextRequest | NextApiRequest,
      resOrCtx: AppRouterContext | NextApiResponse
    ) => {
      if (isAppRouter(req)) {
        return this.protectAppApi(
          req as NextRequest,
          resOrCtx as AppRouterContext,
          handler as AppRouterApiHandlerFn,
          options as ProtectApiAppOptions
        );
      }
      return this.protectPageApi(
        req as NextApiRequest,
        resOrCtx as NextApiResponse,
        handler as NextApiHandler,
        options as ProtectApiPageOptions
      );
    };
  }

  private async protectAppApi(
    req: NextRequest,
    ctx: AppRouterContext,
    handler: AppRouterApiHandlerFn,
    options?: ProtectApiAppOptions
  ): Promise<NextResponse> {
    const res = new NextResponse();

    const session = await this.getSession(req, res);

    if (!session) {
      if (options?.onAccessDenied) {
        const result = await options.onAccessDenied(req, ctx);

        if (result instanceof NextResponse) {
          return mergeResponse([res, result]);
        }

        return mergeResponse([res, new NextResponse(result.body, result)]);
      }

      return mergeResponse([
        res,
        NextResponse.json({ message: 'unauthorized' }, { status: 401 }),
      ]);
    }

    if (
      options?.groups &&
      !isUserInGroup(
        session.user,
        options.groups,
        options.groupsClaim ?? process.env.MONOCLOUD_AUTH_GROUPS_CLAIM,
        options.matchAll
      )
    ) {
      if (options.onGroupAccessDenied) {
        const result = await options.onGroupAccessDenied(
          req,
          ctx,
          session.user
        );

        if (result instanceof NextResponse) {
          return mergeResponse([res, result]);
        }

        return mergeResponse([res, new NextResponse(result.body, result)]);
      }

      return mergeResponse([
        res,
        NextResponse.json({ message: 'forbidden' }, { status: 403 }),
      ]);
    }

    const resp = await handler(req, ctx);

    if (resp instanceof NextResponse) {
      return mergeResponse([res, resp]);
    }

    return mergeResponse([res, new NextResponse(resp.body, resp)]);
  }

  private async protectPageApi(
    req: NextApiRequest,
    res: NextApiResponse,
    handler: NextApiHandler,
    options?: ProtectApiPageOptions
  ): Promise<unknown> {
    const session = await this.getSession(req, res);

    if (!session) {
      if (options?.onAccessDenied) {
        return options.onAccessDenied(req, res);
      }

      return res.status(401).json({
        message: 'unauthorized',
      });
    }

    if (
      options?.groups &&
      !isUserInGroup(
        session.user,
        options.groups,
        options.groupsClaim ?? process.env.MONOCLOUD_AUTH_GROUPS_CLAIM,
        options.matchAll
      )
    ) {
      if (options.onGroupAccessDenied) {
        return options.onGroupAccessDenied(req, res, session.user);
      }

      return res.status(403).json({
        message: 'forbidden',
      });
    }

    return handler(req, res);
  }

  /**
   * A middleware/proxy that protects pages and APIs and handles authentication.
   *
   * @param options Middleware configuration options
   *
   * @returns A Next.js middleware/proxy function.
   *
   * @example Protect All Routes
   *
   * - Default behavior: protect all routes matched by `config.matcher`
   *
   * ```typescript
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export default monoCloud.authMiddleware();
   *
   * export const config = {
   *   matcher: [
   *     "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)",
   *   ],
   * };
   * ```
   *
   * @example Protect Selected Routes
   *
   * - Protect only the routes listed in `protectedRoutes`
   *
   * ```typescript
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export default monoCloud.authMiddleware({
   *   protectedRoutes: ["/api/admin", "^/api/protected(/.*)?$"],
   * });
   *
   * export const config = {
   *   matcher: [
   *     "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)",
   *   ],
   * };
   *```
   *
   * @example Make All Routes Public
   *
   * - Do not protect any routes; MonoCloud still handles auth endpoints
   *
   * ```typescript
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export default monoCloud.authMiddleware({
   *   protectedRoutes: [],
   * });
   *
   * export const config = {
   *   matcher: [
   *     "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)",
   *   ],
   * };
   * ```
   *
   * @example Protect Routes Dynamically
   *
   * - Decide at runtime which routes to protect
   *
   * ```typescript
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export default monoCloud.authMiddleware({
   *   protectedRoutes: (req) => {
   *     return req.nextUrl.pathname.startsWith("/api/protected");
   *   },
   * });
   *
   * export const config = {
   *   matcher: [
   *     "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)",
   *   ],
   * };
   * ```
   *
   * @example Protect routes based on groups
   *
   * ```typescript
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export default monoCloud.authMiddleware({
   *   // group names or IDs
   *   protectedRoutes: [
   *     {
   *       groups: ["admin", "editor", "537e7c3d-a442-4b5b-b308-30837aa045a4"],
   *       routes: ["/internal", "/api/internal(.*)"],
   *     },
   *   ],
   * });
   *
   * export const config = {
   *   matcher: [
   *     "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)",
   *   ],
   * };
   * ```
   *
   */
  authMiddleware(
    options?: MonoCloudMiddlewareOptions
  ): NextMiddleware | NextProxy;

  /**
   * A middleware that protects pages and APIs and handles authentication.
   *
   * @param request The Next.js fetch event object.
   * @param event The associated fetch event [Docs](https://nextjs.org/docs/app/api-reference/file-conventions/proxy#waituntil-and-nextfetchevent).
   *
   * @returns A promise resolving to a Next.js middleware result or a Next.js middleware result.
   *
   * @example Nest Custom Middleware
   *
   * - Use your own middleware wrapper and call MonoCloud only for specific routes
   *
   * ```typescript
   * import { monoCloud } from "@/lib/monocloud";
   * import { NextFetchEvent, NextRequest, NextResponse } from "next/server";
   *
   * export default function customMiddleware(req: NextRequest, evt: NextFetchEvent) {
   *   if (req.nextUrl.pathname.startsWith("/api/protected")) {
   *     return monoCloud.authMiddleware(req, evt);
   *   }
   *
   *   return NextResponse.next();
   * }
   *
   * export const config = {
   *   matcher: [
   *     "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)",
   *   ],
   * };
   * ```
   *
   */
  authMiddleware(
    request: NextRequest,
    event: NextFetchEvent
  ): Promise<NextMiddlewareResult> | NextMiddlewareResult;

  public authMiddleware(
    ...args: unknown[]
  ):
    | NextMiddleware
    | NextProxy
    | Promise<NextMiddlewareResult>
    | NextMiddlewareResult {
    let req: NextRequest | undefined;
    let evt: NextFetchEvent | undefined;
    let options: MonoCloudMiddlewareOptions | undefined;

    /* v8 ignore else -- @preserve */
    if (Array.isArray(args)) {
      if (args.length === 2) {
        /* v8 ignore else -- @preserve */
        if (isAppRouter(args[0])) {
          req = args[0] as NextRequest;
          evt = args[1] as NextFetchEvent;
        }
      }

      if (args.length === 1) {
        options = args[0] as MonoCloudMiddlewareOptions;
      }
    }

    if (req && evt) {
      return this.authMiddlewareHandler(req, evt, options) as any;
    }

    return (request: NextRequest, nxtEvt: NextFetchEvent) => {
      return this.authMiddlewareHandler(request, nxtEvt, options);
    };
  }

  private async authMiddlewareHandler(
    req: NextRequest,
    evt: NextFetchEvent,
    options?: MonoCloudMiddlewareOptions
  ): Promise<NextMiddlewareResult> {
    // eslint-disable-next-line no-param-reassign
    req = getNextRequest(req);

    if (req.headers.has('x-middleware-subrequest')) {
      return NextResponse.json({ message: 'forbidden' }, { status: 403 });
    }

    const { routes, appUrl } = this.getOptions();

    if (
      Object.values(routes!)
        .map(x => ensureLeadingSlash(x))
        .includes(req.nextUrl.pathname)
    ) {
      let onError;
      if (typeof options?.onError === 'function') {
        onError = (
          error: Error
        ):
          | Promise<void | NextResponse<unknown>>
          | void
          | NextResponse<unknown> => options.onError!(req, evt, error);
      }

      const request = new MonoCloudAppRouterRequest(req);
      const response = new MonoCloudAppRouterResponse(new NextResponse());

      return this.handleAuthRoutes(
        request,
        response,
        req.nextUrl.pathname,
        routes,
        onError
      );
    }

    const nxtResp = new NextResponse();

    nxtResp.headers.set(
      'x-monocloud-path',
      req.nextUrl.pathname + req.nextUrl.search
    );

    let isRouteProtected = true;
    let allowedGroups: string[] | undefined;

    if (typeof options?.protectedRoutes === 'function') {
      isRouteProtected = await options.protectedRoutes(req);
    } else if (
      typeof options?.protectedRoutes !== 'undefined' &&
      Array.isArray(options.protectedRoutes)
    ) {
      isRouteProtected = options.protectedRoutes.some(route => {
        if (typeof route === 'string' || route instanceof RegExp) {
          return new RegExp(route).test(req.nextUrl.pathname);
        }

        return route.routes.some(groupRoute => {
          const result = new RegExp(groupRoute).test(req.nextUrl.pathname);

          if (result) {
            allowedGroups = route.groups;
          }

          return result;
        });
      });
    }

    if (!isRouteProtected) {
      return NextResponse.next({
        headers: {
          'x-monocloud-path': req.nextUrl.pathname + req.nextUrl.search,
        },
      });
    }

    const session = await this.getSession(req, nxtResp);

    if (!session) {
      if (options?.onAccessDenied) {
        const result = await options.onAccessDenied(req, evt);

        if (result instanceof NextResponse) {
          return mergeResponse([nxtResp, result]);
        }

        if (result) {
          return mergeResponse([
            nxtResp,
            new NextResponse(result.body, result),
          ]);
        }

        return NextResponse.next(nxtResp);
      }

      if (req.nextUrl.pathname.startsWith('/api')) {
        return mergeResponse([
          nxtResp,
          NextResponse.json({ message: 'unauthorized' }, { status: 401 }),
        ]);
      }

      const signInRoute = new URL(
        `${appUrl}${ensureLeadingSlash(routes!.signIn)}`
      );

      signInRoute.searchParams.set(
        'return_url',
        req.nextUrl.pathname + req.nextUrl.search
      );

      return mergeResponse([nxtResp, NextResponse.redirect(signInRoute)]);
    }

    const groupsClaim =
      options?.groupsClaim ?? process.env.MONOCLOUD_AUTH_GROUPS_CLAIM;

    if (
      allowedGroups &&
      !isUserInGroup(session.user, allowedGroups, groupsClaim)
    ) {
      if (options?.onGroupAccessDenied) {
        const result = await options.onGroupAccessDenied(
          req,
          evt,
          session.user
        );

        if (result instanceof NextResponse) {
          return mergeResponse([nxtResp, result]);
        }

        if (result) {
          return mergeResponse([
            nxtResp,
            new NextResponse(result.body, result),
          ]);
        }

        return NextResponse.next(nxtResp);
      }

      if (req.nextUrl.pathname.startsWith('/api')) {
        return mergeResponse([
          nxtResp,
          NextResponse.json({ message: 'forbidden' }, { status: 403 }),
        ]);
      }

      return new NextResponse(`forbidden`, {
        status: 403,
      });
    }

    return NextResponse.next(nxtResp);
  }

  private handleAuthRoutes(
    request: MonoCloudRequest,
    response: MonoCloudResponse,
    path: string,
    routes: MonoCloudOptions['routes'],
    onError?: OnError
  ): Promise<any> {
    switch (path) {
      case ensureLeadingSlash(routes!.signIn):
        return this.coreClient.signIn(request, response, {
          onError,
        });

      case ensureLeadingSlash(routes!.callback):
        return this.coreClient.callback(request, response, {
          onError,
        });

      case ensureLeadingSlash(routes!.userInfo):
        return this.coreClient.userInfo(request, response, {
          onError,
        });

      case ensureLeadingSlash(routes!.signOut):
        return this.coreClient.signOut(request, response, {
          onError,
        });

      default:
        response.notFound();
        return response.done();
    }
  }

  /**
   * ## SSR Components, Actions, Middleware or API Handlers
   *
   * Retrieves the session object for the currently authenticated user on the server.
   *
   * **Use Case:**
   * - App Router Server Components (RSC).
   * - Server Actions
   * - Route Handlers (App Router only).
   * - Middleware (App Router and Pages Router).
   *
   * *Note: If the session cannot be resolved or an underlying error occurs, the promise rejects with an error.*
   *
   * @returns `MonoCloudSession` if found, or `undefined`.
   *
   * @example Middleware/Proxy
   *
   * ```typescript
   * import { monoCloud } from "@/lib/monocloud";
   * import { NextResponse } from "next/server";
   *
   * export default async function middleware() {
   *   const session = await monoCloud.getSession();
   *
   *   if (!session) {
   *     return new NextResponse("User not signed in", { status: 401 });
   *   }
   *
   *   return NextResponse.next();
   * }
   *
   * export const config = {
   *   matcher: [
   *     "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)",
   *   ],
   * };
   * ```
   *
   * @example App Router API Handler
   *
   * ```typescript
   * import { NextResponse } from "next/server";
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export const GET = async () => {
   *   const session = await monoCloud.getSession();
   *
   *   return NextResponse.json({ name: session?.user.name });
   * };
   * ```
   *
   * @example React Server Components
   *
   * ```tsx
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export default async function Home() {
   *   const session = await monoCloud.getSession();
   *
   *   return <div>{session?.user.name}</div>;
   * }
   * ```
   *
   * @example Server Action
   *
   * ```typescript
   * "use server";
   *
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export async function getUserAction() {
   *   const session = await monoCloud.getSession();
   *
   *   return { name: session?.user.name };
   * }
   * ```
   *
   */
  public getSession(): Promise<MonoCloudSession | undefined>;

  /**
   * ## Middleware/Proxy or Route Handlers
   *
   * Retrieves the session object for the currently authenticated user on the server.
   *
   * **Use Case:**
   * - Middleware (for both App and Pages Router).
   * - App Router Route Handlers (API routes).
   * - Edge functions.
   *
   * *Note: If the session cannot be resolved or an underlying error occurs, the promise rejects with an error.*
   *
   * @param req NextRequest
   * @param res An optional `NextResponse` instance. Pass this if you have already initialized a response; otherwise, omit this parameter.
   *
   * @returns `MonoCloudSession` if found, or `undefined`.
   *
   * @example Middleware/Proxy
   *
   * ```typescript
   * import { monoCloud } from "@/lib/monocloud";
   * import { NextRequest, NextResponse } from "next/server";
   *
   * export default async function middleware(req: NextRequest) {
   *   const session = await monoCloud.getSession(req);
   *
   *   if (!session) {
   *     return new NextResponse("User not signed in", { status: 401 });
   *   }
   *
   *   return NextResponse.next();
   * }
   *
   * export const config = {
   *   matcher: [
   *     "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)",
   *   ],
   * };
   * ```
   *
   * @example Middleware/Proxy (Custom Response)
   *
   * ```typescript
   * import { monoCloud } from "@/lib/monocloud";
   * import { NextRequest, NextResponse } from "next/server";
   *
   * export default async function middleware(req: NextRequest) {
   *   const res = NextResponse.next();
   *
   *   const session = await monoCloud.getSession(req, res);
   *
   *   if (!session) {
   *     return new NextResponse("User not signed in", { status: 401 });
   *   }
   *
   *   res.headers.set("x-auth-status", "active");
   *
   *   return res;
   * }
   *
   * export const config = {
   *   matcher: [
   *     "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)",
   *   ],
   * };
   * ```
   *
   * @example API Handler
   *
   * ```typescript
   * import { NextRequest, NextResponse } from "next/server";
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export const GET = async (req: NextRequest) => {
   *   const session = await monoCloud.getSession(req);
   *
   *   return NextResponse.json({ name: session?.user.name });
   * };
   * ```
   *
   * @example API Handler with NextResponse
   *
   * ```typescript
   * import { NextRequest, NextResponse } from "next/server";
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export const GET = async (req: NextRequest) => {
   *   const res = new NextResponse("YOUR CUSTOM RESPONSE");
   *
   *   const session = await monoCloud.getSession(req, res);
   *
   *   if (session?.user) {
   *     res.cookies.set("something", "important");
   *   }
   *
   *   return res;
   * };
   * ```
   */
  public getSession(
    req: NextRequest | Request,
    res?: NextResponse | Response
  ): Promise<MonoCloudSession | undefined>;

  /**
   * ## Pages Router (Node.js Runtime)
   *
   * Retrieves the session object for the currently authenticated user on the server.
   *
   * *Note: If the session cannot be resolved or an underlying error occurs, the promise rejects with an error.*
   *
   * @param req NextApiRequest
   * @param res NextApiResponse
   *
   * @returns `MonoCloudSession` if found, or `undefined`.
   *
   * @example API Handler
   *
   * ```typescript
   * import { monoCloud } from "@/lib/monocloud";
   * import type { NextApiRequest, NextApiResponse } from "next";
   *
   * type Data = {
   *   name?: string;
   * };
   *
   * export default async function handler(
   *   req: NextApiRequest,
   *   res: NextApiResponse<Data>
   * ) {
   *   const session = await monoCloud.getSession(req, res);
   *
   *   res.status(200).json({ name: session?.user.name });
   * }
   * ```
   *
   * @example SSR Component
   *
   * ```typescript
   * import { monoCloud } from "@/monocloud";
   * import type {
   *   GetServerSideProps,
   *   GetServerSidePropsContext,
   *   InferGetServerSidePropsType,
   * } from "next";
   *
   * type HomeProps = InferGetServerSidePropsType<typeof getServerSideProps>;
   *
   * export default function Home({ session }: HomeProps) {
   *   return <pre>Session: {JSON.stringify(session, null, 2)}</pre>;
   * }
   *
   * export const getServerSideProps = (async (
   *   context: GetServerSidePropsContext,
   * ) => {
   *   const session = await monoCloud.getSession(
   *     context.req,
   *     context.res,
   *   );
   *
   *   return {
   *     props: {
   *       session: session ?? null,
   *     },
   *   };
   * }) satisfies GetServerSideProps;
   * ```
   */
  public getSession(
    req: NextApiRequest | IncomingMessage,
    res: NextApiResponse | ServerResponse<IncomingMessage>
  ): Promise<MonoCloudSession | undefined>;

  async getSession(...args: any[]): Promise<MonoCloudSession | undefined> {
    let request: IMonoCloudCookieRequest;
    let response: IMonoCloudCookieResponse;

    if (args.length === 0) {
      request = new MonoCloudCookieRequest();
      response = new MonoCloudCookieResponse();
    } else {
      ({ request, response } = getMonoCloudCookieReqRes(args[0], args[1]));
    }

    /* v8 ignore next -- @preserve */
    if (!isMonoCloudRequest(request) || !isMonoCloudResponse(response)) {
      throw new MonoCloudValidationError(
        'Invalid parameters passed to getSession()'
      );
    }

    return await this.coreClient.getSession(request, response);
  }

  /**
   * ## SSR Components, Actions, Middleware or API Handlers
   *
   * Retrieves the tokens for the currently signed-in user. Optionally refreshes/fetches new tokens.
   *
   * **Use Case:**
   * - App Router Server Components (RSC).
   * - Server Actions
   * - Route Handlers (App Router only).
   * - Middleware (App Router and Pages Router).
   *
   * @param options Configuration options for token retrieval.
   *
   * @returns
   *
   * @throws {@link MonoCloudValidationError} If session is not found
   *
   * @example Middleware/Proxy
   *
   * ```typescript
   * import { monoCloud } from "@/lib/monocloud";
   * import { NextResponse } from "next/server";
   *
   * export default async function middleware() {
   *   const tokens = await monoCloud.getTokens();
   *
   *   if (tokens.isExpired) {
   *     return new NextResponse("Tokens expired", { status: 401 });
   *   }
   *
   *   return NextResponse.next();
   * }
   *
   * export const config = {
   *   matcher: [
   *     "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)",
   *   ],
   * };
   * ```
   *
   * @example App Router API Handler
   *
   * ```typescript
   * import { NextResponse } from "next/server";
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export const GET = async () => {
   *   const tokens = await monoCloud.getTokens();
   *
   *   return NextResponse.json({ expired: tokens.isExpired });
   * };
   * ```
   *
   * @example React Server Components
   *
   * ```tsx
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export default async function Home() {
   *   const tokens = await monoCloud.getTokens();
   *
   *   return <div>Expired: {tokens.isExpired.toString()}</div>;
   * }
   * ```
   *
   * @example Server Action
   *
   * ```typescript
   * "use server";
   *
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export async function getExpiredAction() {
   *   const tokens = await monoCloud.getTokens();
   *
   *   return { expired: tokens.isExpired };
   * }
   * ```
   *
   * @example Refresh Default Token
   *
   *  The default token is an access token with scopes set through `MONOCLOUD_AUTH_SCOPES` or
   * `options.defaultAuthParams.scopes`, and resources set through `MONOCLOUD_AUTH_RESOURCE` or
   * `options.defaultAuthParams.resource`. This token is refreshed when calling getTokens without resource and scopes parameters.
   *
   * ```typescript
   * import { NextResponse } from "next/server";
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export const GET = async () => {
   * // Although the token refreshes automatically upon expiration, we are manually refreshing it here.
   * const tokens = await monoCloud.getTokens({ forceRefresh: true });
   *
   * return NextResponse.json({ accessToken: tokens?.accessToken });
   * };
   * ```
   *
   * @example Request new access token for resource(s)
   *
   * **Note: Ensure that the resources and scopes are included in the initial authorization flow**
   *
   * The following example shows how to request a new token scoped to two non-exclusive resources.
   *
   * ```typescript
   * import { NextResponse } from "next/server";
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export const GET = async () => {
   *   const tokens = await monoCloud.getTokens({
   *     resource: "https://first.example.com https://second.example.com",
   *     scopes: "read:first read:second shared",
   *   });
   *
   *   return NextResponse.json({ accessToken: tokens?.accessToken });
   * };
   * ```
   *
   * @example Request an exclusive token
   *
   * **Note: Ensure that the resources and scopes are included in the initial authorization flow**
   *
   * ```typescript
   * import { NextResponse } from "next/server";
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export const GET = async () => {
   *   const tokens = await monoCloud.getTokens({
   *     resource: "https://exclusive.example.com",
   *     scopes: "read:exclusive shared",
   *   });
   *
   *   return NextResponse.json({ accessToken: tokens?.accessToken });
   * };
   * ```
   */
  public getTokens(options?: GetTokensOptions): Promise<MonoCloudTokens>;

  /**
   * ## Middleware/Proxy or Route Handlers
   *
   * Retrieves the tokens for the currently signed-in user. Optionally refreshes/fetches new tokens.
   *
   * **Use Case:**
   * - Middleware (for both App and Pages Router).
   * - App Router Route Handlers (API routes).
   * - Edge functions.
   *
   * @param req NextRequest
   * @param options Configuration options for token retrieval.
   *
   * @returns
   *
   * @throws {@link MonoCloudValidationError} If session is not found
   *
   * @example Middleware/Proxy
   *
   * ```typescript
   * import { monoCloud } from "@/lib/monocloud";
   * import { NextRequest, NextResponse } from "next/server";
   *
   * export default async function middleware(req: NextRequest) {
   *   const tokens = await monoCloud.getTokens(req);
   *
   *   if (tokens.isExpired) {
   *     return new NextResponse("Tokens expired", { status: 401 });
   *   }
   *
   *   return NextResponse.next();
   * }
   *
   * export const config = {
   *   matcher: [
   *     "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)",
   *   ],
   * };
   * ```
   *
   * @example App Router API Handler
   *
   * ```typescript
   * import { NextRequest, NextResponse } from "next/server";
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export const GET = async (req: NextRequest) => {
   *   const tokens = await monoCloud.getTokens(req);
   *
   *   return NextResponse.json({ expired: tokens?.isExpired });
   * };
   * ```
   *
   * @example Refresh Default Token
   *
   *  The default token is an access token with scopes set through `MONOCLOUD_AUTH_SCOPES` or
   * `options.defaultAuthParams.scopes`, and resources set through `MONOCLOUD_AUTH_RESOURCE` or
   * `options.defaultAuthParams.resource`. This token is refreshed when calling getTokens without parameters.
   *
   * ```typescript
   * import { NextRequest, NextResponse } from "next/server";
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export const GET = async (req: NextRequest) => {
   *   // Although the token refreshes automatically upon expiration, we are manually refreshing it here.
   *   const tokens = await monoCloud.getTokens(req, { forceRefresh: true });
   *
   *   return NextResponse.json({ accessToken: tokens?.accessToken });
   * };
   * ```
   *
   * @example Request new access token for resource(s)
   *
   * **Note: Ensure that the resources and scopes are included in the initial authorization flow**
   *
   * The following example shows how to request a new token scoped to two non-exclusive resources.
   *
   * ```typescript
   * import { NextRequest, NextResponse } from "next/server";
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export const GET = async (req: NextRequest) => {
   *   const tokens = await monoCloud.getTokens(req, {
   *     resource: "https://first.example.com https://second.example.com",
   *     scopes: "read:first read:second shared",
   *   });
   *
   *   return NextResponse.json({ accessToken: tokens?.accessToken });
   * };
   * ```
   *
   * @example Request an exclusive token
   *
   * **Note: Ensure that the resources and scopes are included in the initial authorization flow**
   *
   * ```typescript
   * import { NextRequest, NextResponse } from "next/server";
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export const GET = async (req: NextRequest) => {
   *   const tokens = await monoCloud.getTokens(req, {
   *     resource: "https://exclusive.example.com",
   *     scopes: "read:exclusive shared",
   *   });
   *
   *   return NextResponse.json({ accessToken: tokens?.accessToken });
   * };
   * ```
   */
  public getTokens(
    req: NextRequest | Request,
    options?: GetTokensOptions
  ): Promise<MonoCloudTokens>;

  /**
   * ## Middleware/Proxy or Route Handlers (Custom Response)
   *
   * Retrieves the tokens for the currently signed-in user. Optionally refreshes/fetches new tokens and updates the provided response object.
   *
   * **Use Case:**
   * - Middleware (when modifying the response).
   * - App Router Route Handlers (when a NextResponse is already initialized).
   *
   * @param req NextRequest
   * @param res An optional `NextResponse` instance. Pass this if you have already initialized a response and want token updates (e.g., refreshing) to be applied to it.
   * @param options Configuration options for token retrieval.
   *
   * @returns
   *
   * @throws {@link MonoCloudValidationError} If session is not found
   *
   * @example Middleware/Proxy
   *
   *```typescript
   * import { monoCloud } from "@/lib/monocloud";
   * import { NextRequest, NextResponse } from "next/server";
   *
   * export default async function middleware(req: NextRequest) {
   *   const res = NextResponse.next();
   *
   *   const tokens = await monoCloud.getTokens(req, res);
   *
   *   res.headers.set("x-tokens-expired", tokens.isExpired.toString());
   *
   *   return res;
   * }
   *
   * export const config = {
   *   matcher: [
   *     "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)",
   *   ],
   * };
   * ```
   *
   * @example API Handler with NextResponse
   *
   * ```typescript
   * import { NextRequest, NextResponse } from "next/server";
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export const GET = async (req: NextRequest) => {
   *   const res = new NextResponse("Custom Body");
   *
   *   const tokens = await monoCloud.getTokens(req, res);
   *
   *   if (!tokens.isExpired) {
   *     res.headers.set("x-auth-status", "active");
   *   }
   *
   *   return res;
   * };
   * ```
   *
   * @example Refresh Default Token
   *
   * The default token is an access token with scopes set through `MONOCLOUD_AUTH_SCOPES` or
   * `options.defaultAuthParams.scopes`, and resources set through `MONOCLOUD_AUTH_RESOURCE` or
   * `options.defaultAuthParams.resource`. This token is refreshed when calling getTokens without parameters.
   *
   * ```typescript
   * import { NextRequest, NextResponse } from "next/server";
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export const GET = async (req: NextRequest) => {
   *   const res = new NextResponse("Custom Body");
   *
   *   // Although the token refreshes automatically upon expiration, we are manually refreshing it here.
   *   const tokens = await monoCloud.getTokens(req, res, { forceRefresh: true });
   *
   *   if (!tokens.isExpired) {
   *     res.headers.set("x-auth-status", "active");
   *   }
   *
   *   return res;
   * };
   * ```
   *
   * @example Request new access token for resource(s)
   *
   * **Note: Ensure that the resources and scopes are included in the initial authorization flow**
   *
   * The following example shows how to request a new token scoped to two non-exclusive resources.
   *
   * ```typescript
   * import { NextRequest, NextResponse } from "next/server";
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export const GET = async (req: NextRequest) => {
   *   const res = new NextResponse("Custom Body");
   *
   *   const tokens = await monoCloud.getTokens(req, res, {
   *     resource: "https://first.example.com https://second.example.com",
   *     scopes: "read:first read:second shared",
   *   });
   *
   *   if (!tokens.isExpired) {
   *     res.headers.set("x-auth-status", "active");
   *   }
   *
   *   return res;
   * };
   * ```
   *
   * @example Request an exclusive token
   *
   * **Note: Ensure that the resources and scopes are included in the initial authorization flow**
   *
   * ```typescript
   * import { NextRequest, NextResponse } from "next/server";
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export const GET = async (req: NextRequest) => {
   *   const res = new NextResponse("Custom Body");
   *
   *   const tokens = await monoCloud.getTokens(req, res, {
   *     resource: "https://exclusive.example.com",
   *     scopes: "read:exclusive shared",
   *   });
   *
   *   if (!tokens.isExpired) {
   *     res.headers.set("x-auth-status", "active");
   *   }
   *
   *   return res;
   * };
   * ```
   */
  public getTokens(
    req: NextRequest | Request,
    res: NextResponse | Response,
    options?: GetTokensOptions
  ): Promise<MonoCloudTokens>;

  /**
   * ## Pages Router (Node.js Runtime)
   *
   * Retrieves the tokens for the currently signed-in user. Optionally refreshes/fetches new tokens.
   *
   * @param req The `NextApiRequest` or `IncomingMessage`.
   * @param res The `NextApiResponse` or `ServerResponse`.
   * @param options Configuration options for token retrieval.
   *
   * @returns
   *
   * @throws {@link MonoCloudValidationError} If session is not found
   *
   * @example API Route
   *
   * ```typescript
   * import { monoCloud } from "@/lib/monocloud";
   * import type { NextApiRequest, NextApiResponse } from "next";
   *
   * export default async function handler(
   *   req: NextApiRequest,
   *   res: NextApiResponse
   * ) {
   *   const tokens = await monoCloud.getTokens(req, res);
   *
   *   res.status(200).json({ accessToken: tokens?.accessToken });
   * }
   * ```
   *
   * @example SSR Component
   *
   * ```typescript
   * import { monoCloud } from "@/lib/monocloud";
   * import type { GetServerSideProps, InferGetServerSidePropsType } from "next";
   *
   * type HomeProps = InferGetServerSidePropsType<typeof getServerSideProps>;
   *
   * export default function Home({ tokens }: HomeProps) {
   *   return <pre>Tokens: {JSON.stringify(tokens, null, 2)}</pre>;
   * }
   *
   * export const getServerSideProps: GetServerSideProps = async (context) => {
   *   const tokens = await monoCloud.getTokens(context.req, context.res);
   *
   *   return {
   *     props: {
   *       tokens: tokens ?? null,
   *     },
   *   };
   * };
   * ```
   *
   * @example Refresh Default Token
   *
   *  The default token is an access token with scopes set through `MONOCLOUD_AUTH_SCOPES` or
   * `options.defaultAuthParams.scopes`, and resources set through `MONOCLOUD_AUTH_RESOURCE` or
   * `options.defaultAuthParams.resource`. This token is refreshed when calling getTokens without parameters.
   *
   * ```typescript
   * import { monoCloud } from "@/lib/monocloud";
   * import type { NextApiRequest, NextApiResponse } from "next";
   *
   * export default async function handler(
   *   req: NextApiRequest,
   *   res: NextApiResponse
   * ) {
   *   // Although the token refreshes automatically upon expiration, we are manually refreshing it here.
   *   const tokens = await monoCloud.getTokens(req, res, { forceRefresh: true });
   *
   *   res.status(200).json({ accessToken: tokens?.accessToken });
   * }
   * ```
   *
   * @example Request new access token for resource(s)
   *
   *  **Note: Ensure that the resources and scopes are included in the initial authorization flow**
   *
   *  The following example shows how to request a new token scoped to two non-exclusive resources.
   *
   * ```typescript
   * import { monoCloud } from "@/lib/monocloud";
   * import type { NextApiRequest, NextApiResponse } from "next";
   *
   * export default async function handler(
   *   req: NextApiRequest,
   *   res: NextApiResponse
   * ) {
   *   const tokens = await monoCloud.getTokens(req, res, {
   *     resource: "https://first.example.com https://second.example.com",
   *     scopes: "read:first read:second shared",
   *   });
   *
   *   res.status(200).json({ accessToken: tokens?.accessToken });
   * }
   * ```
   *
   * @example Request an exclusive token
   *
   *  **Note: Ensure that the resources and scopes are included in the initial authorization flow**
   *
   * ```typescript
   * import { monoCloud } from "@/lib/monocloud";
   * import type { NextApiRequest, NextApiResponse } from "next";
   *
   * export default async function handler(
   *   req: NextApiRequest,
   *   res: NextApiResponse
   * ) {
   *   const tokens = await monoCloud.getTokens(req, res, {
   *     resource: "https://exclusive.example.com",
   *     scopes: "read:exclusive shared",
   *   });
   *
   *   res.status(200).json({ accessToken: tokens?.accessToken });
   * }
   * ```
   */
  public getTokens(
    req: NextApiRequest | IncomingMessage,
    res: NextApiResponse | ServerResponse<IncomingMessage>,
    options?: GetTokensOptions
  ): Promise<MonoCloudTokens>;

  async getTokens(...args: any[]): Promise<MonoCloudTokens> {
    let request: IMonoCloudCookieRequest;
    let response: IMonoCloudCookieResponse;
    let options: GetTokensOptions | undefined;

    if (args.length === 0) {
      request = new MonoCloudCookieRequest();
      response = new MonoCloudCookieResponse();
    } else if (args.length === 1) {
      if (args[0] instanceof Request) {
        ({ request, response } = getMonoCloudCookieReqRes(args[0], undefined));
      } else {
        request = new MonoCloudCookieRequest();
        response = new MonoCloudCookieResponse();
        options = args[0];
      }
    } else if (args.length === 2 && args[0] instanceof Request) {
      if (args[1] instanceof Response) {
        ({ request, response } = getMonoCloudCookieReqRes(args[0], args[1]));
      } else {
        ({ request, response } = getMonoCloudCookieReqRes(args[0], undefined));

        options = args[1] as GetTokensOptions;
      }
    } else if (
      args.length === 2 &&
      args[0] instanceof IncomingMessage &&
      args[1] instanceof ServerResponse
    ) {
      ({ request, response } = getMonoCloudCookieReqRes(args[0], args[1]));
    } else {
      ({ request, response } = getMonoCloudCookieReqRes(args[0], args[1]));

      options = args[2] as GetTokensOptions;
    }

    if (
      !isMonoCloudRequest(request) ||
      !isMonoCloudResponse(response) ||
      (options && typeof options !== 'object')
    ) {
      throw new MonoCloudValidationError(
        'Invalid parameters passed to getTokens()'
      );
    }

    return await this.coreClient.getTokens(request, response, options);
  }

  /**
   * ## SSR Components, Actions, Middleware or API Handlers
   *
   * Checks if the current user is authenticated.
   *
   * **Use Case:**
   * - App Router Server Components (RSC).
   * - Server Actions
   * - Route Handlers (App Router only).
   * - Middleware (App Router and Pages Router).
   *
   * @returns `true` if the user is authenticated, otherwise `false`.
   *
   * @example Middleware/Proxy
   *
   * ```typescript
   * import { monoCloud } from "@/lib/monocloud";
   * import { NextResponse } from "next/server";
   *
   * export default async function middleware() {
   *   const authenticated = await monoCloud.isAuthenticated();
   *
   *   if (!authenticated) {
   *     return new NextResponse("User not signed in", { status: 401 });
   *   }
   *
   *   return NextResponse.next();
   * }
   *
   * export const config = {
   *   matcher: [
   *     "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)",
   *   ],
   * };
   * ```
   *
   * @example App Router API Handler
   *
   * ```typescript
   * import { NextResponse } from "next/server";
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export const GET = async () => {
   *   const authenticated = await monoCloud.isAuthenticated();
   *
   *   return NextResponse.json({ authenticated });
   * };
   * ```
   *
   * @example React Server Components
   *
   * ```tsx
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export default async function Home() {
   *   const authenticated = await monoCloud.isAuthenticated();
   *
   *   return <div>Authenticated: {authenticated.toString()}</div>;
   * }
   * ```
   *
   * @example Server Action
   *
   * ```typescript
   * "use server";
   *
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export async function checkAuthAction() {
   *   const authenticated = await monoCloud.isAuthenticated();
   *
   *   return { authenticated };
   * }
   * ```
   */
  public isAuthenticated(): Promise<boolean>;

  /**
   * ## Middleware/Proxy or Route Handlers
   *
   * Checks if the current user is authenticated.
   *
   * **Use Case:**
   * - Middleware (for both App and Pages Router).
   * - App Router Route Handlers (API routes).
   * - Edge functions.
   *
   * @param req NextRequest
   * @param res An optional `NextResponse` instance. Pass this if you have already initialized a response; otherwise, omit this parameter.
   *
   * @returns `true` if the user is authenticated, otherwise `false`.
   *
   * @example Middleware/Proxy
   *
   * ```typescript
   * import { monoCloud } from "@/lib/monocloud";
   * import { NextRequest, NextResponse } from "next/server";
   *
   * export default async function middleware(req: NextRequest) {
   *   const authenticated = await monoCloud.isAuthenticated(req);
   *
   *   if (!authenticated) {
   *     return new NextResponse("User not signed in", { status: 401 });
   *   }
   *
   *   return NextResponse.next();
   * }
   *
   * export const config = {
   *   matcher: [
   *     "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)",
   *   ],
   * };
   * ```
   *
   * @example Middleware/Proxy (Custom Response)
   *
   * ```typescript
   * import { monoCloud } from "@/lib/monocloud";
   * import { NextRequest, NextResponse } from "next/server";
   *
   * export default async function middleware(req: NextRequest) {
   *   const res = NextResponse.next();
   *
   *   const authenticated = await monoCloud.isAuthenticated(req, res);
   *
   *   if (!authenticated) {
   *     return new NextResponse("User not signed in", { status: 401 });
   *   }
   *
   *   res.headers.set("x-authenticated", "true");
   *
   *   return res;
   * }
   *
   * export const config = {
   *   matcher: [
   *     "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)",
   *   ],
   * };
   * ```
   *
   * @example API Handler
   *
   * ```typescript
   * import { NextRequest, NextResponse } from "next/server";
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export const GET = async (req: NextRequest) => {
   *   const authenticated = await monoCloud.isAuthenticated(req);
   *
   *   return NextResponse.json({ authenticated });
   * };
   * ```
   *
   * @example API Handler with NextResponse
   *
   * ```typescript
   * import { NextRequest, NextResponse } from "next/server";
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export const GET = async (req: NextRequest) => {
   *   const res = new NextResponse("YOUR CUSTOM RESPONSE");
   *
   *   const authenticated = await monoCloud.isAuthenticated(req, res);
   *
   *   if (authenticated) {
   *     res.cookies.set("something", "important");
   *   }
   *
   *   return res;
   * };
   * ```
   */
  public isAuthenticated(
    req: NextRequest | Request,
    res?: NextResponse | Response
  ): Promise<boolean>;

  /**
   * ## Pages Router (Node.js Runtime)
   *
   * Checks if the current user is authenticated.
   *
   * @param req NextApiRequest
   * @param res NextApiResponse
   *
   * @returns `true` if the user is authenticated, otherwise `false`.
   *
   * @example API Handler
   *
   * ```typescript
   * import { monoCloud } from "@/lib/monocloud";
   * import type { NextApiRequest, NextApiResponse } from "next";
   *
   * type Data = {
   *   authenticated: boolean;
   * };
   *
   * export default async function handler(
   *   req: NextApiRequest,
   *   res: NextApiResponse<Data>
   * ) {
   *   const authenticated = await monoCloud.isAuthenticated(req, res);
   *
   *   res.status(200).json({ authenticated });
   * }
   * ```
   *
   * @example SSR Component
   *
   * ```typescript
   * import { monoCloud } from "@/lib/monocloud";
   * import type { GetServerSideProps, InferGetServerSidePropsType } from "next";
   *
   * type HomeProps = InferGetServerSidePropsType<typeof getServerSideProps>;
   *
   * export default function Home({ authenticated }: HomeProps) {
   *   return <pre>User is {authenticated ? "logged in" : "guest"}</pre>;
   * }
   *
   * export const getServerSideProps: GetServerSideProps = async (context) => {
   *   const authenticated = await monoCloud.isAuthenticated(
   *     context.req,
   *     context.res
   *   );
   *
   *   return {
   *     props: {
   *       authenticated,
   *     },
   *   };
   * };
   * ```
   */
  public isAuthenticated(
    req: NextApiRequest | IncomingMessage,
    res: NextApiResponse | ServerResponse<IncomingMessage>
  ): Promise<boolean>;

  async isAuthenticated(...args: any[]): Promise<boolean> {
    let request: IMonoCloudCookieRequest;
    let response: IMonoCloudCookieResponse;

    if (args.length === 0) {
      request = new MonoCloudCookieRequest();
      response = new MonoCloudCookieResponse();
    } else {
      ({ request, response } = getMonoCloudCookieReqRes(args[0], args[1]));
    }

    /* v8 ignore next -- @preserve */
    if (!isMonoCloudRequest(request) || !isMonoCloudResponse(response)) {
      throw new MonoCloudValidationError(
        'Invalid parameters passed to isAuthenticated()'
      );
    }

    return await this.coreClient.isAuthenticated(request, response);
  }

  /**
   * Redirects the user to the sign-in flow if they are not authenticated.
   *
   * **This helper is App Router only and is designed for server environments (server components, route handlers, and server actions).**
   *
   * @param options Options to customize the sign-in.
   *
   * @returns
   *
   * @example React Server Component
   *
   * ```tsx
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export default async function Home() {
   *   await monoCloud.protect();
   *
   *   return <>You are signed in.</>;
   * }
   * ```
   *
   * @example API Handler
   *
   * ```typescript
   * import { NextResponse } from "next/server";
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export const GET = async () => {
   *   await monoCloud.protect();
   *
   *   return NextResponse.json({ secret: "ssshhhh!!!" });
   * };
   * ```
   *
   * @example Server Action
   *
   * ```typescript
   * "use server";
   *
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export async function getMessage() {
   *   await monoCloud.protect();
   *
   *   return { secret: "sssshhhhh!!!" };
   * }
   * ```
   */
  public async protect(options?: ProtectOptions): Promise<void> {
    const { routes, appUrl } = this.coreClient.getOptions();
    let path: string;
    try {
      const session = await this.getSession();

      if (session && !options?.groups) {
        return;
      }

      if (
        session &&
        options &&
        options.groups &&
        isUserInGroup(
          session.user,
          options.groups,
          options.groupsClaim ?? process.env.MONOCLOUD_AUTH_GROUPS_CLAIM,
          options.matchAll
        )
      ) {
        return;
      }

      // @ts-expect-error Cannot find module 'next/headers'
      const { headers } = await import('next/headers');

      path = (await headers()).get('x-monocloud-path') ?? '/';
    } catch {
      throw new Error(
        'protect() can only be used in App Router server environments (RSC, route handlers, or server actions)'
      );
    }

    const signInRoute = new URL(`${appUrl}${routes.signIn}`);

    signInRoute.searchParams.set('return_url', options?.returnUrl ?? path);

    if (options?.authParams?.maxAge) {
      signInRoute.searchParams.set(
        'max_age',
        options.authParams.maxAge.toString()
      );
    }

    if (options?.authParams?.authenticatorHint) {
      signInRoute.searchParams.set(
        'authenticator_hint',
        options.authParams.authenticatorHint
      );
    }

    if (options?.authParams?.scopes) {
      signInRoute.searchParams.set('scope', options.authParams.scopes);
    }

    if (options?.authParams?.resource) {
      signInRoute.searchParams.set('resource', options.authParams.resource);
    }

    if (options?.authParams?.display) {
      signInRoute.searchParams.set('display', options.authParams.display);
    }

    if (options?.authParams?.uiLocales) {
      signInRoute.searchParams.set('ui_locales', options.authParams.uiLocales);
    }

    if (Array.isArray(options?.authParams?.acrValues)) {
      signInRoute.searchParams.set(
        'acr_values',
        options.authParams.acrValues.join(' ')
      );
    }

    if (options?.authParams?.loginHint) {
      signInRoute.searchParams.set('login_hint', options.authParams.loginHint);
    }

    if (options?.authParams?.prompt) {
      signInRoute.searchParams.set('prompt', options.authParams.prompt);
    }

    // @ts-expect-error Cannot find module 'next/navigation'
    const { redirect } = await import('next/navigation');

    redirect(signInRoute.toString());
  }

  /**
   * ## SSR Components, Actions, Middleware or API Handlers
   *
   * Checks if the currently authenticated user is a member of any of the specified groups.
   *
   * **Use Case:**
   * - App Router Server Components (RSC).
   * - Server Actions
   * - Route Handlers (App Router only).
   * - Middleware (App Router and Pages Router).
   *
   * @param groups A list of group names or IDs to check against the user's group memberships.
   * @param options Configuration options.
   *
   * @returns
   *
   * @example Middleware/Proxy
   *
   * ```typescript
   * import { monoCloud } from "@/lib/monocloud";
   * import { NextResponse } from "next/server";
   *
   * export default async function middleware() {
   *   const isAdmin = await monoCloud.isUserInGroup(["admin"]);
   *
   *   if (!isAdmin) {
   *     return new NextResponse("User is not admin", { status: 403 });
   *   }
   *
   *   return NextResponse.next();
   * }
   *
   * export const config = {
   *   matcher: [
   *     "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)",
   *   ],
   * };
   * ```
   *
   * @example App Router API Handler
   *
   * ```typescript
   * import { NextResponse } from "next/server";
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export const GET = async () => {
   *   const allowed = await monoCloud.isUserInGroup(["admin", "editor"]);
   *
   *   if (!allowed) {
   *     return new NextResponse("Forbidden", { status: 403 });
   *   }
   *
   *   return NextResponse.json({ status: "success" });
   * };
   * ```
   *
   * @example React Server Components
   *
   * ```tsx
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export default async function AdminPanel() {
   *   const isAdmin = await monoCloud.isUserInGroup(["admin"]);
   *
   *   if (!isAdmin) {
   *     return <div>Access Denied</div>;
   *   }
   *
   *   return <div>Admin Control Panel</div>;
   * }
   * ```
   *
   * @example Server Action
   *
   * ```typescript
   * "use server";
   *
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export async function deletePostAction() {
   *   const canDelete = await monoCloud.isUserInGroup(["admin", "editor"]);
   *
   *   if (!canDelete) {
   *     return { success: false };
   *   }
   *
   *   return { success: true };
   * }
   * ```
   */
  isUserInGroup(
    groups: string[],
    options?: IsUserInGroupOptions
  ): Promise<boolean>;

  /**
   * ## Middleware/Proxy or Route Handlers
   *
   * Checks if the currently authenticated user is a member of any of the specified groups.
   *
   * **Use Case:**
   * - Middleware (for both App and Pages Router).
   * - App Router Route Handlers (API routes).
   * - Edge functions.
   *
   * @param req NextRequest
   * @param groups A list of group names or IDs to check against the user's group memberships.
   * @param options Configuration options.
   *
   * @returns
   *
   * @example Middleware/Proxy
   *
   * ```typescript
   * import { monoCloud } from "@/lib/monocloud";
   * import { NextRequest, NextResponse } from "next/server";
   *
   * export default async function middleware(req: NextRequest) {
   *   const isAdmin = await monoCloud.isUserInGroup(req, ["admin"]);
   *
   *   if (!isAdmin) {
   *     return new NextResponse("User is not admin", { status: 403 });
   *   }
   *
   *   return NextResponse.next();
   * }
   *
   * export const config = {
   *   matcher: [
   *     "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)",
   *   ],
   * };
   * ```
   *
   * @example App Router API Handler
   *
   * ```typescript
   * import { NextRequest, NextResponse } from "next/server";
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export const GET = async (req: NextRequest) => {
   *   const isMember = await monoCloud.isUserInGroup(req, ["admin", "editor"]);
   *
   *   return NextResponse.json({ isMember });
   * };
   * ```
   */
  isUserInGroup(
    req: NextRequest | Request,
    groups: string[],
    options?: IsUserInGroupOptions
  ): Promise<boolean>;

  /**
   * ## Middleware/Proxy or Route Handlers (Custom Response)
   *
   * Checks if the currently authenticated user is a member of any of the specified groups.
   *
   * **Use Case:**
   * - Middleware (when modifying the response).
   * - App Router Route Handlers (when a NextResponse is already initialized).
   *
   * @param req NextRequest
   * @param res An optional `NextResponse` instance. Pass this if you have already initialized a response and want token updates to be applied to it.
   * @param groups A list of group names or IDs to check against the user's group memberships.
   * @param options Configuration options.
   *
   * @returns
   *
   * @example Middleware/Proxy
   *
   * ```typescript
   * import { monoCloud } from "@/lib/monocloud";
   * import { NextRequest, NextResponse } from "next/server";
   *
   * export default async function middleware(req: NextRequest) {
   *   const res = NextResponse.next();
   *
   *   const isAdmin = await monoCloud.isUserInGroup(req, res, ["admin"]);
   *
   *   if (!isAdmin) {
   *     return new NextResponse("User is not admin", { status: 403 });
   *   }
   *
   *   res.headers.set("x-user", "admin");
   *
   *   return res;
   * }
   *
   * export const config = {
   *   matcher: [
   *     "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)",
   *   ],
   * };
   * ```
   *
   * @example API Handler with NextResponse
   *
   * ```typescript
   * import { NextRequest, NextResponse } from "next/server";
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export const GET = async (req: NextRequest) => {
   *   const res = new NextResponse("Restricted Content");
   *
   *   const allowed = await monoCloud.isUserInGroup(req, res, ["admin"]);
   *
   *   if (!allowed) {
   *     return new NextResponse("Not Allowed", res);
   *   }
   *
   *   return res;
   * };
   * ```
   */
  isUserInGroup(
    req: NextRequest | Request,
    res: NextResponse | Response,
    groups: string[],
    options?: IsUserInGroupOptions
  ): Promise<boolean>;

  /**
   * ## Pages Router (Node.js Runtime)
   *
   * Checks if the currently authenticated user is a member of any of the specified groups.
   *
   * @param req The `NextApiRequest` or `IncomingMessage`.
   * @param res The `NextApiResponse` or `ServerResponse`.
   * @param groups A list of group names or IDs to check against the user's group memberships.
   * @param options Configuration options.
   *
   * @returns
   *
   * @example API Route
   *
   * ```typescript
   * import { monoCloud } from "@/lib/monocloud";
   * import type { NextApiRequest, NextApiResponse } from "next";
   *
   * export default async function handler(
   *   req: NextApiRequest,
   *   res: NextApiResponse
   * ) {
   *   const isAdmin = await monoCloud.isUserInGroup(req, res, ["admin"]);
   *
   *   if (!isAdmin) {
   *     return res.status(403).json({ error: "Forbidden" });
   *   }
   *
   *   res.status(200).json({ message: "Welcome Admin" });
   * }
   * ```
   *
   * @example SSR Component
   *
   * ```typescript
   * import { monoCloud } from "@/lib/monocloud";
   * import type { GetServerSideProps, InferGetServerSidePropsType } from "next";
   *
   * type HomeProps = InferGetServerSidePropsType<typeof getServerSideProps>;
   *
   * export default function Home({ isAdmin }: HomeProps) {
   *   return <div>User is admin: {isAdmin.toString()}</div>;
   * }
   *
   * export const getServerSideProps: GetServerSideProps = async (context) => {
   *   const isAdmin = await monoCloud.isUserInGroup(context.req, context.res, [
   *     "admin",
   *   ]);
   *
   *   return {
   *     props: {
   *       isAdmin,
   *     },
   *   };
   * };
   * ```
   */
  isUserInGroup(
    req: NextApiRequest | IncomingMessage,
    res: NextApiResponse | ServerResponse<IncomingMessage>,
    groups: string[],
    options?: IsUserInGroupOptions
  ): Promise<boolean>;

  public async isUserInGroup(...args: any[]): Promise<boolean> {
    let request: IMonoCloudCookieRequest | undefined;
    let response: IMonoCloudCookieResponse | undefined;
    let groups: string[] | undefined;
    let options: IsUserInGroupOptions | undefined;

    if (args.length === 4) {
      groups = args[2];
      options = args[3];

      ({ request, response } = getMonoCloudCookieReqRes(args[0], args[1]));
    }

    if (args.length === 3) {
      if (args[0] instanceof Request) {
        if (args[1] instanceof Response) {
          ({ request, response } = getMonoCloudCookieReqRes(args[0], args[1]));
          groups = args[2];
        } else {
          ({ request, response } = getMonoCloudCookieReqRes(
            args[0],
            undefined
          ));
          groups = args[1];
          options = args[2];
        }
      }

      if (
        args[0] instanceof IncomingMessage &&
        args[1] instanceof ServerResponse
      ) {
        ({ request, response } = getMonoCloudCookieReqRes(args[0], args[1]));
        groups = args[2];
      }
    }

    if (args.length === 2) {
      if (args[0] instanceof Request) {
        ({ request, response } = getMonoCloudCookieReqRes(args[0], undefined));
        groups = args[1];
      }

      if (Array.isArray(args[0])) {
        request = new MonoCloudCookieRequest();
        response = new MonoCloudCookieResponse();

        groups = args[0];
        options = args[1];
      }
    }

    if (args.length === 1) {
      request = new MonoCloudCookieRequest();
      response = new MonoCloudCookieResponse();

      groups = args[0];
    }

    if (
      !Array.isArray(groups) ||
      !isMonoCloudRequest(request) ||
      !isMonoCloudResponse(response) ||
      (options && typeof options !== 'object')
    ) {
      throw new MonoCloudValidationError(
        'Invalid parameters passed to isUserInGroup()'
      );
    }

    const result = await this.coreClient.isUserInGroup(
      request,
      response,
      groups,
      options?.groupsClaim ?? process.env.MONOCLOUD_AUTH_GROUPS_CLAIM,
      options?.matchAll
    );

    return result;
  }

  /**
   * Redirects the user to the sign-in flow.
   *
   * **This helper is App Router only and is designed for server environments (server components, route handlers, and server actions).**
   *
   * @param options Options to customize the sign-in.
   *
   * @returns
   *
   * @example React Server Component
   *
   * ```tsx
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export default async function Home() {
   *   const allowed = await monoCloud.isUserInGroup(["admin"]);
   *
   *   if (!allowed) {
   *     await monoCloud.redirectToSignIn({ returnUrl: "/home" });
   *   }
   *
   *   return <>You are signed in.</>;
   * }
   * ```
   *
   * @example Server Action
   *
   * ```typescript
   * "use server";
   *
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export async function protectedAction() {
   *   const session = await monoCloud.getSession();
   *
   *   if (!session) {
   *     await monoCloud.redirectToSignIn();
   *   }
   *
   *   return { data: "Sensitive Data" };
   * }
   * ```
   *
   * @example API Handler
   *
   * ```typescript
   * import { NextResponse } from "next/server";
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export const GET = async () => {
   *   const session = await monoCloud.getSession();
   *
   *   if (!session) {
   *     await monoCloud.redirectToSignIn({
   *       returnUrl: "/dashboard",
   *     });
   *   }
   *
   *   return NextResponse.json({ data: "Protected content" });
   * };
   * ```
   */
  public async redirectToSignIn(
    options?: RedirectToSignInOptions
  ): Promise<void> {
    const { routes, appUrl } = this.coreClient.getOptions();

    try {
      // @ts-expect-error Cannot find module 'next/headers'
      const { headers } = await import('next/headers');

      await headers();
    } catch {
      throw new Error(
        'redirectToSignIn() can only be used in App Router server environments (RSC, route handlers, or server actions)'
      );
    }

    const signInRoute = new URL(`${appUrl}${routes.signIn}`);

    if (options?.returnUrl) {
      signInRoute.searchParams.set('return_url', options.returnUrl);
    }

    if (options?.maxAge) {
      signInRoute.searchParams.set('max_age', options.maxAge.toString());
    }

    if (options?.authenticatorHint) {
      signInRoute.searchParams.set(
        'authenticator_hint',
        options.authenticatorHint
      );
    }

    if (Array.isArray(options?.scopes)) {
      signInRoute.searchParams.set('scope', options.scopes.join(' '));
    }

    if (Array.isArray(options?.resource)) {
      signInRoute.searchParams.set('resource', options.resource.join(' '));
    }

    if (options?.display) {
      signInRoute.searchParams.set('display', options.display);
    }

    if (options?.uiLocales) {
      signInRoute.searchParams.set('ui_locales', options.uiLocales);
    }

    if (Array.isArray(options?.acrValues)) {
      signInRoute.searchParams.set('acr_values', options.acrValues.join(' '));
    }

    if (options?.loginHint) {
      signInRoute.searchParams.set('login_hint', options.loginHint);
    }

    if (options?.prompt) {
      signInRoute.searchParams.set('prompt', options.prompt);
    }

    // @ts-expect-error Cannot find module 'next/navigation'
    const { redirect } = await import('next/navigation');

    redirect(signInRoute.toString());
  }

  /**
   * Redirects the user to the sign-out flow.
   *
   * **This helper is App Router only and is designed for server environments (server components, route handlers, and server actions).**
   *
   * @param options Options to customize the sign out.
   *
   * @returns
   *
   * @example React Server Component
   *
   * ```tsx
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export default async function Page() {
   *   const session = await monoCloud.getSession();
   *
   *   // Example: Force sign-out if a specific condition is met (e.g., account suspended)
   *   if (session?.user.isSuspended) {
   *     await monoCloud.redirectToSignOut();
   *   }
   *
   *   return <>Welcome User</>;
   * }
   * ```
   *
   * @example Server Action
   *
   * ```typescript
   * "use server";
   *
   * import { monoCloud } from "@/lib/monocloud";
   *
   * export async function signOutAction() {
   *   const session = await monoCloud.getSession();
   *
   *   if (session) {
   *     await monoCloud.redirectToSignOut();
   *   }
   * }
   * ```
   *
   * @example API Handler
   *
   * ```typescript
   * import { monoCloud } from "@/lib/monocloud";
   * import { NextResponse } from "next/server";
   *
   * export const GET = async () => {
   *   const session = await monoCloud.getSession();
   *
   *   if (session) {
   *     await monoCloud.redirectToSignOut({
   *       postLogoutRedirectUri: "/goodbye",
   *     });
   *   }
   *
   *   return NextResponse.json({ status: "already_signed_out" });
   * };
   * ```
   */
  public async redirectToSignOut(
    options?: RedirectToSignOutOptions
  ): Promise<void> {
    const { routes, appUrl } = this.coreClient.getOptions();

    try {
      // @ts-expect-error Cannot find module 'next/headers'
      const { headers } = await import('next/headers');

      await headers();
    } catch {
      throw new Error(
        'redirectToSignOut() can only be used in App Router server environments (RSC, route handlers, or server actions)'
      );
    }

    const signOutRoute = new URL(`${appUrl}${routes.signOut}`);

    if (options?.postLogoutRedirectUri?.trim().length) {
      signOutRoute.searchParams.set(
        'post_logout_url',
        options.postLogoutRedirectUri
      );
    }

    if (typeof options?.federated === 'boolean') {
      signOutRoute.searchParams.set('federated', options.federated.toString());
    }

    // @ts-expect-error Cannot find module 'next/navigation'
    const { redirect } = await import('next/navigation');

    redirect(signOutRoute.toString());
  }

  private getOptions(): MonoCloudOptions {
    return this.coreClient.getOptions();
  }

  private registerPublicEnvVariables(): void {
    Object.keys(process.env)
      .filter(key => key.startsWith('NEXT_PUBLIC_MONOCLOUD_AUTH'))
      .forEach(publicKey => {
        const [, privateKey] = publicKey.split('NEXT_PUBLIC_');
        process.env[privateKey] = process.env[publicKey];
      });
  }
}
