/* eslint-disable import/extensions */
/* eslint-disable @typescript-eslint/no-non-null-assertion */
import type {
  monoCloudAuth,
  protect,
  protectPage,
  authMiddleware,
  getSession,
  getTokens,
  isAuthenticated,
  isUserInGroup,
  redirectToSignIn,
  redirectToSignOut,
} from './initialize';
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
import { isUserInGroup as isUserInGroupCore } from '@monocloud/auth-node-core/utils';
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
import { MonoCloudOidcClient } from '@monocloud/auth-core';
import {
  MonoCloudCoreClient,
  MonoCloudValidationError,
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
  isNodeRequest,
  isNodeResponse,
} from './utils';
import MonoCloudCookieRequest from './requests/monocloud-cookie-request';
import MonoCloudCookieResponse from './responses/monocloud-cookie-response';
import MonoCloudAppRouterRequest from './requests/monocloud-app-router-request';
import MonoCloudAppRouterResponse from './responses/monocloud-app-router-response';
import type { JSX } from 'react';
import type { ParsedUrlQuery } from 'node:querystring';
import type { IncomingMessage, ServerResponse } from 'node:http';
import MonoCloudPageRouterRequest from './requests/monocloud-page-router-request';
import MonoCloudPageRouterResponse from './responses/monocloud-page-router-response';

/**
 * `MonoCloudNextClient` is the core SDK entry point for integrating MonoCloud authentication into a Next.js application.
 *
 * It provides:
 * - Authentication middleware
 * - Route protection helpers
 * - Session and token access
 * - Redirect utilities
 * - Server-side enforcement helpers
 *
 * ## 1. Add environment variables
 *
 * ```bash:.env.local
 * MONOCLOUD_AUTH_TENANT_DOMAIN=<tenant-domain>
 * MONOCLOUD_AUTH_CLIENT_ID=<client-id>
 * MONOCLOUD_AUTH_CLIENT_SECRET=<client-secret>
 * MONOCLOUD_AUTH_SCOPES=openid profile email
 * MONOCLOUD_AUTH_APP_URL=http://localhost:3000
 * MONOCLOUD_AUTH_COOKIE_SECRET=<cookie-secret>
 * ```
 *
 * ## 2. Register middleware
 *
 * ```typescript:src/proxy.ts
 * import { authMiddleware } from "@monocloud/auth-nextjs";
 *
 * export default authMiddleware();
 *
 * export const config = {
 *   matcher: [
 *     "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)",
 *   ],
 * };
 * ```
 *
 * ## Advanced usage
 *
 * ### Create a shared client instance
 *
 * By default, the SDK exposes function exports (for example, `authMiddleware()`, `getSession()`, `getTokens()`) that internally use a shared singleton `MonoCloudNextClient`.
 *
 * Create your own `MonoCloudNextClient` instance when you need multiple configurations, dependency injection, or explicit control over initialization.
 *
 * ```ts:src/monocloud.ts
 * import { MonoCloudNextClient } from "@monocloud/auth-nextjs";
 *
 * export const monoCloud = new MonoCloudNextClient();
 * ```
 *
 * ### Using instance methods
 *
 * Once you create a client instance, call methods directly on it instead of using the default function exports.
 *
 * ```ts:src/app/page.tsx
 * import { monoCloud } from "@/monocloud";
 *
 * export default async function Page() {
 *   const session = await monoCloud.getSession();
 *
 *   if (!session) {
 *     return <>Not signed in</>;
 *   }
 *
 *   return <>Hello {session.user.name}</>;
 * }
 * ```
 *
 * #### Using constructor options
 *
 * When configuration is provided through both constructor options and environment variables, the values passed to the constructor take precedence. Environment variables are used only for options that are not explicitly supplied.
 *
 * ```ts:src/monocloud.ts
 * import { MonoCloudNextClient } from "@monocloud/auth-nextjs";
 *
 * export const monoCloud = new MonoCloudNextClient({
 *   tenantDomain: "<tenant-domain>",
 *   clientId: "<client-id>",
 *   clientSecret: "<client-secret>",
 *   appUrl: "http://localhost:3000",
 *   cookieSecret: "<cookie-secret>",
 *   defaultAuthParams: {
 *     scopes: "openid profile email",
 *   },
 * });
 * ```
 *
 * ### Modifying default routes
 *
 * If you customize any of the default auth route paths:
 *
 * - Also set the corresponding `NEXT_PUBLIC_` environment variables so client-side helpers
 *   (for example `<SignIn />`, `<SignOut />`, and `useAuth()`) can discover the correct URLs.
 * - Update the **Application URLs** in your MonoCloud Dashboard to match the new paths.
 *
 * Example:
 *
 * ```bash:.env.local
 * MONOCLOUD_AUTH_CALLBACK_URL=/api/custom_callback
 * NEXT_PUBLIC_MONOCLOUD_AUTH_CALLBACK_URL=/api/custom_callback
 * ```
 *
 * When routes are overridden, the Redirect URI configured in the dashboard
 * must reflect the new path. For example, during local development:
 *
 * `http://localhost:3000/api/custom_callback`
 *
 * @category Classes
 */
export class MonoCloudNextClient {
  private readonly _coreClient: MonoCloudCoreClient;

  /**
   * This exposes the framework-agnostic MonoCloud client used internally by the Next.js SDK.
   * Use it if you need access to lower-level functionality not directly exposed by MonoCloudNextClient.
   *
   * @returns Returns the underlying **Node client** instance.
   */
  public get coreClient(): MonoCloudCoreClient {
    return this._coreClient;
  }

  /**
   * This is intended for advanced scenarios requiring direct control over the authorization or token flow.
   *
   * @returns Returns the underlying **OIDC client** used for OpenID Connect operations.
   */
  public get oidcClient(): MonoCloudOidcClient {
    return this.coreClient.oidcClient;
  }

  /**
   * Creates a new client instance.
   *
   * @param options Optional configuration for initializing the MonoCloud client. If not provided, settings are automatically resolved from environment variables.
   */
  constructor(options?: MonoCloudOptions) {
    const opt = {
      ...(options ?? {}),
      userAgent: options?.userAgent ?? `${SDK_NAME}@${SDK_VERSION}`,
      debugger: options?.debugger ?? SDK_DEBUGGER_NAME,
    };

    this.registerPublicEnvVariables();
    this._coreClient = new MonoCloudCoreClient(opt);
  }

  /**
   * @see {@link monoCloudAuth} for full docs and examples.
   * @param options Optional configuration for the auth handler.
   * @returns Returns a Next.js-compatible handler for App Router route handlers or Pages Router API routes.
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
   * @see {@link protectPage} for full docs and examples.
   * @param component The App Router server component to protect.
   * @param options Optional configuration for authentication, authorization, and custom access handling (`onAccessDenied`, `onGroupAccessDenied`).
   * @returns A wrapped page component that enforces authentication before rendering.
   */
  protectPage(
    component: ProtectedAppServerComponent,
    options?: ProtectAppPageOptions
  ): AppRouterPageHandler;

  /**
   * @see {@link protectPage} for full docs and examples.
   * @param options Optional configuration for authentication, authorization, and custom access handling (`onAccessDenied`, `onGroupAccessDenied`).
   * @typeParam P - Props returned from getServerSideProps.
   * @typeParam Q - Query parameters parsed from the URL.
   * @returns A getServerSideProps wrapper that enforces authentication before executing the page logic.
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
        !isUserInGroupCore(
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
        !isUserInGroupCore(
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
   * @see {@link protectApi} for full docs and examples.
   * @param handler The route handler to protect.
   * @param options Optional configuration controlling authentication and authorization behavior.
   * @returns Returns a wrapped handler that enforces authentication (and optional authorization) before invoking the original handler.
   */
  protectApi(
    handler: AppRouterApiHandlerFn,
    options?: ProtectApiAppOptions
  ): AppRouterApiHandlerFn;

  /**
   * @see {@link protectApi} for full docs and examples.
   * @param handler - The route handler to protect.
   * @param options Optional configuration controlling authentication and authorization behavior.
   * @returns Returns a wrapped handler that enforces authentication (and optional authorization) before invoking the original handler.
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
      !isUserInGroupCore(
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
      !isUserInGroupCore(
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
   * @see {@link authMiddleware} for full docs and examples.
   * @param options Optional configuration that controls how authentication is enforced (for example, redirect behavior, route matching, or custom handling of unauthenticated requests).
   * @returns Returns a Next.js middleware result (`NextResponse`, redirect, or `undefined` to continue processing).
   */
  authMiddleware(
    options?: MonoCloudMiddlewareOptions
  ): NextMiddleware | NextProxy;

  /**
   * @see {@link authMiddleware} for full docs and examples.
   * @param request Incoming Next.js middleware request used to resolve authentication state.
   * @param event Next.js middleware event providing lifecycle hooks such as `waitUntil`.
   * @returns Returns a Next.js middleware result (`NextResponse`, redirect, or `undefined` to continue processing).
   */
  authMiddleware(
    request: NextRequest,
    event: NextFetchEvent
  ): Promise<NextMiddlewareResult> | NextMiddlewareResult;

  public authMiddleware(
    ...args: any[]
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
      !isUserInGroupCore(session.user, allowedGroups, groupsClaim)
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
   * @see {@link getSession} for full docs and examples.
   * @returns Returns the resolved session, or `undefined` if none exists.
   */
  public getSession(): Promise<MonoCloudSession | undefined>;

  /**
   * @see {@link getSession} for full docs and examples.
   * @param req Incoming request used to read authentication cookies and headers to resolve the current user's session.
   * @param res Optional response to update if session resolution requires refreshed authentication cookies or headers.
   * @returns Returns the resolved session, or `undefined` if none exists.
   */
  public getSession(
    req: NextRequest | Request,
    res?: NextResponse | Response
  ): Promise<MonoCloudSession | undefined>;

  /**
   * @see {@link getSession} for full docs and examples.
   * @param req Incoming Node.js request used to read authentication cookies and resolve the current user's session.
   * @param res Outgoing Node.js response used to apply refreshed authentication cookies when required.
   * @returns Returns the resolved session, or `undefined` if none exists.
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
   * @see {@link getTokens} for full docs and examples.
   * @param options Optional configuration controlling refresh behavior and resource/scope selection.
   * @returns The current user's tokens, refreshed if necessary.
   * @throws {@link MonoCloudValidationError} If no valid session exists.
   */
  public getTokens(options?: GetTokensOptions): Promise<MonoCloudTokens>;

  /**
   * @see {@link getTokens} for full docs and examples.
   * @param req Incoming request used to resolve authentication from cookies and headers.
   * @param options Optional configuration controlling refresh behavior and resource/scope selection.
   * @returns The current user's tokens, refreshed if necessary.
   * @throws {@link MonoCloudValidationError} If no valid session exists.
   */
  public getTokens(
    req: NextRequest | Request,
    options?: GetTokensOptions
  ): Promise<MonoCloudTokens>;

  /**
   * @see {@link getTokens} for full docs and examples.
   * @param req Incoming request used to resolve authentication from cookies and headers.
   * @param res Existing response to update with refreshed authentication cookies or headers.
   * @param options Optional configuration controlling refresh behavior and resource/scope selection.
   * @returns The current user's tokens, refreshed if necessary.
   * @throws {@link MonoCloudValidationError} If no valid session exists.
   */
  public getTokens(
    req: NextRequest | Request,
    res: NextResponse | Response,
    options?: GetTokensOptions
  ): Promise<MonoCloudTokens>;

  /**
   * @see {@link getTokens} for full docs and examples.
   * @param req Incoming Node.js request used to resolve authentication from cookies.
   * @param res Outgoing Node.js response used to apply refreshed authentication cookies when required.
   * @param options Optional configuration controlling refresh behavior and resource/scope selection.
   * @returns The current user's tokens, refreshed if necessary.
   * @throws {@link MonoCloudValidationError} If no valid session exists.
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
      isNodeRequest(args[0]) &&
      isNodeResponse(args[1])
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
   * @see {@link isAuthenticated} for full docs and examples.
   * @returns Returns `true` if a valid session exists; otherwise `false`.
   */
  public isAuthenticated(): Promise<boolean>;

  /**
   * @see {@link isAuthenticated} for full docs and examples.
   * @param req Incoming request used to resolve authentication from cookies and headers.
   * @param res Optional response to update if refreshed authentication cookies or headers are required.
   * @returns Returns `true` if a valid session exists; otherwise `false`.
   */
  public isAuthenticated(
    req: NextRequest | Request,
    res?: NextResponse | Response
  ): Promise<boolean>;

  /**
   * @see {@link isAuthenticated} for full docs and examples.
   * @param req Incoming Node.js request used to resolve authentication from cookies.
   * @param res Outgoing Node.js response used to apply refreshed authentication cookies when required.
   * @returns Returns `true` if a valid session exists; otherwise `false`.
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
   * @see {@link protect} for full docs and examples.
   * @param options Optional configuration for redirect behavior (for example, return URL or sign-in parameters).
   * @returns Resolves if the user is authenticated; otherwise triggers a redirect.
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
        options?.groups &&
        isUserInGroupCore(
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
   * @see {@link isUserInGroup} for full docs and examples.
   * @param groups Group IDs or names to check against the user's group memberships.
   * @param options Optional configuration controlling how group membership is evaluated.
   * @returns Returns `true` if the user belongs to at least one specified group; otherwise `false`.
   */
  isUserInGroup(
    groups: string[],
    options?: IsUserInGroupOptions
  ): Promise<boolean>;

  /**
   * @see {@link isUserInGroup} for full docs and examples.
   * @param req Incoming request used to resolve authentication from cookies and headers.
   * @param groups Group IDs or names to check against the user's group memberships.
   * @param options Optional configuration controlling how group membership is evaluated.
   * @returns Returns `true` if the user belongs to at least one specified group; otherwise `false`.
   */
  isUserInGroup(
    req: NextRequest | Request,
    groups: string[],
    options?: IsUserInGroupOptions
  ): Promise<boolean>;

  /**
   * @see {@link isUserInGroup} for full docs and examples.
   * @param req Incoming request used to resolve authentication from cookies and headers.
   * @param res Existing response to update with refreshed authentication cookies or headers when required.
   * @param groups Group IDs or names to check against the user's group memberships.
   * @param options Optional configuration controlling how group membership is evaluated.
   * @returns Returns `true` if the user belongs to at least one specified group; otherwise `false`.
   */
  isUserInGroup(
    req: NextRequest | Request,
    res: NextResponse | Response,
    groups: string[],
    options?: IsUserInGroupOptions
  ): Promise<boolean>;

  /**
   * @see {@link isUserInGroup} for full docs and examples.
   * @param req Incoming Node.js request used to resolve authentication from cookies.
   * @param res Outgoing Node.js response used to apply refreshed authentication cookies when required.
   * @param groups Group IDs or names to check against the user's group memberships.
   * @param options Optional configuration controlling how group membership is evaluated.
   * @returns Returns `true` if the user belongs to at least one specified group; otherwise `false`.
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

      if (isNodeRequest(args[0]) && isNodeResponse(args[1])) {
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
   * @see {@link redirectToSignIn} for full docs and examples.
   * @param options Optional configuration for the redirect, such as `returnUrl` or additional sign-in parameters.
   * @returns Never resolves. Triggers a redirect to the sign-in flow.
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

    if (options?.scopes) {
      signInRoute.searchParams.set('scope', options.scopes);
    }

    if (options?.resource) {
      signInRoute.searchParams.set('resource', options.resource);
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
   * @see {@link redirectToSignOut} for full docs and examples.
   * @param options Optional configuration for the redirect, such as `postLogoutRedirectUri` or additional sign-out parameters.
   * @returns Never resolves. Triggers a redirect to the sign-out flow.
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
