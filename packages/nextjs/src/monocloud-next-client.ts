/* eslint-disable @typescript-eslint/no-non-null-assertion */
import { NextFetchEvent, NextRequest, NextResponse } from 'next/server';
import { redirect } from 'next/navigation';
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
import type { NextMiddlewareResult } from 'next/dist/server/web/types';
import {
  AppRouterApiHandlerFn,
  AppRouterContext,
  AppRouterPageHandler,
  BaseFuncHandler,
  FuncHandler,
  IsUserInGroupOptions,
  MonoCloudAuthOptions,
  MonoCloudMiddleware,
  MonoCloudMiddlewareOptions,
  NextAnyRequest,
  NextAnyResponse,
  ProtectApi,
  ProtectAppApi,
  ProtectAppPage,
  ProtectAppPageOptions,
  ProtectOptions,
  ProtectPage,
  ProtectPageApi,
  ProtectPagePage,
  ProtectPagePageOptions,
  ProtectPagePageReturnType,
  RedirectToSignInOptions,
  RedirectToSignOutOptions,
} from './types';
import { getMonoCloudReqRes, isAppRouter, mergeResponse } from './utils';
import MonoCloudCookieRequest from './requests/monocloud-cookie-request';
import MonoCloudCookieResponse from './responses/monocloud-cookie-response';
import MonoCloudAppRouterRequest from './requests/monocloud-app-router-request';
import MonoCloudAppRouterResponse from './responses/monocloud-app-router-response';
import { JSX } from 'react';

export class MonoCloudNextClient {
  private readonly coreClient: MonoCloudCoreClient;

  /* v8 ignore next -- @preserve */
  public get oidcClient(): MonoCloudOidcClient {
    return this.coreClient.oidcClient;
  }

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
   * @param {MonoCloudAuthOptions} [options] Optional configuration authentication routes.
   *
   * **Note:** If you are already using `authMiddleware()`, you typically do **not**
   * need this API route handler. This function is intended for applications where
   * middleware cannot be used—such as statically generated (SSG) deployments that still
   * require server-side authentication flows.
   */
  public monoCloudAuth(options?: MonoCloudAuthOptions): any {
    return (req: NextAnyRequest, resOrCtx: NextAnyResponse) => {
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

      const { request, response } = getMonoCloudReqRes(req, resOrCtx);

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
   * Protect server-rendered pages.
   *
   * @returns A protected page handler.
   */
  public protectPage: ProtectPage = (...args: unknown[]) => {
    if (typeof args[0] === 'function') {
      return this.protectAppPage(
        args[0] as AppRouterPageHandler,
        args[1] as ProtectAppPageOptions
      ) as any;
    }

    return this.protectPagePage(
      args[0] as ProtectPagePageOptions
    ) as ProtectPagePageReturnType<any, any>;
  };

  private protectAppPage: ProtectAppPage = (component, options) => {
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
        if (options.onAccessDenied) {
          return options.onAccessDenied({ ...params, user: session.user });
        }

        return 'Access Denied' as unknown as JSX.Element;
      }

      return component({ ...params, user: session.user });
    };
  };

  private protectPagePage: ProtectPagePage = options => {
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
        const customProps: any = (await options.onAccessDenied?.({
          ...context,
          user: session.user,
        })) ?? { props: { accessDenied: true } };

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
  };

  /**
   * Protects an api route handler.
   */
  public protectApi: ProtectApi = (handler, options) => {
    return (req, resOrCtx) => {
      if (isAppRouter(req)) {
        return this.protectAppApi(
          req as NextRequest,
          resOrCtx as AppRouterContext,
          handler as AppRouterApiHandlerFn,
          options as any
        ) as any;
      }
      return this.protectPageApi(
        req as NextApiRequest,
        resOrCtx as NextApiResponse,
        handler as NextApiHandler,
        options as any
      ) as any;
    };
  };

  private protectAppApi: ProtectAppApi = async (req, ctx, handler, options) => {
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
      if (options.onAccessDenied) {
        const result = await options.onAccessDenied(req, ctx);

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
  };

  private protectPageApi: ProtectPageApi = async (
    req,
    res,
    handler,
    options
  ) => {
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
      if (options.onAccessDenied) {
        return options.onAccessDenied(req, res, session.user);
      }

      return res.status(403).json({
        message: 'forbidden',
      });
    }

    return handler(req, res);
  };

  /**
   * Middleware factory that protects routes and handles authentication globally.
   */
  public authMiddleware: MonoCloudMiddleware = (...args: unknown[]) => {
    let req: NextRequest | undefined;
    let evt: NextFetchEvent | undefined;
    let options: MonoCloudMiddlewareOptions | undefined;

    /* v8 ignore else -- @preserve */
    if (Array.isArray(args)) {
      if (args.length === 2) {
        /* v8 ignore else -- @preserve */
        if (isAppRouter(args[0] as NextAnyRequest)) {
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
  };

  private async authMiddlewareHandler(
    req: NextRequest,
    evt: NextFetchEvent,
    options?: MonoCloudMiddlewareOptions
  ): Promise<NextMiddlewareResult> {
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

      const request = new MonoCloudAppRouterRequest(req, { params: {} });
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

    const onAccessDenied = options?.onAccessDenied;

    if (
      allowedGroups &&
      !isUserInGroup(session.user, allowedGroups, groupsClaim)
    ) {
      if (onAccessDenied) {
        const result = await onAccessDenied(req, evt, session.user);

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
   * Retrieves the session data associated with the current user.
   *
   */
  public getSession: BaseFuncHandler<MonoCloudSession | undefined> =
    this.resolveFunction<MonoCloudSession | undefined>(
      this.resolvedGetSession.bind(this)
    );

  /**
   * Retrieves the tokens associated with the current session.
   *
   */
  public getTokens: FuncHandler<MonoCloudTokens, GetTokensOptions> =
    this.resolveFunction<MonoCloudTokens, GetTokensOptions>(
      this.resolvedGetTokens.bind(this)
    );

  /**
   * Checks if the current user is authenticated.
   *
   */
  public isAuthenticated: BaseFuncHandler<boolean> =
    this.resolveFunction<boolean>(this.resolvedIsAuthenticated.bind(this));

  /**
   * Redirects the user to sign-in if not authenticated.
   *
   * **Note: This function only works on App Router.**
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
      throw new Error('protect() can only be used in App Router project');
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

    redirect(signInRoute.toString());
  }

  /**
   * @param req - The Next.js request object.
   * @param ctx - The context object, which can be either an AppRouterContext or a NextResponse.
   * @param groups - A list of group IDs or names specifying the groups the user must belong to.
   * @param options - Additional options passed to the function.
   *
   * @returns A promise of the result.
   */
  isUserInGroup(
    req: NextRequest,
    ctx: AppRouterContext | NextResponse,
    groups: string[],
    options?: IsUserInGroupOptions
  ): Promise<boolean>;

  /**
   * @param req - The Next.js API request object.
   * @param res - The Next.js API response object.
   * @param groups - A list of group IDs or names specifying the groups the user must belong to.
   * @param options - Additional options passed to the function.
   *
   * @returns A promise of the result.
   */
  isUserInGroup(
    req: NextApiRequest,
    res: NextApiResponse,
    groups: string[],
    options?: IsUserInGroupOptions
  ): Promise<boolean>;

  /**
   * @param req - The generic Next.js request object.
   * @param res - The generic Next.js response object.
   * @param groups - A list of group IDs or names specifying the groups the user must belong to.
   * @param options - Additional options passed to the function.
   *
   * @returns A promise of the result.
   */
  isUserInGroup(
    req: NextAnyRequest,
    res: NextAnyResponse,
    groups: string[],
    options?: IsUserInGroupOptions
  ): Promise<boolean>;

  /**
   * @param groups - A list of group IDs or names specifying the groups the user must belong to.
   * @param options - Additional options passed to the function.
   *
   * @returns A promise of the result.
   */
  isUserInGroup(
    groups: string[],
    options?: IsUserInGroupOptions
  ): Promise<boolean>;

  public async isUserInGroup(...args: any[]): Promise<boolean> {
    let request: IMonoCloudCookieRequest | undefined;
    let response: IMonoCloudCookieResponse | undefined;
    let groups: string[] | undefined;
    let options: IsUserInGroupOptions | undefined;

    if (args.length === 4) {
      const req = args[0] as NextApiRequest | NextRequest;
      const res = args[1] as NextApiResponse | AppRouterContext;
      groups = args[2] as string[];
      options = args[3] as IsUserInGroupOptions;

      const reqRes = getMonoCloudReqRes(req, res);

      ({ request } = reqRes);
      ({ response } = reqRes);
    }

    if (args.length === 3) {
      const req = args[0] as NextApiRequest | NextRequest;
      const res = args[1] as NextApiResponse | AppRouterContext;
      groups = args[2] as string[];

      const reqRes = getMonoCloudReqRes(req, res);

      ({ request } = reqRes);
      ({ response } = reqRes);
    }

    if (args.length === 2) {
      request = new MonoCloudCookieRequest();
      response = new MonoCloudCookieResponse();

      groups = args[0] as string[];
      options = args[1] as IsUserInGroupOptions;
    }

    if (args.length === 1) {
      request = new MonoCloudCookieRequest();
      response = new MonoCloudCookieResponse();

      groups = args[0] as string[];
    }

    if (!Array.isArray(groups) || !request || !response) {
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
   * Redirects the user to the sign-in route.
   *
   * This helper is intended for **App Router** only (server components,
   * route handlers, server actions). It constructs the MonoCloud sign-in URL
   * with optional parameters and issues a framework redirect.
   *
   * @throws Error if used outside of an App Router context.
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
        'redirectToSignIn() can only be used in App Router project'
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

    redirect(signInRoute.toString());
  }

  /**
   * Redirects the user to the sign-out route.
   *
   * This helper is intended for **App Router** only. It builds the sign-out
   * URL and optionally attaches a `post_logout_redirect_uri` override.
   *
   * @throws Error if used outside of an App Router context.
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
        'redirectToSignOut() can only be used in App Router project'
      );
    }

    const signOutRoute = new URL(`${appUrl}${routes.signOut}`);

    if (options?.postLogoutRedirectUri?.trim().length) {
      signOutRoute.searchParams.set(
        'post_logout_url',
        options.postLogoutRedirectUri
      );
    }

    redirect(signOutRoute.toString());
  }

  private resolveFunction<TResult, TOptions = any>(
    baseHandler: (
      req?: NextAnyRequest,
      resOrCtx?: NextAnyResponse,
      options?: TOptions
    ) => Promise<TResult>
  ): FuncHandler<TResult, TOptions> {
    return ((...args) => {
      if (args.length === 3) {
        const req = args[0] as NextApiRequest | NextRequest;
        const res = args[1] as NextApiResponse | AppRouterContext;
        const options = args[2] as TOptions;
        return baseHandler(req, res, options);
      }

      if (args.length === 2) {
        const req = args[0] as NextApiRequest | NextRequest;
        const res = args[1] as NextApiResponse | AppRouterContext;
        return baseHandler(req, res);
      }

      if (args.length === 1) {
        const options = args[0] as TOptions;
        return baseHandler(undefined, undefined, options);
      }

      return baseHandler();
    }) as FuncHandler<TResult, TOptions>;
  }

  private resolvedGetSession(
    req?: NextAnyRequest,
    resOrCtx?: NextAnyResponse
  ): Promise<MonoCloudSession | undefined> {
    let request: IMonoCloudCookieRequest;
    let response: IMonoCloudCookieResponse;

    if (req && resOrCtx) {
      const result = getMonoCloudReqRes(req, resOrCtx);
      ({ request } = result);
      ({ response } = result);
    } else {
      request = new MonoCloudCookieRequest();
      response = new MonoCloudCookieResponse();
    }

    return this.coreClient.getSession(request, response);
  }

  private resolvedGetTokens(
    req?: NextAnyRequest,
    resOrCtx?: NextAnyResponse,
    options?: GetTokensOptions
  ): Promise<MonoCloudTokens> {
    let request: IMonoCloudCookieRequest;
    let response: IMonoCloudCookieResponse;

    if (req && resOrCtx) {
      const result = getMonoCloudReqRes(req, resOrCtx);
      ({ request } = result);
      ({ response } = result);
    } else {
      request = new MonoCloudCookieRequest();
      response = new MonoCloudCookieResponse();
    }

    return this.coreClient.getTokens(request, response, options);
  }

  private resolvedIsAuthenticated(
    req?: NextAnyRequest,
    resOrCtx?: NextAnyResponse
  ): Promise<boolean> {
    let request: IMonoCloudCookieRequest;
    let response: IMonoCloudCookieResponse;

    if (req && resOrCtx) {
      const result = getMonoCloudReqRes(req, resOrCtx);
      ({ request } = result);
      ({ response } = result);
    } else {
      request = new MonoCloudCookieRequest();
      response = new MonoCloudCookieResponse();
    }

    return this.coreClient.isAuthenticated(request, response);
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
