import type { ParsedUrlQuery } from 'node:querystring';
import { MonoCloudNextClient } from './monocloud-next-client';
import type {
  AppRouterApiHandlerFn,
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
import type {
  NextMiddleware,
  NextProxy,
  NextRequest,
  NextFetchEvent,
  NextResponse,
} from 'next/server';
import type { MonoCloudSession } from '@monocloud/auth-core';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { NextApiHandler, NextApiRequest, NextApiResponse } from 'next';
import type {
  GetTokensOptions,
  MonoCloudTokens,
} from '@monocloud/auth-node-core';

let instance: MonoCloudNextClient | undefined;

/**
 * Retrieves the singleton instance of the MonoCloudNextClient.
 * Initializes it lazily on the first call.
 */
const getInstance = (): MonoCloudNextClient => {
  instance ??= new MonoCloudNextClient();
  return instance;
};

/**
 * Creates a Next.js catch-all auth route handler (Pages Router and App Router) for the built-in routes (`/signin`, `/callback`, `/userinfo`, `/signout`).
 *
 * Mount this handler on a catch-all route (e.g. `/api/auth/[...monocloud]`).
 *
 * > If you already use `authMiddleware()`, you typically don’t need this handler. Use `monoCloudAuth()` when middleware cannot be used or when auth routes need customization.
 *
 * @example App Router
 * ```tsx:src/app/api/auth/[...monocloud]/route.ts tab="App Router" tab-group="monoCloudAuth"
 * import { monoCloudAuth } from "@monocloud/auth-nextjs";
 *
 * export const GET = monoCloudAuth();
 *```
 *
 * @example App Router (Response)
 * ```tsx:src/app/api/auth/[...monocloud]/route.ts tab="App Router (Response)" tab-group="monoCloudAuth"
 * import { monoCloudAuth } from "@monocloud/auth-nextjs";
 * import { NextRequest, NextResponse } from "next/server";
 *
 * export const GET = (req: NextRequest) => {
 *   const authHandler = monoCloudAuth();
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
 * ```tsx:src/pages/api/auth/[...monocloud].ts tab="Pages Router" tab-group="monoCloudAuth"
 * import { monoCloudAuth } from "@monocloud/auth-nextjs";
 *
 * export default monoCloudAuth();
 *```
 *
 * @example Pages Router (Response)
 * ```tsx:src/pages/api/auth/[...monocloud].ts tab="Pages Router (Response)" tab-group="monoCloudAuth"
 * import { monoCloudAuth } from "@monocloud/auth-nextjs";
 * import { NextApiRequest, NextApiResponse } from "next";
 *
 * export default function handler(req: NextApiRequest, res: NextApiResponse) {
 *   const authHandler = monoCloudAuth();
 *
 *   res.setHeader("last_auth_requested", `${Date.now()}`);
 *
 *   return authHandler(req, res);
 * }
 * ```
 *
 * @param options Optional configuration for the auth handler.
 * @returns Returns a Next.js-compatible handler for App Router route handlers or Pages Router API routes.
 *
 * @category Functions
 */
export function monoCloudAuth(
  options?: MonoCloudAuthOptions
): MonoCloudAuthHandler {
  return getInstance().monoCloudAuth(options);
}

/**
 * Creates a Next.js authentication middleware that protects routes.
 *
 * By default, all routes matched by `config.matcher` are protected unless configured otherwise.
 *
 * @example Protect All Routes
 * ```tsx:src/proxy.ts tab="Protect All Routes" tab-group="auth-middleware"
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
 * @example Protect Selected Routes
 * ```tsx:src/proxy.ts tab="Protect Selected Routes" tab-group="auth-middleware"
 * import { authMiddleware } from "@monocloud/auth-nextjs";
 *
 * export default authMiddleware({
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
 * @example No Protected Routes
 * ```tsx:src/proxy.ts tab="No Protected Routes" tab-group="auth-middleware"
 * import { authMiddleware } from "@monocloud/auth-nextjs";
 *
 * export default authMiddleware({
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
 * @example Dynamic
 * ```tsx:src/proxy.ts tab="Dynamic" tab-group="auth-middleware"
 * import { authMiddleware } from "@monocloud/auth-nextjs";
 *
 * export default authMiddleware({
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
 * @example Group Protection
 * ```tsx:src/proxy.ts tab="Group Protection" tab-group="auth-middleware"
 * import { authMiddleware } from "@monocloud/auth-nextjs";
 *
 * export default authMiddleware({
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
 * @param options Optional configuration that controls how authentication is enforced (for example, redirect behavior, route matching, or custom handling of unauthenticated requests).
 * @returns Returns a Next.js middleware result, such as a NextResponse, redirect, or undefined to continue processing.
 *
 * @category Functions
 */
export function authMiddleware(
  options?: MonoCloudMiddlewareOptions
): NextMiddleware | NextProxy;

/**
 * Executes the authentication middleware manually.
 *
 * Intended for advanced scenarios where the middleware is composed within custom logic.
 *
 * @example Composing with custom middleware
 *
 * ```tsx:src/proxy.ts title="Composing with custom middleware"
 * import { authMiddleware } from "@monocloud/auth-nextjs";
 * import { NextFetchEvent, NextRequest, NextResponse } from "next/server";
 *
 * export default function customMiddleware(req: NextRequest, evt: NextFetchEvent) {
 *   if (req.nextUrl.pathname.startsWith("/api/protected")) {
 *     return authMiddleware(req, evt);
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
 * @param request Incoming Next.js middleware request used to resolve authentication state.
 * @param event Next.js middleware event providing lifecycle hooks such as `waitUntil`.
 * @returns Returns a Next.js middleware result (`NextResponse`, redirect, or `undefined` to continue processing).
 *
 * @category Functions
 */
export function authMiddleware(
  request: NextRequest,
  event: NextFetchEvent
): Promise<NextMiddlewareResult> | NextMiddlewareResult;

export function authMiddleware(
  ...args: any[]
):
  | NextMiddleware
  | NextProxy
  | Promise<NextMiddlewareResult>
  | NextMiddlewareResult {
  return getInstance().authMiddleware(...args);
}

/**
 * Retrieves the current user's session using the active server request context.
 *
 * Intended for Server Components, Server Actions, Route Handlers, and Middleware where the request is implicitly available.
 *
 * @example Server Component
 * ```tsx:src/app/page.tsx tab="Server Component" tab-group="session-ssr"
 * import { getSession } from "@monocloud/auth-nextjs";
 *
 * export default async function Home() {
 *   const session = await getSession();
 *
 *   return <div>{session?.user.name}</div>;
 * }
 * ```
 *
 * @example Server Action
 * ```tsx:src/action.ts tab="Server Action" tab-group="session-ssr"
 * "use server";
 *
 * import { getSession } from "@monocloud/auth-nextjs";
 *
 * export async function getUserAction() {
 *   const session = await getSession();
 *
 *   return { name: session?.user.name };
 * }
 * ```
 *
 * @example API Handler
 * ```tsx:src/app/api/user/route.ts tab="API Handler" tab-group="session-ssr"
 * import { getSession } from "@monocloud/auth-nextjs";
 * import { NextResponse } from "next/server";
 *
 * export const GET = async () => {
 *   const session = await getSession();
 *
 *   return NextResponse.json({ name: session?.user.name });
 * };
 * ```
 *
 * @example Middleware
 * ```tsx:src/proxy.ts tab="Middleware" tab-group="session-ssr"
 * import { getSession } from "@monocloud/auth-nextjs";
 * import { NextResponse } from "next/server";
 *
 * export default async function proxy() {
 *   const session = await getSession();
 *
 *   if (!session) {
 *     return new NextResponse("User not signed in", { status: 401 });
 *   }
 *
 *   return NextResponse.next();
 * }
 * ```
 *
 * @returns Returns the resolved session, or `undefined` if none exists.
 *
 * @category Functions
 */
export function getSession(): Promise<MonoCloudSession | undefined>;

/**
 * Retrieves the current user's session using an explicit Web or Next.js request.
 *
 * Use this overload when you already have access to a `Request` or `NextRequest` (for example in Middleware or Route Handlers).
 *
 * @example Middleware (Request)
 * ```tsx:src/proxy.ts tab="Middleware (Request)" tab-group="session-route-handler"
 * import { getSession } from "@monocloud/auth-nextjs";
 * import { NextRequest, NextResponse } from "next/server";
 *
 * export default async function proxy(req: NextRequest) {
 *   const session = await getSession(req);
 *
 *   if (!session) {
 *     return new NextResponse("User not signed in", { status: 401 });
 *   }
 *
 *   return NextResponse.next();
 * }
 * ```
 *
 * @example Middleware (Response)
 * ```tsx:src/proxy.ts tab="Middleware (Response)" tab-group="session-route-handler"
 * import { getSession } from "@monocloud/auth-nextjs";
 * import { NextRequest, NextResponse } from "next/server";
 *
 * export default async function proxy(req: NextRequest) {
 *   const res = NextResponse.next();
 *
 *   const session = await getSession(req, res);
 *
 *   if (!session) {
 *     return new NextResponse("User not signed in", { status: 401 });
 *   }
 *
 *   res.headers.set("x-auth-status", "active");
 *
 *   return res;
 * }
 * ```
 *
 * @example API Handler (Request)
 * ```tsx:src/app/api/user/route.ts tab="API Handler (Request)" tab-group="session-route-handler"
 * import { getSession } from "@monocloud/auth-nextjs";
 * import { NextRequest, NextResponse } from "next/server";
 *
 * export const GET = async (req: NextRequest) => {
 *   const session = await getSession(req);
 *
 *   return NextResponse.json({ name: session?.user.name });
 * };
 * ```
 *
 * @example API Handler (Response)
 * ```tsx:src/app/api/user/route.ts tab="API Handler (Response)" tab-group="session-route-handler"
 * import { getSession } from "@monocloud/auth-nextjs";
 * import { NextRequest, NextResponse } from "next/server";
 *
 * export const GET = async (req: NextRequest) => {
 *   const res = new NextResponse("YOUR CUSTOM RESPONSE");
 *
 *   const session = await getSession(req, res);
 *
 *   if (session?.user) {
 *     res.cookies.set("something", "important");
 *   }
 *
 *   return res;
 * };
 * ```
 *
 * @param req Incoming request used to read authentication cookies and headers to resolve the current user's session.
 * @param res Optional response to update if session resolution requires refreshed authentication cookies or headers.
 * @returns Returns the resolved session, or `undefined` if none exists.
 *
 * @category Functions
 */
export function getSession(
  req: NextRequest | Request,
  res?: NextResponse | Response
): Promise<MonoCloudSession | undefined>;

/**
 * Retrieves the current user's session in the Pages Router or Node.js runtime.
 *
 * Use this overload in API routes or `getServerSideProps`, where Node.js request and response objects are available.
 *
 * @example Pages Router (Pages)
 * ```tsx:src/pages/index.tsx tab="Pages Router (Pages)" tab-group="session-pages"
 * import { getSession, MonoCloudSession } from "@monocloud/auth-nextjs";
 * import { GetServerSideProps } from "next";
 *
 * type Props = {
 *   session?: MonoCloudSession;
 * };
 *
 * export default function Home({ session }: Props) {
 *   return <pre>Session: {JSON.stringify(session, null, 2)}</pre>;
 * }
 *
 * export const getServerSideProps: GetServerSideProps<Props> = async (ctx) => {
 *   const session = await getSession(ctx.req, ctx.res);
 *
 *   return {
 *     props: {
 *       session
 *     }
 *   };
 * };
 * ```
 * @example Pages Router (API)
 * ```tsx:src/pages/api/user.ts tab="Pages Router (API)" tab-group="session-pages"
 * import { getSession } from "@monocloud/auth-nextjs";
 * import { NextApiRequest, NextApiResponse } from "next";
 *
 * export default async function handler(
 *   req: NextApiRequest,
 *   res: NextApiResponse
 * ) {
 *   const session = await getSession(req, res);
 *
 *   res.status(200).json({ name: session?.user.name });
 * }
 * ```
 *
 * @param req Incoming Node.js request used to read authentication cookies and resolve the current user's session.
 * @param res Outgoing Node.js response used to apply refreshed authentication cookies when required.
 * @returns Returns the resolved session, or `undefined` if none exists.
 *
 * @category Functions
 */
export function getSession(
  req: NextApiRequest | IncomingMessage,
  res: NextApiResponse | ServerResponse<IncomingMessage>
): Promise<MonoCloudSession | undefined>;

export function getSession(
  ...args: any[]
): Promise<MonoCloudSession | undefined> {
  return (getInstance().getSession as any)(...args);
}

/**
 * Retrieves the current user's tokens using the active server request context.
 *
 * @example Server Component
 * ```tsx:src/app/page.tsx tab="Server Component" tab-group="tokens-ssr"
 * import { getTokens } from "@monocloud/auth-nextjs";
 *
 * export default async function Home() {
 *   const tokens = await getTokens();
 *
 *   return <div>Expired: {tokens.isExpired.toString()}</div>;
 * }
 * ```
 *
 * @example Server Action
 * ```tsx:src/action.ts tab="Server Action" tab-group="tokens-ssr"
 * "use server";
 *
 * import { getTokens } from "@monocloud/auth-nextjs";
 *
 * export async function getExpiredAction() {
 *   const tokens = await getTokens();
 *
 *   return { expired: tokens.isExpired };
 * }
 * ```
 *
 * @example API Handler
 * ```tsx:src/app/api/tokens/route.ts tab="API Handler" tab-group="tokens-ssr"
 * import { getTokens } from "@monocloud/auth-nextjs";
 * import { NextResponse } from "next/server";
 *
 * export const GET = async () => {
 *   const tokens = await getTokens();
 *
 *   return NextResponse.json({ expired: tokens.isExpired });
 * };
 * ```
 *
 * @example Middleware
 * ```tsx:src/proxy.ts tab="Middleware" tab-group="tokens-ssr"
 * import { getTokens } from "@monocloud/auth-nextjs";
 * import { NextResponse } from "next/server";
 *
 * export default async function proxy() {
 *   const tokens = await getTokens();
 *
 *   if (tokens.isExpired) {
 *     return new NextResponse("Tokens expired", { status: 401 });
 *   }
 *
 *   return NextResponse.next();
 * }
 * ```
 *
 * @example Refresh the default token
 *
 * The **default token** is the access token associated with your default authorization parameters:
 * - Scopes: `MONOCLOUD_AUTH_SCOPES` or `options.defaultAuthParams.scopes`
 * - Resource: `MONOCLOUD_AUTH_RESOURCE` or `options.defaultAuthParams.resource`
 *
 * Calling `getTokens()` returns the current token set and **refreshes the default token automatically when needed** (for example, if it has expired). To force a refresh even when it isn’t expired, use `forceRefresh: true`.
 *
 * ```tsx:src/app/page.tsx title="Refresh default token"
 * import { getTokens } from "@monocloud/auth-nextjs";
 * import { NextResponse } from "next/server";
 *
 * export const GET = async () => {
 *   // Forces a refresh of the default token
 *   const tokens = await getTokens({ forceRefresh: true });
 *
 *   return NextResponse.json({ accessToken: tokens?.accessToken });
 * };
 * ```
 *
 * @example Request an access token for resource(s)
 *
 * Use `resource` and `scopes` to request an access token for one or more resources.
 *
 * > The requested resource and scopes must be included in the initial authorization flow (so the user has consented / the session is eligible to mint that token).
 *
 * ```tsx:src/app/page.tsx title="Request a new access token for resource(s)"
 * import { getTokens } from "@monocloud/auth-nextjs";
 * import { NextResponse } from "next/server";
 *
 * export const GET = async () => {
 *   const tokens = await getTokens({
 *     resource: "https://first.example.com https://second.example.com",
 *     scopes: "read:first read:second shared",
 *   });
 *
 *   return NextResponse.json({ accessToken: tokens?.accessToken });
 * };
 * ```
 *
 * @param options Optional configuration controlling refresh behavior and resource/scope selection.
 * @returns The current user's tokens, refreshed if necessary.
 * @throws {@link MonoCloudValidationError} If no valid session exists.
 *
 * @category Functions
 */
export function getTokens(options?: GetTokensOptions): Promise<MonoCloudTokens>;

/**
 * Retrieves the current user's tokens using an explicit Web or Next.js request.
 *
 * Use this overload when you already have access to a `Request` or `NextRequest` (for example, in Middleware or Route Handlers).
 *
 * @example Middleware (Request)
 * ```tsx:src/proxy.ts tab="Middleware (Request)" tab-group="tokens-route-handler-request"
 * import { getTokens } from "@monocloud/auth-nextjs";
 * import { NextRequest, NextResponse } from "next/server";
 *
 * export default async function proxy(req: NextRequest) {
 *   const tokens = await getTokens(req);
 *
 *   if (tokens.isExpired) {
 *     return new NextResponse("Tokens expired", { status: 401 });
 *   }
 *
 *   return NextResponse.next();
 * }
 * ```
 *
 * @example API Handler (Request)
 * ```tsx:src/app/api/tokens/route.ts tab="API Handler (Request)" tab-group="tokens-route-handler-request"
 * import { getTokens } from "@monocloud/auth-nextjs";
 * import { NextRequest, NextResponse } from "next/server";
 *
 * export const GET = async (req: NextRequest) => {
 *   const tokens = await getTokens(req);
 *
 *   return NextResponse.json({ expired: tokens?.isExpired });
 * };
 * ```
 *
 * @param req Incoming request used to resolve authentication from cookies and headers.
 * @param options Optional configuration controlling refresh behavior and resource/scope selection.
 * @returns The current user's tokens, refreshed if necessary.
 * @throws {@link MonoCloudValidationError} If no valid session exists.
 *
 * @category Functions
 */
export function getTokens(
  req: NextRequest | Request,
  options?: GetTokensOptions
): Promise<MonoCloudTokens>;

/**
 * Retrieves the current user's tokens using an explicit request and response.
 *
 * Use this overload when you have already created a response and want refreshed authentication cookies or headers applied to it.
 *
 * @example Middleware (Response)
 *```tsx:src/proxy.ts tab="Middleware (Response)" tab-group="tokens-route-handler-response"
 * import { getTokens } from "@monocloud/auth-nextjs";
 * import { NextRequest, NextResponse } from "next/server";
 *
 * export default async function proxy(req: NextRequest) {
 *   const res = NextResponse.next();
 *
 *   const tokens = await getTokens(req, res);
 *
 *   res.headers.set("x-tokens-expired", tokens.isExpired.toString());
 *
 *   return res;
 * }
 * ```
 *
 * @example API Handler (Response)
 * ```tsx:src/app/api/tokens/route.ts tab="API Handler (Response)" tab-group="tokens-route-handler-response"
 * import { getTokens } from "@monocloud/auth-nextjs";
 * import { NextRequest, NextResponse } from "next/server";
 *
 * export const GET = async (req: NextRequest) => {
 *   const res = new NextResponse("Custom Body");
 *
 *   const tokens = await getTokens(req, res);
 *
 *   if (!tokens.isExpired) {
 *     res.headers.set("x-auth-status", "active");
 *   }
 *
 *   return res;
 * };
 * ```
 *
 * @param req Incoming request used to resolve authentication from cookies and headers.
 * @param res Existing response to update with refreshed authentication cookies or headers.
 * @param options Optional configuration controlling refresh behavior and resource/scope selection.
 * @returns The current user's tokens, refreshed if necessary.
 * @throws {@link MonoCloudValidationError} If no valid session exists.
 *
 * @category Functions
 */
export function getTokens(
  req: NextRequest | Request,
  res: NextResponse | Response,
  options?: GetTokensOptions
): Promise<MonoCloudTokens>;

/**
 * Retrieves the current user's tokens in the Pages Router or Node.js runtime.
 *
 * Use this overload in API routes or `getServerSideProps`, where Node.js request and response objects are available.
 *
 * @example Pages Router (Pages)
 * ```tsx:src/pages/index.tsx tab="Pages Router (Pages)" tab-group="tokens-pages"
 * import { getTokens, MonoCloudTokens } from "@monocloud/auth-nextjs";
 * import { GetServerSideProps } from "next";
 *
 * type Props = {
 *   tokens: MonoCloudTokens;
 * };
 *
 * export default function Home({ tokens }: Props) {
 *   return <pre>Tokens: {JSON.stringify(tokens, null, 2)}</pre>;
 * }
 *
 * export const getServerSideProps: GetServerSideProps<Props> = async (ctx) => {
 *   const tokens = await getTokens(ctx.req, ctx.res);
 *
 *   return {
 *     props: {
 *       tokens: tokens
 *     }
 *   };
 * };
 * ```
 *
 * @example Pages Router (API)
 * ```tsx:src/pages/api/tokens.ts tab="Pages Router (API)" tab-group="tokens-pages"
 * import { getTokens } from "@monocloud/auth-nextjs";
 * import { NextApiRequest, NextApiResponse } from "next";
 *
 * export default async function handler(
 *   req: NextApiRequest,
 *   res: NextApiResponse
 * ) {
 *   const tokens = await getTokens(req, res);
 *
 *   res.status(200).json({ accessToken: tokens?.accessToken });
 * }
 * ```
 *
 * @param req Incoming Node.js request used to resolve authentication from cookies.
 * @param res Outgoing Node.js response used to apply refreshed authentication cookies when required.
 * @param options Optional configuration controlling refresh behavior and resource/scope selection.
 * @returns The current user's tokens, refreshed if necessary.
 * @throws {@link MonoCloudValidationError} If no valid session exists.
 *
 * @category Functions
 */
export function getTokens(
  req: NextApiRequest | IncomingMessage,
  res: NextApiResponse | ServerResponse<IncomingMessage>,
  options?: GetTokensOptions
): Promise<MonoCloudTokens>;

export function getTokens(...args: any[]): Promise<MonoCloudTokens> {
  return getInstance().getTokens(...args);
}

/**
 * Checks whether the current user is authenticated using the active server request context.
 *
 * Intended for Server Components, Server Actions, Route Handlers, and Middleware where the request is implicitly available.
 *
 * @example Server Component
 * ```tsx:src/app/page.tsx tab="Server Component" tab-group="is-authenticated-ssr"
 * import { isAuthenticated } from "@monocloud/auth-nextjs";
 *
 * export default async function Home() {
 *   const authenticated = await isAuthenticated();
 *
 *   return <div>Authenticated: {authenticated.toString()}</div>;
 * }
 * ```
 *
 * @example Server Action
 * ```tsx:src/action.ts tab="Server Action" tab-group="is-authenticated-ssr"
 * "use server";
 *
 * import { isAuthenticated } from "@monocloud/auth-nextjs";
 *
 * export async function checkAuthAction() {
 *   const authenticated = await isAuthenticated();
 *
 *   return { authenticated };
 * }
 * ```
 *
 * @example API Handler
 * ```tsx:src/app/api/authenticated/route.ts tab="API Handler" tab-group="is-authenticated-ssr"
 * import { isAuthenticated } from "@monocloud/auth-nextjs";
 * import { NextResponse } from "next/server";
 *
 * export const GET = async () => {
 *   const authenticated = await isAuthenticated();
 *
 *   return NextResponse.json({ authenticated });
 * };
 * ```
 *
 * @example Middleware
 * ```tsx:src/proxy.ts tab="Middleware" tab-group="is-authenticated-ssr"
 * import { isAuthenticated } from "@monocloud/auth-nextjs";
 * import { NextResponse } from "next/server";
 *
 * export default async function proxy() {
 *   const authenticated = await isAuthenticated();
 *
 *   if (!authenticated) {
 *     return new NextResponse("User not signed in", { status: 401 });
 *   }
 *
 *   return NextResponse.next();
 * }
 * ```
 *
 * @returns Returns `true` if a valid session exists; otherwise `false`.
 *
 * @category Functions
 */
export function isAuthenticated(): Promise<boolean>;

/**
 * Checks whether the current user is authenticated using an explicit Web or Next.js request.
 *
 * Use this overload when you already have access to a `Request` or `NextRequest` (for example, in Middleware or Route Handlers).
 *
 * @example Middleware (Request)
 * ```tsx:src/proxy.ts tab="Middleware (Request)" tab-group="is-authenticated-route-handler"
 * import { isAuthenticated } from "@monocloud/auth-nextjs";
 * import { NextRequest, NextResponse } from "next/server";
 *
 * export default async function proxy(req: NextRequest) {
 *   const authenticated = await isAuthenticated(req);
 *
 *   if (!authenticated) {
 *     return new NextResponse("User not signed in", { status: 401 });
 *   }
 *
 *   return NextResponse.next();
 * }
 * ```
 *
 * @example Middleware (Response)
 * ```tsx:src/proxy.ts tab="Middleware (Response)" tab-group="is-authenticated-route-handler"
 * import { isAuthenticated } from "@monocloud/auth-nextjs";
 * import { NextRequest, NextResponse } from "next/server";
 *
 * export default async function proxy(req: NextRequest) {
 *   const res = NextResponse.next();
 *
 *   const authenticated = await isAuthenticated(req, res);
 *
 *   if (!authenticated) {
 *     return new NextResponse("User not signed in", { status: 401 });
 *   }
 *
 *   res.headers.set("x-authenticated", "true");
 *
 *   return res;
 * }
 * ```
 *
 * @example API Handler (Request)
 * ```tsx:src/app/api/authenticated/route.ts tab="API Handler (Request)" tab-group="is-authenticated-route-handler"
 * import { isAuthenticated } from "@monocloud/auth-nextjs";
 * import { NextRequest, NextResponse } from "next/server";
 *
 * export const GET = async (req: NextRequest) => {
 *   const authenticated = await isAuthenticated(req);
 *
 *   return NextResponse.json({ authenticated });
 * };
 * ```
 *
 * @example API Handler (Response)
 * ```tsx:src/app/api/authenticated/route.ts tab="API Handler (Response)" tab-group="is-authenticated-route-handler"
 * import { isAuthenticated } from "@monocloud/auth-nextjs";
 * import { NextRequest, NextResponse } from "next/server";
 *
 * export const GET = async (req: NextRequest) => {
 *   const res = new NextResponse("YOUR CUSTOM RESPONSE");
 *
 *   const authenticated = await isAuthenticated(req, res);
 *
 *   if (authenticated) {
 *     res.cookies.set("something", "important");
 *   }
 *
 *   return res;
 * };
 * ```
 *
 * @param req Incoming request used to resolve authentication from cookies and headers.
 * @param res Optional response to update if refreshed authentication cookies or headers are required.
 * @returns Returns `true` if a valid session exists; otherwise `false`.
 *
 * @category Functions
 */
export function isAuthenticated(
  req: NextRequest | Request,
  res?: NextResponse | Response
): Promise<boolean>;

/**
 * Checks whether the current user is authenticated in the Pages Router or Node.js runtime.
 *
 * Use this overload in API routes or `getServerSideProps`, where Node.js request and response objects are available.
 *
 * @example Pages Router (Pages)
 * ```tsx:src/pages/index.tsx tab="Pages Router (Pages)" tab-group="is-authenticated-pages"
 * import { isAuthenticated } from "@monocloud/auth-nextjs";
 * import { GetServerSideProps } from "next";
 *
 * type Props = {
 *   authenticated: boolean;
 * };
 *
 * export default function Home({ authenticated }: Props) {
 *   return <pre>User is {authenticated ? "logged in" : "guest"}</pre>;
 * }
 *
 * export const getServerSideProps: GetServerSideProps<Props> = async (ctx) => {
 *   const authenticated = await isAuthenticated(ctx.req, ctx.res);
 *
 *   return {
 *     props: {
 *       authenticated
 *     }
 *   };
 * };
 * ```
 *
 * @example Pages Router (API)
 * ```tsx:src/pages/api/authenticated.ts tab="Pages Router (API)" tab-group="is-authenticated-pages"
 * import { isAuthenticated } from "@monocloud/auth-nextjs";
 * import { NextApiRequest, NextApiResponse } from "next";
 *
 * export default async function handler(
 *   req: NextApiRequest,
 *   res: NextApiResponse
 * ) {
 *   const authenticated = await isAuthenticated(req, res);
 *
 *   res.status(200).json({ authenticated });
 * }
 * ```
 *
 * @param req Incoming Node.js request used to resolve authentication from cookies.
 * @param res Outgoing Node.js response used to apply refreshed authentication cookies when required.
 * @returns Returns `true` if a valid session exists; otherwise `false`.
 *
 * @category Functions
 */
export function isAuthenticated(
  req: NextApiRequest | IncomingMessage,
  res: NextApiResponse | ServerResponse<IncomingMessage>
): Promise<boolean>;

export function isAuthenticated(...args: any[]): Promise<boolean> {
  return (getInstance().isAuthenticated as any)(...args);
}

/**
 * Ensures the current user is authenticated. If not, redirects to the sign-in flow.
 *
 * > **App Router only.** Intended for Server Components, Route Handlers, and Server Actions.
 *
 * @example Server Component
 * ```tsx:src/app/page.tsx tab="Server Component" tab-group="protect"
 * import { protect } from "@monocloud/auth-nextjs";
 *
 * export default async function Home() {
 *   await protect();
 *
 *   return <>You are signed in.</>;
 * }
 * ```
 *
 * @example Server Action
 * ```tsx:src/action.ts tab="Server Action" tab-group="protect"
 * "use server";
 *
 * import { protect } from "@monocloud/auth-nextjs";
 *
 * export async function getMessage() {
 *   await protect();
 *
 *   return { secret: "sssshhhhh!!!" };
 * }
 * ```
 *
 * @example API Handler
 * ```tsx:src/app/api/protected/route.ts tab="API Handler" tab-group="protect"
 * import { protect } from "@monocloud/auth-nextjs";
 * import { NextResponse } from "next/server";
 *
 * export const GET = async () => {
 *   await protect();
 *
 *   return NextResponse.json({ secret: "ssshhhh!!!" });
 * };
 * ```
 *
 * @param options Optional configuration for redirect behavior (for example, return URL or sign-in parameters).
 * @returns Resolves if the user is authenticated; otherwise triggers a redirect.
 *
 * @category Functions
 */
export function protect(options?: ProtectOptions): Promise<void> {
  return getInstance().protect(options);
}

/**
 * Wraps an App Router API route handler and ensures that only authenticated (and optionally authorized) requests can access the route.
 *
 * Intended for Next.js App Router Route Handlers.
 *
 * @example
 * ```tsx:src/app/api/protected/route.ts
 * import { protectApi } from "@monocloud/auth-nextjs";
 * import { NextResponse } from "next/server";
 *
 * export const GET = protectApi(async () => {
 *   return NextResponse.json({
 *     message: "You accessed a protected endpoint",
 *   });
 * });
 * ```
 *
 * @param handler The route handler to protect.
 * @param options Optional configuration controlling authentication and authorization behavior.
 * @returns Returns a wrapped handler that enforces authentication (and optional authorization) before invoking the original handler.
 *
 * @category Functions
 */
export function protectApi(
  handler: AppRouterApiHandlerFn,
  options?: ProtectApiAppOptions
): AppRouterApiHandlerFn;

/**
 * Wraps a Pages Router API route handler and ensures that only authenticated (and optionally authorized) requests can access the route.
 *
 * Intended for Next.js Pages Router API routes.
 *
 * @example
 * ```tsx:src/pages/api/protected.ts
 * import { protectApi } from "@monocloud/auth-nextjs";
 * import { NextApiRequest, NextApiResponse } from "next";
 *
 * export default protectApi(
 *   async (req: NextApiRequest, res: NextApiResponse) => {
 *     return res.json({
 *       message: "You accessed a protected endpoint",
 *     });
 *   }
 * );
 * ```
 *
 * @param handler - The route handler to protect.
 * @param options Optional configuration controlling authentication and authorization behavior.
 * @returns Returns a wrapped handler that enforces authentication (and optional authorization) before invoking the original handler.
 *
 * @category Functions
 */
export function protectApi(
  handler: NextApiHandler,
  options?: ProtectApiPageOptions
): NextApiHandler;

export function protectApi(
  handler: AppRouterApiHandlerFn | NextApiHandler,
  options?: ProtectApiAppOptions | ProtectApiPageOptions
): AppRouterApiHandlerFn | NextApiHandler {
  return (getInstance().protectApi as any)(handler, options);
}

/**
 * Restricts access to App Router server-rendered pages.
 *
 * **Access control**
 * - If the user is not authenticated, `onAccessDenied` is invoked (or default behavior applies).
 * - If the user is authenticated but fails group checks, `onGroupAccessDenied` is invoked (or the default "Access Denied" view is rendered).
 *
 * Both behaviors can be customized via options.
 *
 * @example Basic Usage
 * ```tsx:src/app/page.tsx tab="Basic Usage" tab-group="protectPage-app"
 * import { protectPage } from "@monocloud/auth-nextjs";
 *
 * export default protectPage(async function Home({ user }) {
 *  return <>Hi {user.email}. You accessed a protected page.</>;
 * });
 * ```
 *
 * @example With Options
 * ```tsx:src/app/page.tsx tab="With Options" tab-group="protectPage-app"
 * import { protectPage } from "@monocloud/auth-nextjs";
 *
 * export default protectPage(
 *   async function Home({ user }) {
 *     return <>Hi {user.email}. You accessed a protected page.</>;
 *   },
 *   {
 *     returnUrl: "/dashboard",
 *     groups: ["admin"],
 *   }
 * );
 * ```
 *
 * @param component The App Router server component to protect.
 * @param options Optional configuration for authentication, authorization, and custom access handling (`onAccessDenied`, `onGroupAccessDenied`).
 * @returns A wrapped page component that enforces authentication before rendering.
 *
 * @category Functions
 */
export function protectPage(
  component: ProtectedAppServerComponent,
  options?: ProtectAppPageOptions
): AppRouterPageHandler;

/**
 * Restricts access to Pages Router server-rendered pages using `getServerSideProps`.
 *
 * **Access control**
 * - If the user is not authenticated, `onAccessDenied` is invoked (or default behavior applies).
 * - If the user is authenticated but fails group checks, the page can still render and `groupAccessDenied` is provided in props. Use `onGroupAccessDenied` to customize the props or behavior.
 *
 * Both behaviors can be customized via options.
 *
 * @example Basic Usage
 * ```tsx:src/pages/index.tsx tab="Basic Usage" tab-group="protectPage-page"
 * import { protectPage, MonoCloudUser } from "@monocloud/auth-nextjs";
 *
 * type Props = {
 *   user: MonoCloudUser;
 * };
 *
 * export default function Home({ user }: Props) {
 *   return <>Hi {user.email}. You accessed a protected page.</>;
 * }
 *
 * export const getServerSideProps = protectPage();
 * ```
 *
 * @example With Options
 * ```tsx:src/pages/index.tsx tab="With Options" tab-group="protectPage-page"
 * import { protectPage, MonoCloudUser } from "@monocloud/auth-nextjs";
 * import { GetServerSidePropsContext } from "next";
 *
 * type Props = {
 *   user: MonoCloudUser;
 *   url: string;
 * };
 *
 * export default function Home({ user, url }: Props) {
 *   console.log(url);
 *   return <div>Hi {user?.email}. You accessed a protected page.</div>;
 * }
 *
 * export const getServerSideProps = protectPage({
 *   returnUrl: "/dashboard",
 *   groups: ["admin"],
 *   getServerSideProps: async (context: GetServerSidePropsContext) => ({
 *     props: { url: context.resolvedUrl }
 *   })
 * });
 * ```
 *
 * @param options Optional configuration for authentication, authorization, and custom access handling (`onAccessDenied`, `onGroupAccessDenied`).
 * @typeParam P - Props returned from getServerSideProps.
 * @typeParam Q - Query parameters parsed from the URL.
 * @returns A getServerSideProps wrapper that enforces authentication before executing the page logic.
 *
 * @category Functions
 */
export function protectPage<
  P extends Record<string, any> = Record<string, any>,
  Q extends ParsedUrlQuery = ParsedUrlQuery,
>(options?: ProtectPagePageOptions<P, Q>): ProtectPagePageReturnType<P, Q>;

export function protectPage(...args: any[]): any {
  return getInstance().protectPage(...args);
}

/**
 * Checks whether the currently authenticated user is a member of **any** of the specified groups.
 *
 * The `groups` parameter accepts group identifiers (IDs or names).
 *
 * The authenticated user's session may contain groups represented as:
 * - Group IDs
 * - Group names
 * - `Group` objects (for example, `{ id: string; name: string }`)
 *
 * Matching is always performed against the group's **ID** and **name**, regardless of how the group is represented in the session.
 *
 * @example Server Component
 * ```tsx:src/app/page.tsx tab="Server Component" tab-group="is-user-in-group-rsc"
 * import { isUserInGroup } from "@monocloud/auth-nextjs";
 *
 * export default async function AdminPanel() {
 *   const isAdmin = await isUserInGroup(["admin"]);
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
 * ```tsx:src/action.ts tab="Server Action" tab-group="is-user-in-group-rsc"
 * "use server";
 *
 * import { isUserInGroup } from "@monocloud/auth-nextjs";
 *
 * export async function deletePostAction() {
 *   const canDelete = await isUserInGroup(["admin", "editor"]);
 *
 *   if (!canDelete) {
 *     return { success: false };
 *   }
 *
 *   return { success: true };
 * }
 * ```
 *
 * @example API Handler
 * ```tsx:src/app/api/group-check/route.ts tab="API Handler" tab-group="is-user-in-group-rsc"
 * import { isUserInGroup } from "@monocloud/auth-nextjs";
 * import { NextResponse } from "next/server";
 *
 * export const GET = async () => {
 *   const allowed = await isUserInGroup(["admin", "editor"]);
 *
 *   if (!allowed) {
 *     return new NextResponse("Forbidden", { status: 403 });
 *   }
 *
 *   return NextResponse.json({ status: "success" });
 * };
 * ```
 *
 * @example Middleware
 * ```tsx:src/proxy.ts tab="Middleware" tab-group="is-user-in-group-rsc"
 * import { isUserInGroup } from "@monocloud/auth-nextjs";
 * import { NextResponse } from "next/server";
 *
 * export default async function proxy() {
 *   const isAdmin = await isUserInGroup(["admin"]);
 *
 *   if (!isAdmin) {
 *     return new NextResponse("User is not admin", { status: 403 });
 *   }
 *
 *   return NextResponse.next();
 * }
 * ```
 *
 * @param groups Group IDs or names to check against the user's group memberships.
 * @param options Optional configuration controlling how group membership is evaluated.
 * @returns Returns `true` if the user belongs to at least one specified group; otherwise `false`.
 *
 * @category Functions
 */
export function isUserInGroup(
  groups: string[],
  options?: IsUserInGroupOptions
): Promise<boolean>;

/**
 * Checks group membership using an explicit Web or Next.js request.
 *
 * Use this overload when you already have access to a `Request` or `NextRequest` (for example, in Middleware or Route Handlers).
 *
 * @example Middleware (Request)
 * ```tsx:src/proxy.ts tab="Middleware (Request)" tab-group="is-user-in-group-request"
 * import { isUserInGroup } from "@monocloud/auth-nextjs";
 * import { NextRequest, NextResponse } from "next/server";
 *
 * export default async function proxy(req: NextRequest) {
 *   const isAdmin = await isUserInGroup(req, ["admin"]);
 *
 *   if (!isAdmin) {
 *     return new NextResponse("User is not admin", { status: 403 });
 *   }
 *
 *   return NextResponse.next();
 * }
 * ```
 *
 * @example API Handler (Request)
 * ```tsx:src/app/api/group-check/route.ts tab="API Handler (Request)" tab-group="is-user-in-group-request"
 * import { isUserInGroup } from "@monocloud/auth-nextjs";
 * import { NextRequest, NextResponse } from "next/server";
 *
 * export const GET = async (req: NextRequest) => {
 *   const isMember = await isUserInGroup(req, ["admin", "editor"]);
 *
 *   return NextResponse.json({ isMember });
 * };
 * ```
 *
 * @param req Incoming request used to resolve authentication from cookies and headers.
 * @param groups Group IDs or names to check against the user's group memberships.
 * @param options Optional configuration controlling how group membership is evaluated.
 * @returns Returns `true` if the user belongs to at least one specified group; otherwise `false`.
 *
 * @category Functions
 */
export function isUserInGroup(
  req: NextRequest | Request,
  groups: string[],
  options?: IsUserInGroupOptions
): Promise<boolean>;

/**
 * Checks group membership using an explicit request and response.
 *
 * Use this overload when you have already created a response and want refreshed authentication cookies or headers applied to it.
 *
 * @example Middleware (Response)
 * ```tsx:src/proxy.ts tab="Middleware (Response)" tab-group="is-user-in-group-response"
 * import { isUserInGroup } from "@monocloud/auth-nextjs";
 * import { NextRequest, NextResponse } from "next/server";
 *
 * export default async function proxy(req: NextRequest) {
 *   const res = NextResponse.next();
 *
 *   const isAdmin = await isUserInGroup(req, res, ["admin"]);
 *
 *   if (!isAdmin) {
 *     return new NextResponse("User is not admin", { status: 403 });
 *   }
 *
 *   res.headers.set("x-user", "admin");
 *
 *   return res;
 * }
 * ```
 *
 * @example API Handler (Response)
 * ```tsx:src/app/api/group-check/route.ts tab="API Handler (Response)" tab-group="is-user-in-group-response"
 * import { isUserInGroup } from "@monocloud/auth-nextjs";
 * import { NextRequest, NextResponse } from "next/server";
 *
 * export const GET = async (req: NextRequest) => {
 *   const res = new NextResponse("Restricted Content");
 *
 *   const allowed = await isUserInGroup(req, res, ["admin"]);
 *
 *   if (!allowed) {
 *     return new NextResponse("Not Allowed", res);
 *   }
 *
 *   return res;
 * };
 * ```
 *
 * @param req Incoming request used to resolve authentication from cookies and headers.
 * @param res Existing response to update with refreshed authentication cookies or headers when required.
 * @param groups Group IDs or names to check against the user's group memberships.
 * @param options Optional configuration controlling how group membership is evaluated.
 * @returns Returns `true` if the user belongs to at least one specified group; otherwise `false`.
 *
 * @category Functions
 */
export function isUserInGroup(
  req: NextRequest | Request,
  res: NextResponse | Response,
  groups: string[],
  options?: IsUserInGroupOptions
): Promise<boolean>;

/**
 * Checks group membership in the Pages Router or Node.js runtime.
 *
 * Use this overload in API routes or `getServerSideProps`, where Node.js request and response objects are available.
 *
 * @example Pages Router (Pages)
 * ```tsx:src/pages/index.tsx tab="Pages Router (Pages)" tab-group="is-user-in-group-pages"
 * import { isUserInGroup } from "@monocloud/auth-nextjs";
 * import { GetServerSideProps } from "next";
 *
 * type Props = {
 *   isAdmin: boolean;
 * };
 *
 * export default function Home({ isAdmin }: Props) {
 *   return <div>User is admin: {isAdmin.toString()}</div>;
 * }
 *
 * export const getServerSideProps: GetServerSideProps<Props> = async (ctx) => {
 *   const isAdmin = await isUserInGroup(ctx.req, ctx.res, ["admin"]);
 *
 *   return {
 *     props: {
 *       isAdmin
 *     }
 *   };
 * };
 * ```
 *
 * @example Pages Router (API)
 * ```tsx:src/pages/api/group-check.ts tab="Pages Router (API)" tab-group="is-user-in-group-pages"
 * import { isUserInGroup } from "@monocloud/auth-nextjs";
 * import { NextApiRequest, NextApiResponse } from "next";
 *
 * export default async function handler(
 *   req: NextApiRequest,
 *   res: NextApiResponse
 * ) {
 *   const isAdmin = await isUserInGroup(req, res, ["admin"]);
 *
 *   if (!isAdmin) {
 *     return res.status(403).json({ error: "Forbidden" });
 *   }
 *
 *   res.status(200).json({ message: "Welcome Admin" });
 * }
 * ```
 *
 * @param req Incoming Node.js request used to resolve authentication from cookies.
 * @param res Outgoing Node.js response used to apply refreshed authentication cookies when required.
 * @param groups Group IDs or names to check against the user's group memberships.
 * @param options Optional configuration controlling how group membership is evaluated.
 * @returns Returns `true` if the user belongs to at least one specified group; otherwise `false`.
 *
 * @category Functions
 */
export function isUserInGroup(
  req: NextApiRequest | IncomingMessage,
  res: NextApiResponse | ServerResponse<IncomingMessage>,
  groups: string[],
  options?: IsUserInGroupOptions
): Promise<boolean>;

export function isUserInGroup(...args: any[]): Promise<boolean> {
  return (getInstance().isUserInGroup as any)(...args);
}

/**
 * Redirects the user to the sign-in flow.
 *
 * > **App Router only**. Intended for use in Server Components, Route Handlers, and Server Actions.
 *
 * This helper performs a server-side redirect to the configured sign-in route. Execution does not continue after the redirect is triggered.
 *
 * @example Server Component
 * ```tsx:src/app/page.tsx tab="Server Component" tab-group="redirect-to-sign-in"
 * import { isUserInGroup, redirectToSignIn } from "@monocloud/auth-nextjs";
 *
 * export default async function Home() {
 *   const allowed = await isUserInGroup(["admin"]);
 *
 *   if (!allowed) {
 *     await redirectToSignIn({ returnUrl: "/home" });
 *   }
 *
 *   return <>You are signed in.</>;
 * }
 * ```
 *
 * @example Server Action
 * ```tsx:src/action.ts tab="Server Action" tab-group="redirect-to-sign-in"
 * "use server";
 *
 * import { getSession, redirectToSignIn } from "@monocloud/auth-nextjs";
 *
 * export async function protectedAction() {
 *   const session = await getSession();
 *
 *   if (!session) {
 *     await redirectToSignIn();
 *   }
 *
 *   return { data: "Sensitive Data" };
 * }
 * ```
 *
 * @example API Handler
 * ```tsx:src/app/api/protected/route.ts tab="API Handler" tab-group="redirect-to-sign-in"
 * import { getSession, redirectToSignIn } from "@monocloud/auth-nextjs";
 * import { NextResponse } from "next/server";
 *
 * export const GET = async () => {
 *   const session = await getSession();
 *
 *   if (!session) {
 *     await redirectToSignIn({
 *       returnUrl: "/dashboard",
 *     });
 *   }
 *
 *   return NextResponse.json({ data: "Protected content" });
 * };
 * ```
 *
 * @param options Optional configuration for the redirect, such as `returnUrl` or additional sign-in parameters.
 * @returns Never resolves. Triggers a redirect to the sign-in flow.
 *
 * @category Functions
 */
export function redirectToSignIn(
  options?: RedirectToSignInOptions
): Promise<void> {
  return getInstance().redirectToSignIn(options);
}

/**
 * Redirects the user to the sign-out flow.
 *
 * > **App Router only**. Intended for use in Server Components, Route Handlers, and Server Actions.
 *
 * This helper performs a server-side redirect to the configured sign-out route. Execution does not continue after the redirect is triggered.
 *
 * @example Server Component
 * ```tsx:src/app/page.tsx tab="Server Component" tab-group="redirect-to-sign-out"
 * import { getSession, redirectToSignOut } from "@monocloud/auth-nextjs";
 *
 * export default async function Page() {
 *   const session = await getSession();
 *
 *   // Example: Force sign-out if a specific condition is met (e.g., account suspended)
 *   if (session?.user.isSuspended) {
 *     await redirectToSignOut();
 *   }
 *
 *   return <>Welcome User</>;
 * }
 * ```
 *
 * @example Server Action
 * ```tsx:src/action.ts tab="Server Action" tab-group="redirect-to-sign-out"
 * "use server";
 *
 * import { getSession, redirectToSignOut } from "@monocloud/auth-nextjs";
 *
 * export async function signOutAction() {
 *   const session = await getSession();
 *
 *   if (session) {
 *     await redirectToSignOut();
 *   }
 * }
 * ```
 *
 * @example API Handler
 * ```tsx:src/app/api/signout/route.ts tab="API Handler" tab-group="redirect-to-sign-out"
 * import { getSession, redirectToSignOut } from "@monocloud/auth-nextjs";
 * import { NextResponse } from "next/server";
 *
 * export const GET = async () => {
 *   const session = await getSession();
 *
 *   if (session) {
 *     await redirectToSignOut({
 *       postLogoutRedirectUri: "/goodbye",
 *     });
 *   }
 *
 *   return NextResponse.json({ status: "already_signed_out" });
 * };
 * ```
 *
 * @param options Optional configuration for the redirect, such as `postLogoutRedirectUri` or additional sign-out parameters.
 * @returns Never resolves. Triggers a redirect to the sign-out flow.
 *
 * @category Functions
 */
export function redirectToSignOut(
  options?: RedirectToSignOutOptions
): Promise<void> {
  return getInstance().redirectToSignOut(options);
}
