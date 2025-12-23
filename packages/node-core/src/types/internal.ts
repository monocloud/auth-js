import type { SerializeOptions } from 'cookie';
import type { SessionLifetime } from '.';
import type { MonoCloudSession } from '@monocloud/auth-core';

export type CookieOptions = SerializeOptions;

export interface IMonoCloudCookieRequest {
  getCookie(name: string): Promise<string | undefined>;
  getAllCookies(): Promise<Map<string, string>>;
}

export interface MonoCloudRequest extends IMonoCloudCookieRequest {
  getRoute(parameter: string): string | string[] | undefined;
  getQuery(parameter: string): string | string[] | undefined;
  getRawRequest(): Promise<{
    method: string;
    url: string;
    body: Record<string, string> | string;
  }>;
}

export interface IMonoCloudCookieResponse {
  setCookie(
    cookieName: string,
    value: string,
    options: CookieOptions
  ): Promise<void>;
}

export interface MonoCloudResponse extends IMonoCloudCookieResponse {
  redirect(url: string, statusCode?: number): void;
  sendJson(data: any, statusCode?: number): void;
  notFound(): void;
  noContent(): void;
  internalServerError(): void;
  methodNotAllowed(): void;
  setNoCache(): void;
  done(): any;
}

export interface SessionCookieValue {
  key: string;
  lifetime: SessionLifetime;
  session?: MonoCloudSession;
}
