import type { SerializeOptions } from 'cookie';
import type { SessionLifetime } from '.';
import type { MonoCloudSession } from '@monocloud/auth-core';

/**
 * Options for serializing cookies.
 *
 * @category Types
 */
// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export interface CookieOptions extends SerializeOptions {}

/**
 * Interface for reading cookies from an incoming request.
 *
 * @category Types
 */
export interface IMonoCloudCookieRequest {
  /**
   * Retrieves a single cookie value by name.
   *
   * @param name - The name of the cookie to retrieve.
   */
  getCookie(name: string): Promise<string | undefined>;
  /** Retrieves all cookies from the request. */
  getAllCookies(): Promise<Map<string, string>>;
}

/**
 * Represents a request object that includes cookie handling capabilities.
 *
 * @category Types
 */
export interface MonoCloudRequest extends IMonoCloudCookieRequest {
  /**
   * Retrieves a query parameter value by name.
   *
   * @param parameter - The name of the query parameter to retrieve.
   */
  getQuery(parameter: string): string | string[] | undefined;
  /**
   * Retrieves a request header value by name.
   *
   * @param name - The (case-insensitive) name of the header to retrieve.
   */
  getHeader(name: string): string | undefined;
  /** Returns the raw request details including method, URL, and body. */
  getRawRequest(): Promise<{
    method: string;
    url: string;
    body: Record<string, string> | string;
  }>;
}

/**
 * Interface for setting cookies on an outgoing response.
 *
 * @category Types
 */
export interface IMonoCloudCookieResponse {
  /**
   * Sets a cookie on the response.
   *
   * @param cookieName - The name of the cookie to set.
   * @param value - The value to assign to the cookie.
   * @param options - Serialization options for the cookie.
   */
  setCookie(
    cookieName: string,
    value: string,
    options: CookieOptions
  ): Promise<void>;
}

/**
 * Represents an outgoing HTTP response with common helper methods.
 *
 * @category Types
 */
export interface MonoCloudResponse extends IMonoCloudCookieResponse {
  /**
   * Redirects the client to the specified URL.
   *
   * @param url - The URL to redirect to.
   * @param statusCode - The HTTP status code to use for the redirect.
   */
  redirect(url: string, statusCode?: number): void;
  /**
   * Sends a JSON response with an optional status code.
   *
   * @param data - The data to serialize and send as JSON.
   * @param statusCode - The HTTP status code for the response.
   */
  sendJson(data: any, statusCode?: number): void;
  /** Sends a 404 Not Found response. */
  notFound(): void;
  /** Sends a 204 No Content response. */
  noContent(): void;
  /** Sends a 500 Internal Server Error response. */
  internalServerError(): void;
  /** Sends a 405 Method Not Allowed response. */
  methodNotAllowed(): void;
  /**
   * Sets a header on the response.
   *
   * @param name - The name of the header to set.
   * @param value - The value to assign to the header.
   */
  setHeader(name: string, value: string): void;
  /** Sets cache-control headers to prevent caching. */
  setNoCache(): void;
  /** Finalizes and returns the response. */
  done(): any;
}

/**
 * Represents the value stored in a session cookie.
 *
 * @category Types
 */
export interface SessionCookieValue {
  /** The unique key identifying the session. */
  key: string;
  /** The lifetime metadata of the session. */
  lifetime: SessionLifetime;
  /** The session data, if stored in the cookie. */
  session?: MonoCloudSession;
}
