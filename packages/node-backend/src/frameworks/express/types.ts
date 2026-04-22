import type { Request, RequestHandler } from 'express';
import {
  MonoCloudBackendNodeClientOptions,
  ProtectApiRequestOptions,
  ProtectOptions,
} from '../../types';
import { AccessTokenClaims } from '@monocloud/auth-core';

/**
 * Combined options for initializing the Express middleware with client configuration and request options.
 *
 * @category Types
 */
export interface ProtectExpressApiOptions
  extends
    MonoCloudBackendNodeClientOptions,
    ProtectApiRequestOptions<Request> {}

/**
 * Factory function that returns an Express middleware for protecting API routes.
 *
 * @category Types (Handler)
 */
export type ProtectMiddleware = (
  /**
   * Validation options applied to each incoming request.
   */
  options?: ProtectOptions
) => RequestHandler;

/**
 * An Express request augmented with validated access token claims.
 *
 * @category Types
 */
export type AuthenticatedExpressRequest = Request & {
  /**
   * Validated access token claims attached after successful token validation.
   */
  claims: AccessTokenClaims;
};
