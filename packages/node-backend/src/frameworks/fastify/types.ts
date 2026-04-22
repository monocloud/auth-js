import type { FastifyReply, FastifyRequest } from 'fastify';
import { AccessTokenClaims } from '@monocloud/auth-core';
import {
  MonoCloudBackendNodeClientOptions,
  ProtectApiRequestOptions,
  ProtectOptions,
} from '../../types';

/**
 * Combined options for initializing the Fastify hook with client configuration and request options.
 *
 * @category Types
 */
export interface ProtectFastifyApiOptions
  extends
    MonoCloudBackendNodeClientOptions,
    ProtectApiRequestOptions<FastifyRequest> {}

/**
 * Factory function that returns a Fastify `onRequest` hook for protecting API routes.
 *
 * @category Types (Handler)
 */
export type ProtectHook = (
  /**
   * Validation options applied to each incoming request.
   */
  options?: ProtectOptions
) => (request: FastifyRequest, reply: FastifyReply) => Promise<void>;

/**
 * A Fastify request augmented with validated access token claims.
 *
 * @category Types
 */
export type AuthenticatedFastifyRequest = FastifyRequest & {
  /**
   * Validated access token claims attached after successful token validation.
   */
  claims: AccessTokenClaims;
};
