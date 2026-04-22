import { MonoCloudTokenError } from '@monocloud/auth-core';
import type { FastifyReply, FastifyRequest } from 'fastify';
import type {
  ClientCertificateResolver,
  ProtectApiRequestOptions,
  TokenResolver,
  ProtectOptions,
} from '../../types';
import { MonoCloudBackendNodeClient } from '../../monocloud-backend-node-client';
import { getBearerToken } from '../../get-bearer-token';
import { AuthenticatedFastifyRequest, ProtectHook } from './types';

/**
 * Creates a Fastify `onRequest` hook factory for protecting API routes using a pre-configured client.
 *
 * @param client - A pre-configured {@link MonoCloudBackendNodeClient} instance.
 * @param options - Options for extracting tokens and certificates from the request.
 *
 * @category Functions
 */
export function protectApi(
  client: MonoCloudBackendNodeClient,
  options?: ProtectApiRequestOptions<FastifyRequest>
): ProtectHook;

/**
 * Creates a Fastify `onRequest` hook factory for protecting API routes.
 *
 * A new {@link MonoCloudBackendNodeClient} is created from the provided options,
 * or from environment variables.
 *
 * @param options - Options for extracting tokens and certificates from the request.
 *
 * @category Functions
 */
export function protectApi(
  options?: ProtectApiRequestOptions<FastifyRequest>
): ProtectHook;

export function protectApi(
  clientOrOptions?:
    | ProtectApiRequestOptions<FastifyRequest>
    | MonoCloudBackendNodeClient,
  requestOptions?: ProtectApiRequestOptions<FastifyRequest>
) {
  let client: MonoCloudBackendNodeClient;
  let certificateResolver:
    | ClientCertificateResolver<FastifyRequest>
    | undefined;
  let tokenResolver: TokenResolver<FastifyRequest> | undefined;

  if (clientOrOptions instanceof MonoCloudBackendNodeClient) {
    client = clientOrOptions;
    certificateResolver = requestOptions?.certificateResolver;
    tokenResolver = requestOptions?.tokenResolver;
  } else {
    certificateResolver = clientOrOptions?.certificateResolver;
    tokenResolver = clientOrOptions?.tokenResolver;
    client = new MonoCloudBackendNodeClient();
  }

  return (validateOptions?: ProtectOptions) => {
    return async (
      request: FastifyRequest,
      reply: FastifyReply
      // eslint-disable-next-line consistent-return
    ): Promise<void> => {
      try {
        let clientCertificate: string | undefined;
        if (validateOptions?.validateCertificateBinding) {
          clientCertificate = await certificateResolver?.(request);
        }

        const accessToken =
          (await tokenResolver?.(request)) ??
          getBearerToken(request.headers.authorization);

        if (!accessToken) {
          return reply.status(401).send({
            message: 'unauthorized',
          });
        }

        // eslint-disable-next-line no-param-reassign
        (request as AuthenticatedFastifyRequest).claims =
          await client.validateAccessToken(accessToken, {
            clientCertificate,
            validateCertificateBinding:
              validateOptions?.validateCertificateBinding,
            groups: validateOptions?.groups,
            scopes: validateOptions?.scopes,
          });
      } catch (error) {
        let statusCode = 401;
        let message = 'unauthorized';

        if (
          error instanceof MonoCloudTokenError &&
          (error.message === 'Token is missing required scopes' ||
            error.message === 'Token is missing required groups')
        ) {
          statusCode = 403;
          message = 'forbidden';
        }

        return reply.status(statusCode).send({
          message,
        });
      }
    };
  };
}
