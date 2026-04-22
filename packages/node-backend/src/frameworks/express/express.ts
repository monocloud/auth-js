import { MonoCloudTokenError } from '@monocloud/auth-core';
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import type {
  ClientCertificateResolver,
  ProtectApiRequestOptions,
  TokenResolver,
  ProtectOptions,
} from '../../types';
import { MonoCloudBackendNodeClient } from '../../monocloud-backend-node-client';
import { getBearerToken } from '../../get-bearer-token';
import { AuthenticatedExpressRequest, ProtectMiddleware } from './types';

/**
 * Creates an Express middleware factory for protecting API routes using a pre-configured client.
 *
 * @param client - A pre-configured {@link MonoCloudBackendNodeClient} instance.
 * @param options - Options for extracting tokens and certificates from the request.
 *
 * @category Functions
 */
export function protectApi(
  client: MonoCloudBackendNodeClient,
  options?: ProtectApiRequestOptions<Request>
): ProtectMiddleware;

/**
 * Creates an Express middleware factory for protecting API routes.
 *
 * A new {@link MonoCloudBackendNodeClient} is created from the provided options,
 * or from environment variables.
 *
 * @param options - Options for extracting tokens and certificates from the request.
 *
 * @category Functions
 */
export function protectApi(
  options?: ProtectApiRequestOptions<Request>
): ProtectMiddleware;

export function protectApi(
  clientOrOptions?:
    | ProtectApiRequestOptions<Request>
    | MonoCloudBackendNodeClient,
  requestOptions?: ProtectApiRequestOptions<Request>
) {
  let client: MonoCloudBackendNodeClient;
  let certificateResolver: ClientCertificateResolver<Request> | undefined;
  let tokenResolver: TokenResolver<Request> | undefined;

  if (clientOrOptions instanceof MonoCloudBackendNodeClient) {
    client = clientOrOptions;
    certificateResolver = requestOptions?.certificateResolver;
    tokenResolver = requestOptions?.tokenResolver;
  } else {
    certificateResolver = clientOrOptions?.certificateResolver;
    tokenResolver = clientOrOptions?.tokenResolver;
    client = new MonoCloudBackendNodeClient();
  }

  return (validateOptions?: ProtectOptions): RequestHandler => {
    return async (
      request: Request,
      response: Response,
      next: NextFunction
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
          response.status(401).json({
            message: 'unauthorized',
          });
          return;
        }

        // eslint-disable-next-line no-param-reassign
        (request as AuthenticatedExpressRequest).claims =
          await client.validateAccessToken(accessToken, {
            clientCertificate,
            validateCertificateBinding:
              validateOptions?.validateCertificateBinding,
            groups: validateOptions?.groups,
            scopes: validateOptions?.scopes,
          });
        next();
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

        response.status(statusCode).json({
          message,
        });
      }
    };
  };
}
