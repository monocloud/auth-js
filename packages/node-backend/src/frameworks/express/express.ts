import type { NextFunction, Request, RequestHandler, Response } from 'express';
import type {
  ClientCertificateResolver,
  ProtectApiRequestOptions,
  TokenResolver,
  ProtectOptions,
} from '../../types';
import { MonoCloudBackendNodeClient } from '../../monocloud-backend-node-client';
import { getBearerToken } from '../../get-bearer-token';
import { mapProtectError } from '../map-protect-error';
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
    ProtectApiRequestOptions<Request> | MonoCloudBackendNodeClient,
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
        const clientCertificate = await certificateResolver?.(request);

        const accessToken = (
          (await tokenResolver?.(request)) ??
          getBearerToken(request.headers.authorization)
        )?.trim();

        if (!accessToken) {
          response.status(401).set('WWW-Authenticate', 'Bearer').json({
            message: 'unauthorized',
          });
          return;
        }

        // eslint-disable-next-line no-param-reassign
        (request as AuthenticatedExpressRequest).claims =
          await client.validateAccessToken(accessToken, {
            clientCertificate,
            groups: validateOptions?.groups,
            scopes: validateOptions?.scopes,
          });
        next();
      } catch (error) {
        const { status, message, wwwAuthenticate } = mapProtectError(error);

        if (wwwAuthenticate) {
          response.set('WWW-Authenticate', wwwAuthenticate);
        }

        response.status(status).json({
          message,
        });
      }
    };
  };
}
