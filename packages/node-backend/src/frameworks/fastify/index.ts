export type { ProtectHook, AuthenticatedFastifyRequest } from './types';
export type {
  ProtectApiRequestOptions,
  ClientCertificateResolver,
  IIntrospectionCache,
  MonoCloudBackendNodeClientOptions,
  ProtectOptions,
  TokenResolver,
  ValidateAccessTokenOptions,
} from '../../types';

export { protectApi } from './fastify';

export { MonoCloudBackendNodeClient } from '../../monocloud-backend-node-client';

export {
  MonoCloudValidationError,
  MonoCloudOPError,
  MonoCloudAuthBaseError,
  MonoCloudHttpError,
  MonoCloudTokenError,
} from '@monocloud/auth-core';

export type {
  AccessTokenClaims,
  ValidateJwtAccessTokenOptions,
  IntrospectOptions,
  IsUserInGroupOptions,
  MonoCloudOidcBackendClientOptions,
  ClientAuthMethod,
  Jwk,
  JwsHeaderParameters,
  JwtClaims,
  IssuerMetadata,
  Jwks,
} from '@monocloud/auth-core';

export { MonoCloudOidcBackendClient } from '@monocloud/auth-core';
