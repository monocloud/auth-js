export type { ProtectMiddleware, AuthenticatedExpressRequest } from './types';
export type {
  ProtectApiRequestOptions,
  ClientCertificateResolver,
  IIntrospectionCache,
  MonoCloudBackendNodeClientOptions,
  ProtectOptions,
  TokenResolver,
  ValidateAccessTokenOptions,
} from '../../types';

export { protectApi } from './express';

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
  MonoCloudTokenErrorCode,
  CertificateBindingValidation,
  MonoCloudRawResponse,
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
