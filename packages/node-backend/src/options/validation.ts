import Joi from 'joi';
import type {
  ClientAuthMethod,
  IsUserInGroupOptions,
} from '@monocloud/auth-core';
import { MonoCloudBackendNodeClientOptions } from '../types';

const stringRequired = Joi.string().required();
const stringOptional = Joi.string().optional();
const boolOptional = Joi.bool().optional();
const numRequired = Joi.number().required();
const numOptional = Joi.number().optional();
const funcOptional = Joi.function().optional();

const validClientAuthMethods: ClientAuthMethod[] = [
  'client_secret_basic',
  'client_secret_post',
  'client_secret_jwt',
  'private_key_jwt',
  'tls_client_auth',
  'self_signed_tls_client_auth',
  'spiffe_jwt',
  'spiffe_x509',
];

export const groupOptionsSchema: Joi.ObjectSchema<IsUserInGroupOptions> =
  Joi.object({
    groupsClaim: stringOptional,
    matchAll: boolOptional,
  });

export const optionsSchema: Joi.ObjectSchema<MonoCloudBackendNodeClientOptions> =
  Joi.object({
    tenantDomain: stringRequired.uri(),
    audience: stringRequired.uri(),
    clientId: stringOptional,
    clientSecret: Joi.alternatives().conditional('clientAuthMethod', {
      is: 'private_key_jwt',
      then: Joi.object().messages({
        'object.base':
          "clientSecret must be a valid JWK when clientAuthMethod is 'private_key_jwt'",
      }),
      otherwise: stringOptional,
    }),
    clientAuthMethod: stringOptional.valid(...validClientAuthMethods),
    trustStoreId: stringOptional,
    metadataResolver: funcOptional,
    jwksResolver: funcOptional,
    groupOptions: groupOptionsSchema.optional(),
    clockSkew: numRequired.min(0),
    clockTolerance: numRequired.min(0),
    jwksCacheDuration: numOptional.min(0),
    metadataCacheDuration: numOptional.min(0),
    introspectJwtTokens: boolOptional,
    validateCertificateBinding: stringRequired.valid(
      'when_present',
      'required',
      'dangerously_ignore'
    ),
    responseTimeout: numRequired.min(1000),
    introspectionCacheDuration: numRequired.min(0),
    fetcher: funcOptional,
    cache: Joi.object({
      set: Joi.function().required(),
      get: Joi.function().required(),
      delete: Joi.function().required(),
    }).optional(),
  });
