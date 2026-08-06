import Joi from 'joi';
import type {
  AuthorizationParams,
  ClientAuthMethod,
} from '@monocloud/auth-core';
import {
  CallbackOptions,
  GetSessionOptions,
  GetTokensOptions,
  Indicator,
  MonoCloudOptionsBase,
  MonoCloudRoutes,
  MonoCloudSessionOptionsBase,
  MonoCloudStateOptions,
  SignInOptions,
  SignOutOptions,
  UserInfoOptions,
} from '../types';

const stringRequired = Joi.string().required();
const stringOptional = Joi.string().optional();
const boolRequired = Joi.boolean().required();
const boolOptional = Joi.boolean().optional();
const numRequired = Joi.number().required();
const numOptional = Joi.number().optional();
const objectOptional = Joi.object().optional();
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

const cookieSchema = Joi.object({
  name: stringRequired,
  path: stringRequired.uri({ relativeOnly: true }),
  domain: stringOptional,
  httpOnly: boolRequired,
  secure: boolRequired.when(Joi.ref('/appUrl'), {
    is: Joi.string().pattern(/^https:/i),
    then: Joi.valid(true).messages({
      'any.only':
        'Cookie must be set to secure when app url protocol is https.',
    }),
    otherwise: Joi.valid(false),
  }),
  sameSite: stringRequired.valid('strict', 'lax', 'none'),
}).required();

const sessionCookieSchema = cookieSchema.keys({
  persistent: boolRequired,
});

const resourceSchema = stringRequired.custom((value, helpers) => {
  let valid: boolean;
  try {
    const url = new URL(value);
    valid = url.searchParams.size === 0 && url.hash.length === 0;
  } catch {
    valid = false;
  }

  if (!valid) {
    return helpers.message({
      custom: 'Resource must be a valid URL without query or hash parameters',
    });
  }

  return value;
});

export const resourceValidationSchema = Joi.string()
  .custom((value, helpers) => {
    const parts = value
      .split(/\s+/)
      .map((x: string) => x.trim())
      .filter(Boolean);

    if (parts.length === 0) {
      return helpers.message({ custom: 'Resource must not be empty' });
    }

    for (const part of parts) {
      const { error } = resourceSchema.validate(part);
      if (error) {
        return helpers.message({
          custom: `Invalid resource "${part}": ${error.message}`,
        });
      }
    }

    return parts.join(' ');
  })
  .messages({
    'string.base': 'Resource must be a space-separated string of URLs',
  });

const sessionSchema: Joi.ObjectSchema<MonoCloudSessionOptionsBase> = Joi.object(
  {
    cookie: sessionCookieSchema,
    sliding: boolRequired,
    duration: numRequired.min(1),
    maximumDuration: numRequired.min(1).greater(Joi.ref('duration')),
    store: objectOptional,
  }
).required();

const stateSchema: Joi.ObjectSchema<MonoCloudStateOptions> = Joi.object({
  cookie: cookieSchema,
  duration: numRequired.integer().min(300),
  maxConcurrent: numRequired.integer().min(1).max(20),
}).required();

const scopesSchema = stringRequired
  .custom((value, helpers) => {
    const scopes = value
      .split(/\s+/)
      .map((x: string) => x.trim())
      .filter(Boolean);

    if (scopes.length === 0) {
      return helpers.message({
        custom: 'Scopes must be a space-separated string',
      });
    }

    if (!scopes.includes('openid')) {
      return helpers.message({ custom: 'Scope must contain openid' });
    }

    return scopes.join(' ');
  })
  .messages({ 'string.base': 'Scopes must be a space-separated string' });

const authParamSchema: Joi.ObjectSchema<AuthorizationParams> = Joi.object({
  scopes: scopesSchema,
  responseType: stringOptional.valid('code').optional(),
  responseMode: stringOptional.valid('query', 'form_post'),
  resource: resourceValidationSchema.optional(),
})
  .unknown(true)
  .required();

const optionalAuthParamSchema: Joi.ObjectSchema<AuthorizationParams> =
  Joi.object({
    scopes: scopesSchema,
    responseType: stringOptional.valid('code').optional(),
    responseMode: stringOptional.valid('query', 'form_post'),
  })
    .unknown(true)
    .optional();

const routesSchema: Joi.ObjectSchema<MonoCloudRoutes> = Joi.object({
  callback: stringRequired.uri({ relativeOnly: true }),
  backChannelLogout: stringRequired.uri({ relativeOnly: true }),
  signIn: stringRequired.uri({ relativeOnly: true }),
  signOut: stringRequired.uri({ relativeOnly: true }),
  userInfo: stringRequired.uri({ relativeOnly: true }),
}).required();

export const scopesValidationSchema = stringRequired
  .custom((value, helpers) => {
    const scopes = value
      .split(/\s+/)
      .map((x: string) => x.trim())
      .filter(Boolean);

    if (scopes.length === 0) {
      return helpers.message({
        custom: 'Scopes must be a space-separated string',
      });
    }

    return scopes.join(' ');
  })
  .messages({ 'string.base': 'Scopes must be a space-separated string' });

export const indicatorOptionsSchema: Joi.ObjectSchema<Indicator> = Joi.object({
  resource: resourceValidationSchema,
  scopes: scopesValidationSchema.optional(),
});

export const optionsSchema: Joi.ObjectSchema<MonoCloudOptionsBase> = Joi.object(
  {
    clientId: stringRequired,
    clientSecret: Joi.alternatives().conditional('clientAuthMethod', {
      is: 'private_key_jwt',
      then: Joi.object().required().messages({
        'object.base':
          "clientSecret must be a valid JWK when clientAuthMethod is 'private_key_jwt'",
      }),
      otherwise: stringRequired,
    }),
    clientAuthMethod: Joi.string().valid(...validClientAuthMethods),
    trustStoreId: stringOptional,
    fetcher: funcOptional,
    metadataResolver: funcOptional,
    jwksResolver: funcOptional,
    tenantDomain: stringRequired.uri(),
    cookieSecret: stringRequired.min(8),
    appUrl: stringRequired.uri(),
    routes: routesSchema,
    clockSkew: numRequired.min(0),
    clockTolerance: numRequired.min(0),
    responseTimeout: numRequired.min(1000),
    usePar: boolRequired,
    postLogoutRedirectUri: stringOptional.uri({ allowRelative: true }),
    federatedSignOut: boolRequired,
    fetchUserInfo: boolRequired,
    refetchUserInfo: boolRequired,
    allowQueryParamOverrides: boolRequired,
    strictProfileSync: boolRequired,
    defaultAuthParams: authParamSchema,
    resources: Joi.array<Indicator>().items(indicatorOptionsSchema).optional(),
    session: sessionSchema,
    state: stateSchema,
    idTokenSigningAlg: Joi.string().valid(
      'RS256',
      'RS384',
      'RS512',
      'PS256',
      'PS384',
      'PS512',
      'ES256',
      'ES384',
      'ES512'
    ),
    filteredIdTokenClaims: Joi.array<string>().items(stringRequired),
    groupsClaim: stringRequired,
    debugger: stringRequired,
    userAgent: stringRequired,
    jwksCacheDuration: numOptional,
    metadataCacheDuration: numOptional,
    onBackChannelLogout: funcOptional,
    onSetApplicationState: funcOptional,
    onSessionCreating: funcOptional,
  }
).custom((value, helpers) => {
  const sessionName = value.session.cookie.name;
  const stateName = value.state.cookie.name;

  if (stateName === sessionName) {
    return helpers.message({
      custom:
        'The state cookie name must be different from the session cookie name',
    });
  }

  if (stateName.startsWith(`${sessionName}.`)) {
    return helpers.message({
      custom: `The state cookie name must not start with "${sessionName}." as it would be read as part of the session cookie`,
    });
  }

  if (sessionName.startsWith(`${stateName}.`)) {
    return helpers.message({
      custom: `The session cookie name must not start with "${stateName}." as it would be discarded as a sign-in transaction`,
    });
  }

  return value;
});

export const signInOptionsSchema: Joi.ObjectSchema<SignInOptions> = Joi.object({
  returnUrl: stringOptional.uri({ allowRelative: true }),
  register: boolOptional,
  authParams: optionalAuthParamSchema,
  onError: funcOptional,
});

export const callbackOptionsSchema: Joi.ObjectSchema<CallbackOptions> =
  Joi.object({
    fetchUserInfo: boolOptional,
    redirectUri: stringOptional.uri(),
    onError: funcOptional,
  });

export const userInfoOptionsSchema: Joi.ObjectSchema<UserInfoOptions> =
  Joi.object({
    refresh: boolOptional,
    onError: funcOptional,
  });

export const signOutOptionsSchema: Joi.ObjectSchema<SignOutOptions> =
  Joi.object({
    postLogoutRedirectUri: stringOptional.uri({ allowRelative: true }),
    idTokenHint: stringOptional,
    state: stringOptional,
    federatedSignOut: boolOptional,
    onError: funcOptional,
  });

export const getTokensOptionsSchema: Joi.ObjectSchema<GetTokensOptions> =
  Joi.object({
    forceRefresh: boolOptional,
    refetchUserInfo: boolOptional,
    resource: resourceValidationSchema.optional(),
    scopes: scopesValidationSchema.optional(),
  });

export const getSessionOptionsSchema: Joi.ObjectSchema<GetSessionOptions> =
  Joi.object({
    refetchUserInfo: boolOptional,
  });
