/* eslint-disable prefer-destructuring */
/* eslint-disable @typescript-eslint/no-non-null-assertion */
import {
  getBoolean,
  getNumber,
  parseClientSecret,
  removeTrailingSlash,
} from '@monocloud/auth-core/internal';
import {
  MonoCloudOptions,
  MonoCloudOptionsBase,
  SameSiteValues,
} from '../types';
import { DEFAULT_OPTIONS } from './defaults';
import { optionsSchema } from './validation';
import {
  ClientAuthMethod,
  MonoCloudValidationError,
  SecurityAlgorithms,
} from '@monocloud/auth-core';

export const getOptions = (
  options?: MonoCloudOptions,
  throwOnError = true
): MonoCloudOptionsBase => {
  const MONOCLOUD_AUTH_CLIENT_ID = process.env.MONOCLOUD_AUTH_CLIENT_ID;
  const MONOCLOUD_AUTH_CLIENT_SECRET = process.env.MONOCLOUD_AUTH_CLIENT_SECRET;
  const MONOCLOUD_AUTH_CLIENT_AUTH_METHOD =
    process.env.MONOCLOUD_AUTH_CLIENT_AUTH_METHOD;
  const MONOCLOUD_AUTH_TRUST_STORE_ID =
    process.env.MONOCLOUD_AUTH_TRUST_STORE_ID;
  const MONOCLOUD_AUTH_TENANT_DOMAIN = process.env.MONOCLOUD_AUTH_TENANT_DOMAIN;
  const MONOCLOUD_AUTH_SCOPES = process.env.MONOCLOUD_AUTH_SCOPES;
  const MONOCLOUD_AUTH_COOKIE_SECRET = process.env.MONOCLOUD_AUTH_COOKIE_SECRET;
  const MONOCLOUD_AUTH_APP_URL = process.env.MONOCLOUD_AUTH_APP_URL;
  const MONOCLOUD_AUTH_CALLBACK_URL = process.env.MONOCLOUD_AUTH_CALLBACK_URL;
  const MONOCLOUD_AUTH_BACK_CHANNEL_LOGOUT_URL =
    process.env.MONOCLOUD_AUTH_BACK_CHANNEL_LOGOUT_URL;
  const MONOCLOUD_AUTH_SIGNIN_URL = process.env.MONOCLOUD_AUTH_SIGNIN_URL;
  const MONOCLOUD_AUTH_SIGNOUT_URL = process.env.MONOCLOUD_AUTH_SIGNOUT_URL;
  const MONOCLOUD_AUTH_USER_INFO_URL = process.env.MONOCLOUD_AUTH_USER_INFO_URL;
  const MONOCLOUD_AUTH_RESOURCE = process.env.MONOCLOUD_AUTH_RESOURCE;
  const MONOCLOUD_AUTH_CLOCK_SKEW = process.env.MONOCLOUD_AUTH_CLOCK_SKEW;
  const MONOCLOUD_AUTH_CLOCK_TOLERANCE =
    process.env.MONOCLOUD_AUTH_CLOCK_TOLERANCE;
  const MONOCLOUD_AUTH_RESPONSE_TIMEOUT =
    process.env.MONOCLOUD_AUTH_RESPONSE_TIMEOUT;
  const MONOCLOUD_AUTH_USE_PAR = process.env.MONOCLOUD_AUTH_USE_PAR;
  const MONOCLOUD_AUTH_POST_LOGOUT_REDIRECT_URI =
    process.env.MONOCLOUD_AUTH_POST_LOGOUT_REDIRECT_URI;
  const MONOCLOUD_AUTH_FEDERATED_SIGNOUT =
    process.env.MONOCLOUD_AUTH_FEDERATED_SIGNOUT;
  const MONOCLOUD_AUTH_FETCH_USER_INFO =
    process.env.MONOCLOUD_AUTH_FETCH_USER_INFO;
  const MONOCLOUD_AUTH_REFETCH_USER_INFO =
    process.env.MONOCLOUD_AUTH_REFETCH_USER_INFO;
  const MONOCLOUD_AUTH_ALLOW_QUERY_PARAM_OVERRIDES =
    process.env.MONOCLOUD_AUTH_ALLOW_QUERY_PARAM_OVERRIDES;
  const MONOCLOUD_AUTH_REFETCH_STRICT_PROFILE_SYNC =
    process.env.MONOCLOUD_AUTH_REFETCH_STRICT_PROFILE_SYNC;
  const MONOCLOUD_AUTH_SESSION_COOKIE_NAME =
    process.env.MONOCLOUD_AUTH_SESSION_COOKIE_NAME;
  const MONOCLOUD_AUTH_SESSION_COOKIE_PATH =
    process.env.MONOCLOUD_AUTH_SESSION_COOKIE_PATH;
  const MONOCLOUD_AUTH_SESSION_COOKIE_DOMAIN =
    process.env.MONOCLOUD_AUTH_SESSION_COOKIE_DOMAIN;
  const MONOCLOUD_AUTH_SESSION_COOKIE_HTTP_ONLY =
    process.env.MONOCLOUD_AUTH_SESSION_COOKIE_HTTP_ONLY;
  const MONOCLOUD_AUTH_SESSION_COOKIE_SECURE =
    process.env.MONOCLOUD_AUTH_SESSION_COOKIE_SECURE;
  const MONOCLOUD_AUTH_SESSION_COOKIE_SAME_SITE =
    process.env.MONOCLOUD_AUTH_SESSION_COOKIE_SAME_SITE;
  const MONOCLOUD_AUTH_SESSION_COOKIE_PERSISTENT =
    process.env.MONOCLOUD_AUTH_SESSION_COOKIE_PERSISTENT;
  const MONOCLOUD_AUTH_SESSION_SLIDING =
    process.env.MONOCLOUD_AUTH_SESSION_SLIDING;
  const MONOCLOUD_AUTH_SESSION_DURATION =
    process.env.MONOCLOUD_AUTH_SESSION_DURATION;
  const MONOCLOUD_AUTH_SESSION_MAX_DURATION =
    process.env.MONOCLOUD_AUTH_SESSION_MAX_DURATION;
  const MONOCLOUD_AUTH_STATE_COOKIE_NAME =
    process.env.MONOCLOUD_AUTH_STATE_COOKIE_NAME;
  const MONOCLOUD_AUTH_STATE_COOKIE_PATH =
    process.env.MONOCLOUD_AUTH_STATE_COOKIE_PATH;
  const MONOCLOUD_AUTH_STATE_COOKIE_DOMAIN =
    process.env.MONOCLOUD_AUTH_STATE_COOKIE_DOMAIN;
  const MONOCLOUD_AUTH_STATE_COOKIE_SECURE =
    process.env.MONOCLOUD_AUTH_STATE_COOKIE_SECURE;
  const MONOCLOUD_AUTH_STATE_COOKIE_SAME_SITE =
    process.env.MONOCLOUD_AUTH_STATE_COOKIE_SAME_SITE;
  const MONOCLOUD_AUTH_STATE_COOKIE_PERSISTENT =
    process.env.MONOCLOUD_AUTH_STATE_COOKIE_PERSISTENT;
  const MONOCLOUD_AUTH_ID_TOKEN_SIGNING_ALG =
    process.env.MONOCLOUD_AUTH_ID_TOKEN_SIGNING_ALG;
  const MONOCLOUD_AUTH_FILTERED_ID_TOKEN_CLAIMS =
    process.env.MONOCLOUD_AUTH_FILTERED_ID_TOKEN_CLAIMS;
  const MONOCLOUD_AUTH_JWKS_CACHE_DURATION =
    process.env.MONOCLOUD_AUTH_JWKS_CACHE_DURATION;
  const MONOCLOUD_AUTH_METADATA_CACHE_DURATION =
    process.env.MONOCLOUD_AUTH_METADATA_CACHE_DURATION;
  const MONOCLOUD_AUTH_GROUPS_CLAIM = process.env.MONOCLOUD_AUTH_GROUPS_CLAIM;

  const appUrl = options?.appUrl ?? MONOCLOUD_AUTH_APP_URL!;

  const opt: MonoCloudOptionsBase = {
    clientId: options?.clientId ?? MONOCLOUD_AUTH_CLIENT_ID!,
    clientSecret: parseClientSecret(
      options?.clientSecret ?? MONOCLOUD_AUTH_CLIENT_SECRET
    ),
    clientAuthMethod:
      options?.clientAuthMethod ??
      (MONOCLOUD_AUTH_CLIENT_AUTH_METHOD as ClientAuthMethod) ??
      DEFAULT_OPTIONS.clientAuthMethod,
    trustStoreId: options?.trustStoreId ?? MONOCLOUD_AUTH_TRUST_STORE_ID,
    fetcher: options?.fetcher,
    metadataResolver: options?.metadataResolver,
    jwksResolver: options?.jwksResolver,
    tenantDomain: options?.tenantDomain ?? MONOCLOUD_AUTH_TENANT_DOMAIN!,
    defaultAuthParams: {
      ...(options?.defaultAuthParams ?? {}),
      scopes:
        options?.defaultAuthParams?.scopes ??
        MONOCLOUD_AUTH_SCOPES ??
        DEFAULT_OPTIONS.defaultAuthParams.scopes,
      responseType:
        options?.defaultAuthParams?.responseType ??
        (DEFAULT_OPTIONS.defaultAuthParams.responseType as any),
      resource: options?.defaultAuthParams?.resource ?? MONOCLOUD_AUTH_RESOURCE,
    },
    resources: options?.resources,
    cookieSecret: options?.cookieSecret ?? MONOCLOUD_AUTH_COOKIE_SECRET!,
    appUrl: removeTrailingSlash(appUrl),
    routes: {
      callback: removeTrailingSlash(
        options?.routes?.callback ??
          MONOCLOUD_AUTH_CALLBACK_URL ??
          DEFAULT_OPTIONS.routes.callback
      ),
      backChannelLogout: removeTrailingSlash(
        options?.routes?.backChannelLogout ??
          MONOCLOUD_AUTH_BACK_CHANNEL_LOGOUT_URL ??
          DEFAULT_OPTIONS.routes.backChannelLogout
      ),
      signIn: removeTrailingSlash(
        options?.routes?.signIn ??
          MONOCLOUD_AUTH_SIGNIN_URL ??
          DEFAULT_OPTIONS.routes.signIn
      ),
      signOut: removeTrailingSlash(
        options?.routes?.signOut ??
          MONOCLOUD_AUTH_SIGNOUT_URL ??
          DEFAULT_OPTIONS.routes.signOut
      ),
      userInfo: removeTrailingSlash(
        options?.routes?.userInfo ??
          MONOCLOUD_AUTH_USER_INFO_URL ??
          DEFAULT_OPTIONS.routes.userInfo
      ),
    },
    clockSkew:
      options?.clockSkew ??
      getNumber(MONOCLOUD_AUTH_CLOCK_SKEW) ??
      DEFAULT_OPTIONS.clockSkew,
    clockTolerance:
      options?.clockTolerance ??
      getNumber(MONOCLOUD_AUTH_CLOCK_TOLERANCE) ??
      DEFAULT_OPTIONS.clockTolerance,
    responseTimeout:
      options?.responseTimeout ??
      getNumber(MONOCLOUD_AUTH_RESPONSE_TIMEOUT) ??
      DEFAULT_OPTIONS.responseTimeout,
    usePar:
      options?.usePar ??
      getBoolean(MONOCLOUD_AUTH_USE_PAR) ??
      DEFAULT_OPTIONS.usePar,
    postLogoutRedirectUri:
      options?.postLogoutRedirectUri ?? MONOCLOUD_AUTH_POST_LOGOUT_REDIRECT_URI,
    federatedSignOut:
      options?.federatedSignOut ??
      getBoolean(MONOCLOUD_AUTH_FEDERATED_SIGNOUT) ??
      DEFAULT_OPTIONS.federatedSignOut,
    fetchUserInfo:
      options?.fetchUserInfo ??
      getBoolean(MONOCLOUD_AUTH_FETCH_USER_INFO) ??
      DEFAULT_OPTIONS.fetchUserInfo,
    refetchUserInfo:
      options?.refetchUserInfo ??
      getBoolean(MONOCLOUD_AUTH_REFETCH_USER_INFO) ??
      DEFAULT_OPTIONS.refetchUserInfo,
    allowQueryParamOverrides:
      options?.allowQueryParamOverrides ??
      getBoolean(MONOCLOUD_AUTH_ALLOW_QUERY_PARAM_OVERRIDES) ??
      DEFAULT_OPTIONS.allowQueryParamOverrides,
    strictProfileSync:
      options?.strictProfileSync ??
      getBoolean(MONOCLOUD_AUTH_REFETCH_STRICT_PROFILE_SYNC) ??
      DEFAULT_OPTIONS.strictProfileSync,
    session: {
      cookie: {
        name:
          options?.session?.cookie?.name ??
          MONOCLOUD_AUTH_SESSION_COOKIE_NAME ??
          DEFAULT_OPTIONS.session.cookie.name,
        path:
          options?.session?.cookie?.path ??
          MONOCLOUD_AUTH_SESSION_COOKIE_PATH ??
          DEFAULT_OPTIONS.session.cookie.path,
        domain:
          options?.session?.cookie?.domain ??
          MONOCLOUD_AUTH_SESSION_COOKIE_DOMAIN,
        httpOnly:
          options?.session?.cookie?.httpOnly ??
          getBoolean(MONOCLOUD_AUTH_SESSION_COOKIE_HTTP_ONLY) ??
          DEFAULT_OPTIONS.session.cookie.httpOnly,
        secure:
          options?.session?.cookie?.secure ??
          getBoolean(MONOCLOUD_AUTH_SESSION_COOKIE_SECURE) ??
          appUrl?.startsWith('https:'),
        sameSite:
          options?.session?.cookie?.sameSite ??
          (MONOCLOUD_AUTH_SESSION_COOKIE_SAME_SITE as SameSiteValues) ??
          DEFAULT_OPTIONS.session.cookie.sameSite,
        persistent:
          options?.session?.cookie?.persistent ??
          getBoolean(MONOCLOUD_AUTH_SESSION_COOKIE_PERSISTENT) ??
          DEFAULT_OPTIONS.session.cookie.persistent,
      },
      sliding:
        options?.session?.sliding ??
        getBoolean(MONOCLOUD_AUTH_SESSION_SLIDING) ??
        DEFAULT_OPTIONS.session.sliding,
      duration:
        options?.session?.duration ??
        getNumber(MONOCLOUD_AUTH_SESSION_DURATION) ??
        DEFAULT_OPTIONS.session.duration,
      maximumDuration:
        options?.session?.maximumDuration ??
        getNumber(MONOCLOUD_AUTH_SESSION_MAX_DURATION) ??
        DEFAULT_OPTIONS.session.maximumDuration,
      store: options?.session?.store,
    },
    state: {
      cookie: {
        name:
          options?.state?.cookie?.name ??
          MONOCLOUD_AUTH_STATE_COOKIE_NAME ??
          DEFAULT_OPTIONS.state.cookie.name,
        path:
          options?.state?.cookie?.path ??
          MONOCLOUD_AUTH_STATE_COOKIE_PATH ??
          DEFAULT_OPTIONS.state.cookie.path,
        domain:
          options?.state?.cookie?.domain ?? MONOCLOUD_AUTH_STATE_COOKIE_DOMAIN,
        httpOnly: DEFAULT_OPTIONS.state.cookie.httpOnly,
        secure:
          options?.state?.cookie?.secure ??
          getBoolean(MONOCLOUD_AUTH_STATE_COOKIE_SECURE) ??
          appUrl?.startsWith('https:'),
        sameSite:
          options?.state?.cookie?.sameSite ??
          (MONOCLOUD_AUTH_STATE_COOKIE_SAME_SITE as SameSiteValues) ??
          DEFAULT_OPTIONS.state.cookie.sameSite,
        persistent:
          options?.state?.cookie?.persistent ??
          getBoolean(MONOCLOUD_AUTH_STATE_COOKIE_PERSISTENT) ??
          DEFAULT_OPTIONS.state.cookie.persistent,
      },
    },
    idTokenSigningAlg:
      options?.idTokenSigningAlg ??
      (MONOCLOUD_AUTH_ID_TOKEN_SIGNING_ALG as SecurityAlgorithms) ??
      DEFAULT_OPTIONS.idTokenSigningAlg,
    filteredIdTokenClaims:
      options?.filteredIdTokenClaims ??
      MONOCLOUD_AUTH_FILTERED_ID_TOKEN_CLAIMS?.split(' ')
        .map(x => x.trim())
        .filter(x => x.length) ??
      DEFAULT_OPTIONS.filteredIdTokenClaims,
    groupsClaim:
      options?.groupsClaim ??
      MONOCLOUD_AUTH_GROUPS_CLAIM ??
      DEFAULT_OPTIONS.groupsClaim,
    debugger: options?.debugger ?? DEFAULT_OPTIONS.debugger,
    userAgent: options?.userAgent ?? DEFAULT_OPTIONS.userAgent,
    jwksCacheDuration:
      options?.jwksCacheDuration ??
      getNumber(MONOCLOUD_AUTH_JWKS_CACHE_DURATION),
    metadataCacheDuration:
      options?.metadataCacheDuration ??
      getNumber(MONOCLOUD_AUTH_METADATA_CACHE_DURATION),
    onBackChannelLogout: options?.onBackChannelLogout,
    onSetApplicationState: options?.onSetApplicationState,
    onSessionCreating: options?.onSessionCreating,
  };

  const { value, error } = optionsSchema.validate(opt, { abortEarly: false });

  const requiredEnv: Record<string, string> = {
    tenantDomain: 'MONOCLOUD_AUTH_TENANT_DOMAIN',
    clientId: 'MONOCLOUD_AUTH_CLIENT_ID',
    clientSecret: 'MONOCLOUD_AUTH_CLIENT_SECRET',
    appUrl: 'MONOCLOUD_AUTH_APP_URL',
    cookieSecret: 'MONOCLOUD_AUTH_COOKIE_SECRET',
  };

  if (error) {
    if (throwOnError) {
      throw new MonoCloudValidationError(error.details[0].message);
    }

    // eslint-disable-next-line no-console
    console.warn(
      'WARNING: One or more configuration options were not provided for MonoCloudClient.'
    );
    error.details.forEach(detail => {
      if (detail.context?.key && requiredEnv[detail.context.key]) {
        // eslint-disable-next-line no-console
        console.warn(
          `Missing: ${detail.context.key} - Set ${requiredEnv[detail.context.key]} environment variable in your .env file.`
        );
      }
    });
  }

  return value;
};
