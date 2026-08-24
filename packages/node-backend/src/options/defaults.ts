export const DEFAULT_OPTIONS = {
  clockSkew: 0,
  clockTolerance: 60,
  clientAuthMethod: 'client_secret_post',
  introspectJwtTokens: false,
  validateCertificateBinding: 'when_present' as const,
  responseTimeout: 10000,
  introspectionCacheDuration: 300,
};
