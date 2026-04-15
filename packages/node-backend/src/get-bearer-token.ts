export const getBearerToken = (
  authorizationHeader?: string
): string | undefined => {
  if (!authorizationHeader) {
    return undefined;
  }

  const [scheme, accessToken, ...remaining] = authorizationHeader
    .trim()
    .split(/\s+/);

  if (scheme.toLowerCase() !== 'bearer' || !accessToken || remaining.length) {
    return undefined;
  }

  return accessToken;
};
