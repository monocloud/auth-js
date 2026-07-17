import 'dotenv/config';

/**
 * Obtains a machine-to-machine (M2M) access token for calling the example API.
 *
 * This example API only validates access tokens — it does not issue them. To call the
 * protected endpoints you first need an access token from your MonoCloud tenant. This
 * script obtains one using the OAuth 2.0 Client Credentials grant (RFC 6749, section 4.4),
 * the flow used for machine-to-machine communication where a backend service — not a
 * user — is the caller. The client authenticates with its own ID and secret and receives
 * an access token scoped to the target API.
 *
 * The script:
 *  1. Discovers the token endpoint from the tenant's OpenID Connect discovery document.
 *  2. Sends a `client_credentials` grant request with the M2M client's ID, secret and
 *     scopes. The request includes the `resource` parameter (Resource Indicators for
 *     OAuth 2.0, RFC 8707) set to the API's identifier, so the issued token is audienced
 *     to this API — its `aud` claim will match MONOCLOUD_BACKEND_AUDIENCE, which the SDK
 *     validates on every request.
 *  3. Prints the access token along with ready-to-run curl commands for each endpoint
 *     of the example API.
 *
 * Usage:
 *   npm run get-token
 *
 * Required environment variables (see .env.example):
 *  - MONOCLOUD_BACKEND_TENANT_DOMAIN — your MonoCloud tenant domain
 *  - MONOCLOUD_BACKEND_AUDIENCE — the API identifier, sent as the `resource` parameter
 *  - M2M_CLIENT_ID / M2M_CLIENT_SECRET — credentials of a client with the M2M preset
 *  - M2M_SCOPES — space separated scopes to request (e.g. `data:write`)
 */

/* eslint-disable no-console */

interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  scope?: string;
}

const requireEnv = (name: string): string => {
  const value = process.env[name];
  if (!value) {
    console.error(
      `Missing environment variable ${name}. Copy .env.example to .env and fill in the values.`
    );
    process.exit(1);
  }
  return value;
};

const tenantDomain = requireEnv('MONOCLOUD_BACKEND_TENANT_DOMAIN');
const audience = requireEnv('MONOCLOUD_BACKEND_AUDIENCE');
const clientId = requireEnv('M2M_CLIENT_ID');
const clientSecret = requireEnv('M2M_CLIENT_SECRET');
const scopes = requireEnv('M2M_SCOPES');

// Discover the token endpoint from the tenant's OpenID Connect discovery document.
const discoveryResponse = await fetch(
  `${tenantDomain}/.well-known/openid-configuration`
);

if (!discoveryResponse.ok) {
  console.error(
    `Failed to fetch the discovery document (${discoveryResponse.status}). Check MONOCLOUD_BACKEND_TENANT_DOMAIN.`
  );
  process.exit(1);
}

const { token_endpoint: tokenEndpoint } = (await discoveryResponse.json()) as {
  token_endpoint: string;
};

// Request an access token using the client credentials grant. The `resource`
// parameter (RFC 8707) tells the token endpoint which API the token is for.
const tokenResponse = await fetch(tokenEndpoint, {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: clientId,
    client_secret: clientSecret,
    scope: scopes,
    resource: audience,
  }),
});

if (!tokenResponse.ok) {
  console.error(
    `Token request failed (${tokenResponse.status}): ${await tokenResponse.text()}`
  );
  process.exit(1);
}

const token = (await tokenResponse.json()) as TokenResponse;

const baseUrl = `http://localhost:${process.env.PORT ?? 3000}`;
const authHeader = `Authorization: Bearer ${token.access_token}`;

console.log('Access token obtained successfully!\n');
console.log(`  token_type: ${token.token_type}`);
console.log(`  expires_in: ${token.expires_in} seconds`);
console.log(`  scope     : ${token.scope ?? scopes}`);
console.log(`\n${token.access_token}\n`);
console.log('Call the example API with it:\n');
console.log(`curl ${baseUrl}/api/public`);
console.log(`\ncurl -H "${authHeader}" ${baseUrl}/api/protected`);
console.log(`\ncurl -H "${authHeader}" ${baseUrl}/api/introspected`);
console.log(
  `\n# Returns 403 unless the token contains the data:write scope\ncurl -H "${authHeader}" ${baseUrl}/api/data\n`
);
