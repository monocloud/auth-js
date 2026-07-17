import 'dotenv/config';
import express from 'express';
import { MonoCloudBackendNodeClient } from '@monocloud/backend-node';
import {
  protectApi,
  type AuthenticatedExpressRequest,
} from '@monocloud/backend-node/express';

/**
 * This is a simple example of how to protect an Express API using the MonoCloud Backend Node SDK.
 * The example demonstrates validating bearer access tokens (locally and via introspection)
 * and enforcing scope-based authorization.
 *
 * You will need the following setup in your MonoCloud tenant:
 *  - An API Resource whose identifier matches MONOCLOUD_BACKEND_AUDIENCE
 *    (e.g. https://api.example.com), with a `data:write` scope defined.
 *  - A client created with the Machine to Machine (M2M) preset that is allowed to access the
 *    API Resource and the `data:write` scope. Its credentials are used by `scripts/get-token.ts`
 *    to obtain an access token for calling this API.
 *  - The API client's credentials (MONOCLOUD_BACKEND_CLIENT_ID / MONOCLOUD_BACKEND_CLIENT_SECRET)
 *    for the introspection-validated endpoint below.
 *
 * Copy `.env.example` to `.env`, fill in the values, and start the API with `npm run dev`.
 * Then run `npm run get-token` in another terminal to obtain an access token and call the
 * endpoints below with it.
 */

const app = express();

// Creates the protect middleware factory.
const protect = protectApi();

// A second client that validates tokens at the tenant's introspection endpoint instead
// of locally. Opaque tokens are always introspected; `introspectJwtTokens` forces
// introspection for JWTs too. Introspection authenticates with the API client's
// credentials (MONOCLOUD_BACKEND_CLIENT_ID / MONOCLOUD_BACKEND_CLIENT_SECRET).
const introspectionClient = new MonoCloudBackendNodeClient({
  introspectJwtTokens: true,
});
const protectWithIntrospection = protectApi(introspectionClient);

// Public route — no access token required.
app.get('/api/public', (_req, res) => {
  res.json({ message: 'public' });
});

// Requires a valid access token.
app.get('/api/protected', protect(), (req, res) => {
  const { claims } = req as AuthenticatedExpressRequest;
  res.json({ claims });
});

// Requires a valid access token containing the `data:write` scope.
app.get('/api/data', protect({ scopes: ['data:write'] }), (_req, res) => {
  res.json({ message: 'data:write access granted' });
});

// Requires a valid access token, validated via the introspection endpoint.
app.get('/api/introspected', protectWithIntrospection(), (req, res) => {
  const { claims } = req as AuthenticatedExpressRequest;
  res.json({ claims });
});

const port = Number(process.env.PORT ?? 3000);

app.listen(port, () => {
  // eslint-disable-next-line no-console
  console.log(`Express example API listening on http://localhost:${port}`);
});
