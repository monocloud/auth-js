/* eslint-disable require-await */
import 'dotenv/config';
import Fastify from 'fastify';
import { MonoCloudBackendNodeClient } from '@monocloud/backend-node';
import {
  protectApi,
  type AuthenticatedFastifyRequest,
} from '@monocloud/backend-node/fastify';

/**
 * This is a simple example of how to protect a Fastify API using the MonoCloud Backend Node SDK.
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

const fastify = Fastify();

// Creates the protect onRequest hook factory.
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
fastify.get('/api/public', async () => {
  return { message: 'public' };
});

// Requires a valid access token.
fastify.get('/api/protected', { onRequest: protect() }, async request => {
  const { claims } = request as AuthenticatedFastifyRequest;
  return { claims };
});

// Requires a valid access token containing the `data:write` scope.
fastify.get(
  '/api/data',
  { onRequest: protect({ scopes: ['data:write'] }) },
  async () => {
    return { message: 'data:write access granted' };
  }
);

// Requires a valid access token, validated via the introspection endpoint.
fastify.get(
  '/api/introspected',
  { onRequest: protectWithIntrospection() },
  async request => {
    const { claims } = request as AuthenticatedFastifyRequest;
    return { claims };
  }
);

const port = Number(process.env.PORT ?? 3000);

await fastify.listen({ port });

// eslint-disable-next-line no-console
console.log(`Fastify example API listening on http://localhost:${port}`);
