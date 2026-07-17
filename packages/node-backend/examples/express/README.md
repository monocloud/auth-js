# MonoCloud Backend Node SDK Express Example

An Express API protected with [`@monocloud/backend-node`](https://www.npmjs.com/package/@monocloud/backend-node).

## Getting Started

1. Copy `.env.example` to `.env` and fill in the values. See [src/index.ts](src/index.ts) for the required tenant setup.
2. Install the dependencies and start the API:

   ```bash
   npm install
   npm run dev
   ```

3. Obtain a machine-to-machine (M2M) access token (see [scripts/get-token.ts](scripts/get-token.ts)):

   ```bash
   npm run get-token
   ```

4. Call the API with the token printed by the script:

   ```bash
   curl -H "Authorization: Bearer <access-token>" http://localhost:3000/api/protected
   ```
