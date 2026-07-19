# MonoCloud Backend Node SDK Express Example

An Express API protected with [`@monocloud/backend-node`](https://www.npmjs.com/package/@monocloud/backend-node).

## Getting Started

1. Build the SDK from the repository root (this example links to it via `file:` dependencies):

   ```bash
   pnpm install
   pnpm build
   ```

2. Copy `.env.example` to `.env` and fill in the values. See [src/index.ts](src/index.ts) for the required tenant setup.
3. Install the dependencies and start the API:

   ```bash
   npm install
   npm run dev
   ```

4. Obtain a machine-to-machine (M2M) access token (see [scripts/get-token.ts](scripts/get-token.ts)):

   ```bash
   npm run get-token
   ```

5. Call the API with the token printed by the script:

   ```bash
   curl -H "Authorization: Bearer <access-token>" http://localhost:3000/api/protected
   ```
