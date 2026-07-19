# MonoCloud Next.js Authentication SDK App Router Example

A Next.js **App Router** application secured with [`@monocloud/auth-nextjs`](https://www.npmjs.com/package/@monocloud/auth-nextjs).

## Getting Started

1. Build the SDK from the repository root (this example links to it via `file:` dependencies):

   ```bash
   pnpm install
   pnpm build
   ```

2. Install this example's dependencies:

   ```bash
   npm install
   ```

3. Create a `.env.local` file in this directory and fill in the values from your MonoCloud dashboard:

   ```bash
   MONOCLOUD_AUTH_TENANT_DOMAIN=https://<your-domain>
   MONOCLOUD_AUTH_CLIENT_ID=<your-client-id>
   MONOCLOUD_AUTH_CLIENT_SECRET=<your-client-secret>
   MONOCLOUD_AUTH_SCOPES=openid email profile
   MONOCLOUD_AUTH_APP_URL=http://localhost:3000
   MONOCLOUD_AUTH_COOKIE_SECRET=<your_cookie_secret>
   ```

4. Start the dev server and open [http://localhost:3000](http://localhost:3000):

   ```bash
   npm run dev
   ```

## Learn More

- [Next.js App Router Quickstart](https://www.monocloud.com/docs/quickstarts/nextjs-app-router?utm_source=github&utm_medium=auth_js)
- [Next.js SDK Reference](https://www.monocloud.com/docs/sdks/nextjs?utm_source=github&utm_medium=auth_js)
