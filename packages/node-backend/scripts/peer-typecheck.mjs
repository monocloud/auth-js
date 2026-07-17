/**
 * Peer dependency type-compatibility check.
 *
 * The package declares support for `express` ^4.17 || ^5 and `fastify` ^4 || ^5, but the
 * repo only ever compiles against the single version in devDependencies. The published
 * `dist/express.d.mts` / `dist/fastify.d.mts` import framework types from the *consumer's*
 * installed copy, so an incompatibility with an older (or newer) peer major only surfaces
 * on the consumer's machine.
 *
 * This script verifies the claim for every supported peer set:
 *  1. Packs `@monocloud/auth-core` and `@monocloud/backend-node` (pack applies
 *     `publishConfig`, so the tarball's exports point at `dist/` — the real consumer shape).
 *  2. For each peer set in MATRIX, creates a throwaway consumer project in a temp
 *     directory (outside the repo, so workspace types cannot leak in), installs the
 *     tarballs alongside the peer versions, and type-checks a consumer file that
 *     exercises the public Express and Fastify surface.
 *
 * Requires `dist/` to be built first (`pnpm --filter @monocloud/backend-node build`).
 * Run via `pnpm --filter @monocloud/backend-node run test:peers`.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const pkgDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const coreDir = path.resolve(pkgDir, '../core');

const TYPESCRIPT_VERSION = '~6.0.3';
const TYPES_NODE_VERSION = '^24.10.1';

const MATRIX = [
  {
    label: 'oldest-supported-peers',
    deps: { fastify: '^4.0.0', '@types/express': '^4.17.0' },
  },
  {
    label: 'latest-peers',
    deps: { fastify: '^5.0.0', '@types/express': '^5.0.0' },
  },
];

const CONSUMER_TS = `import express from 'express';
import Fastify from 'fastify';
import { MonoCloudBackendNodeClient } from '@monocloud/backend-node';
import {
  protectApi as expressProtectApi,
  type AuthenticatedExpressRequest,
  type ProtectMiddleware,
} from '@monocloud/backend-node/express';
import {
  protectApi as fastifyProtectApi,
  type AuthenticatedFastifyRequest,
  type ProtectHook,
} from '@monocloud/backend-node/fastify';

const client = new MonoCloudBackendNodeClient({
  tenantDomain: 'https://tenant.example.com',
  audience: 'https://api.example.com',
});

// Express surface
const app = express();
const protect: ProtectMiddleware = expressProtectApi();
const protectWithClient = expressProtectApi(client, {
  tokenResolver: async req => req.headers.authorization,
  certificateResolver: async req =>
    req.header('x-client-cert') ?? undefined,
});

app.get('/protected', protect(), (req, res) => {
  const { claims } = req as AuthenticatedExpressRequest;
  res.json({ claims });
});

app.get(
  '/scoped',
  protectWithClient({
    scopes: ['data:write'],
    groups: ['engineering'],
    validateCertificateBinding: true,
  }),
  (_req, res) => {
    res.status(200).send('ok');
  }
);

// Fastify surface
const fastify = Fastify();
const fastifyProtect: ProtectHook = fastifyProtectApi();
const fastifyProtectWithClient = fastifyProtectApi(client, {
  tokenResolver: async req => req.headers.authorization,
});

fastify.get('/protected', { onRequest: fastifyProtect() }, async request => {
  const { claims } = request as AuthenticatedFastifyRequest;
  return { claims };
});

fastify.get(
  '/scoped',
  { onRequest: fastifyProtectWithClient({ scopes: ['data:write'] }) },
  async () => {
    return { message: 'ok' };
  }
);

export { app, fastify };
`;

const CONSUMER_TSCONFIG = {
  compilerOptions: {
    target: 'ES2022',
    module: 'ESNext',
    moduleResolution: 'bundler',
    lib: ['ES2022', 'DOM', 'DOM.Iterable'],
    types: ['node'],
    strict: true,
    noEmit: true,
    esModuleInterop: true,
    skipLibCheck: false,
  },
  include: ['consumer.ts'],
};

const run = (cmd, args, cwd) =>
  execFileSync(cmd, args, { cwd, stdio: 'inherit' });

const pack = (dir, dest) => {
  const before = new Set(readdirSync(dest));
  execFileSync('pnpm', ['pack', '--pack-destination', dest], { cwd: dir });
  const tarball = readdirSync(dest).find(
    f => f.endsWith('.tgz') && !before.has(f)
  );
  if (!tarball) {
    throw new Error(`pnpm pack produced no tarball for ${dir}`);
  }
  return tarball;
};

if (!existsSync(path.join(pkgDir, 'dist'))) {
  console.error(
    'dist/ not found - build first: pnpm --filter @monocloud/backend-node build'
  );
  process.exit(1);
}

const workDir = mkdtempSync(path.join(os.tmpdir(), 'monocloud-peer-typecheck-'));
let failed = false;

try {
  console.log(`Packing packages into ${workDir}`);
  const coreTarball = pack(coreDir, workDir);
  const backendTarball = pack(pkgDir, workDir);

  for (const { label, deps } of MATRIX) {
    console.log(`\n=== Peer set: ${label} (${JSON.stringify(deps)}) ===`);
    const consumerDir = path.join(workDir, label);
    mkdirSync(consumerDir);

    writeFileSync(
      path.join(consumerDir, 'package.json'),
      JSON.stringify(
        {
          name: `peer-typecheck-${label}`,
          private: true,
          version: '0.0.0',
          type: 'module',
          dependencies: {
            // Direct dep on the core tarball so npm satisfies backend-node's
            // exact-version dependency with the local build instead of the registry.
            '@monocloud/auth-core': `file:../${coreTarball}`,
            '@monocloud/backend-node': `file:../${backendTarball}`,
            '@types/node': TYPES_NODE_VERSION,
            typescript: TYPESCRIPT_VERSION,
            ...deps,
          },
        },
        null,
        2
      )
    );
    writeFileSync(
      path.join(consumerDir, 'tsconfig.json'),
      JSON.stringify(CONSUMER_TSCONFIG, null, 2)
    );
    writeFileSync(path.join(consumerDir, 'consumer.ts'), CONSUMER_TS);

    try {
      run(
        'npm',
        ['install', '--no-audit', '--no-fund', '--loglevel=error'],
        consumerDir
      );
      run('npx', ['tsc', '-p', 'tsconfig.json'], consumerDir);
      console.log(`=== ${label}: OK`);
    } catch {
      console.error(`=== ${label}: FAILED`);
      failed = true;
    }
  }
} finally {
  if (failed) {
    console.error(`\nPeer type-compatibility check failed. Kept ${workDir} for debugging.`);
  } else {
    rmSync(workDir, { recursive: true, force: true });
  }
}

process.exit(failed ? 1 : 0);
