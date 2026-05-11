#!/usr/bin/env node
// Refreshes the `version` field in each Claude plugin manifest from its SDK's
// package.json. The plugin folders under claude-plugin/ are the canonical
// source for skill content — this script only syncs versions.
import fs from 'node:fs';
import path from 'node:path';
import url from 'node:url';

const ROOT = path.resolve(path.dirname(url.fileURLToPath(import.meta.url)), '..');

const PLUGINS = [
  {
    pluginDir: 'nextjs',
    versionFrom: 'packages/nextjs/package.json',
  },
  {
    pluginDir: 'express',
    versionFrom: 'packages/node-backend/package.json',
  },
  {
    pluginDir: 'fastify',
    versionFrom: 'packages/node-backend/package.json',
  },
];

function syncPluginVersion({ pluginDir, versionFrom }) {
  const manifestPath = path.join(ROOT, 'claude-plugin', pluginDir, '.claude-plugin', 'plugin.json');
  const versionPkgPath = path.join(ROOT, versionFrom);

  if (!fs.existsSync(manifestPath)) {
    throw new Error(`plugin manifest missing: ${manifestPath}`);
  }
  if (!fs.existsSync(versionPkgPath)) {
    throw new Error(`version package.json missing: ${versionPkgPath}`);
  }

  const version = JSON.parse(fs.readFileSync(versionPkgPath, 'utf8')).version;
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

  if (manifest.version === version) {
    return { pluginDir, version, changed: false };
  }

  manifest.version = version;
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
  return { pluginDir, version, changed: true };
}

const results = PLUGINS.map(syncPluginVersion);

console.log('claude-plugin manifest versions');
for (const r of results) {
  const tag = r.changed ? 'updated' : 'unchanged';
  console.log(`  ${r.pluginDir}: v${r.version} (${tag})`);
}
