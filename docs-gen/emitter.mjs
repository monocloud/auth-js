// Controlled markdown emitter for the MonoCloud SDK docs.
//
// Replaces typedoc-plugin-markdown + hook.mjs + post-generate.mjs with a
// fully-owned pipeline:
//   - re-exports are materialised as full declarations (inline-references),
//     so every SDK keeps its own copy of the types it surfaces (unchanged
//     behaviour — one file per (package, module, type));
//   - per-kind renderers (render/*) produce the page body;
//   - URLs are computed at emit time (no link-rewriting post-pass).
//
// What it emits, per merged project: one page per documentable declaration,
// one index page per submodule, one index page per package, plus the
// top-level README.md and modules.md. See manifest.mjs for all the knobs.

import fs from 'node:fs';
import path from 'node:path';
import prettier from 'prettier';
import { ReflectionKind } from 'typedoc';
import { registerInlineReferences } from './inline-references.mjs';
import {
  PACKAGES,
  PACKAGE_ORDER,
  PROJECT_NAME,
  FRAMEWORK_SLUGS,
  INDEX_CATEGORY_ORDER,
  OTHER_CATEGORY,
  categoryMeta,
  packageFileSlug,
  moduleSegment,
} from './manifest.mjs';
import { renderPage } from './render/page.mjs';
import {
  frontmatter,
  heading,
  bulletList,
  link,
  sectionsToMarkdown,
} from './render/markdown.mjs';
import { computeDescription } from './description.mjs';
import { readCategoryTag, frameworkForSegment, kindGroupName } from './reflect.mjs';
import { buildLinkResolver, urlForUnit } from './links.mjs';

const OUTPUT_NAME = 'monocloud-markdown';

// Each page is formatted with Prettier (markdown), reproducing the previous
// pipeline's `formatWithPrettier` step: aligns tables, normalises blank lines
// before lists, strips heading indentation — all render-neutral formatting.
// Mirrors the repo .prettierrc.
const PRETTIER_OPTS = {
  parser: 'markdown',
  printWidth: 80,
  proseWrap: 'preserve',
  tabWidth: 2,
  endOfLine: 'lf',
  // Prettier DEFAULTS for embedded code (singleQuote:false, embedded:'auto') —
  // the previous pipeline formatted ```ts/```typescript blocks with double
  // quotes. The example fences use a `tsx:path tab="…"` info string (unknown
  // language), so Prettier leaves those untouched.
};

async function writeFormatted(filePath, md, logger) {
  // Frontmatter is added post-format in the previous pipeline, so keep it raw
  // (Prettier would rewrite "title" double-quotes to single). Format only the
  // markdown body.
  let out = md;
  try {
    const m = md.match(/^(---\n[\s\S]*?\n---\n)([\s\S]*)$/);
    if (m) {
      const body = await prettier.format(m[2], PRETTIER_OPTS);
      out = `${m[1]}\n${body}`;
    } else {
      out = await prettier.format(md, PRETTIER_OPTS);
    }
  } catch (e) {
    logger.warn(`[emitter] prettier failed for ${path.basename(filePath)}: ${e.message}`);
  }
  fs.writeFileSync(filePath, out);
}

const DOCUMENTABLE = new Set([
  ReflectionKind.Class,
  ReflectionKind.Interface,
  ReflectionKind.TypeAlias,
  ReflectionKind.Enum,
  ReflectionKind.Function,
  ReflectionKind.Variable,
]);

/** @param {import('typedoc').Application} app */
export const load = app => {
  registerInlineReferences(app);
  app.outputs.addOutput(OUTPUT_NAME, async (outDir, project) => {
    await emit(project, outDir, app.logger);
  });
};

async function emit(project, outDir, logger) {
  const repoRoot = process.cwd(); // typedoc runs from auth-js/
  const typeUnits = [];
  const modulePages = [];
  const packagePages = [];

  for (const pkgModule of project.children ?? []) {
    if (pkgModule.kind !== ReflectionKind.Module) continue;
    const pkgName = pkgModule.name;
    const pkgInfo = PACKAGES[pkgName];
    if (!pkgInfo) {
      logger.warn(`[emitter] unknown package "${pkgName}" — skipped`);
      continue;
    }
    const pkgFileSlug = packageFileSlug(pkgName);
    const submodules = (pkgModule.children ?? []).filter(
      c => c.kind === ReflectionKind.Module || c.kind === ReflectionKind.Namespace
    );

    if (submodules.length === 0) {
      // Single-entry package (react): types live directly under the package.
      const directUnits = [];
      for (const child of pkgModule.children ?? []) {
        if (!DOCUMENTABLE.has(child.kind)) continue;
        const u = makeTypeUnit(child, pkgName, pkgInfo, pkgFileSlug, null);
        typeUnits.push(u);
        directUnits.push(u);
      }
      packagePages.push({ pkgName, pkgInfo, pkgFileSlug, submoduleList: [], directUnits });
    } else {
      const submoduleList = [];
      for (const sub of submodules) {
        const units = [];
        for (const child of sub.children ?? []) {
          if (!DOCUMENTABLE.has(child.kind)) continue;
          const u = makeTypeUnit(child, pkgName, pkgInfo, pkgFileSlug, sub.name);
          typeUnits.push(u);
          units.push(u);
        }
        const seg = moduleSegment(sub.name);
        const fw = frameworkForSegment(seg);
        const slug = fw ? FRAMEWORK_SLUGS[fw.toLowerCase()] : pkgInfo.slug;
        modulePages.push({
          moduleName: sub.name,
          seg,
          pkgFileSlug,
          slug,
          rootSdk: pkgInfo.rootSdk,
          units,
        });
        submoduleList.push({ moduleName: sub.name, seg, slug });
      }
      packagePages.push({ pkgName, pkgInfo, pkgFileSlug, submoduleList, directUnits: null });
    }
  }

  const resolver = buildLinkResolver(typeUnits);

  fs.mkdirSync(outDir, { recursive: true });
  for (const u of typeUnits) await writeTypePage(u, resolver, outDir, logger);
  for (const m of modulePages) await writeModulePage(m, outDir, logger);
  for (const p of packagePages) await writePackagePage(p, repoRoot, outDir, logger);
  await writeReadme(repoRoot, outDir, logger);
  await writeModulesIndex(outDir, logger);

  logger.info(
    `[emitter] wrote ${typeUnits.length} type pages, ${modulePages.length} module pages, ` +
      `${packagePages.length} package pages, README.md, modules.md`
  );
}

// ---------------------------------------------------------------------------
// Units
// ---------------------------------------------------------------------------

function makeTypeUnit(ref, pkgName, pkgInfo, pkgFileSlug, moduleName) {
  const seg = moduleName ? moduleSegment(moduleName) : null;
  const fw = frameworkForSegment(seg);
  const slug = fw ? FRAMEWORK_SLUGS[fw.toLowerCase()] : pkgInfo.slug;
  const categoryTag = readCategoryTag(ref);
  const meta = categoryMeta(categoryTag);
  const fileName = seg
    ? `${pkgFileSlug}.${seg}.${ref.name}.md`
    : `${pkgFileSlug}.${ref.name}.md`;
  return {
    ref,
    pkgName,
    pkgFileSlug,
    moduleName,
    seg,
    framework: fw,
    slug,
    rootSdk: pkgInfo.rootSdk,
    categoryTag,
    meta,
    fileName,
    folder: meta.folder,
  };
}

// ---------------------------------------------------------------------------
// Writers
// ---------------------------------------------------------------------------

async function writeTypePage(u, resolver, outDir, logger) {
  const ctx = {
    linkFor: r => resolver.resolve(r, u.pkgName, u.framework, u.ref.id),
    linkForExact: r => resolver.resolveExact(r, u.pkgName, u.framework, u.ref.id),
  };
  const description = computeDescription(u.ref, u.meta.label, u.rootSdk);
  const md = renderPage({
    ref: u.ref,
    categoryTag: u.categoryTag,
    rootSdk: u.rootSdk,
    framework: u.framework,
    description,
    ctx,
  });
  const dir = path.join(outDir, u.folder);
  fs.mkdirSync(dir, { recursive: true });
  await writeFormatted(path.join(dir, u.fileName), md, logger);
}

async function writeModulePage(m, outDir, logger) {
  const h1 = m.moduleName.includes('/') ? m.moduleName.split('/').pop() : m.moduleName;
  const framework = frameworkForSegment(m.seg);
  const fm = frontmatter({
    rootSdk: m.rootSdk,
    title: m.moduleName,
    category: OTHER_CATEGORY.label,
    framework,
  });
  const body = renderIndexGroups(m.units);
  const md = sectionsToMarkdown([fm, heading(1, h1), body]) + '\n';
  const dir = path.join(outDir, OTHER_CATEGORY.folder);
  fs.mkdirSync(dir, { recursive: true });
  await writeFormatted(path.join(dir, `${m.pkgFileSlug}.${m.seg}.md`), md, logger);
}

async function writePackagePage(p, repoRoot, outDir, logger) {
  const h1 = p.pkgName.split('/').pop();
  const fm = frontmatter({
    rootSdk: p.pkgInfo.rootSdk,
    title: p.pkgName,
    category: OTHER_CATEGORY.label,
  });
  const readme = readReadme(path.join(repoRoot, 'packages', p.pkgInfo.dir, 'README.md'), logger);

  let tail;
  if (p.submoduleList.length > 0) {
    const mods = [...p.submoduleList].sort((a, b) => a.moduleName.localeCompare(b.moduleName));
    const items = mods.map(m =>
      link(m.moduleName, `/sdks/${m.slug}/api-reference/${OTHER_CATEGORY.url}/${m.seg}`)
    );
    tail = `${heading(2, 'Modules')}\n\n${bulletList(items)}`;
  } else {
    tail = renderIndexGroups(p.directUnits);
  }

  const body = sectionsToMarkdown([readme, tail]);
  const md = sectionsToMarkdown([fm, heading(1, h1), body]) + '\n';
  const dir = path.join(outDir, OTHER_CATEGORY.folder);
  fs.mkdirSync(dir, { recursive: true });
  await writeFormatted(path.join(dir, `${p.pkgFileSlug}.md`), md, logger);
}

async function writeReadme(repoRoot, outDir, logger) {
  const fm = frontmatter({ rootSdk: 'Docs', title: PROJECT_NAME, category: OTHER_CATEGORY.label });
  const readme = readReadme(path.join(repoRoot, 'README.md'), logger);
  const md = sectionsToMarkdown([fm, heading(1, PROJECT_NAME), readme]) + '\n';
  await writeFormatted(path.join(outDir, 'README.md'), md, logger);
}

async function writeModulesIndex(outDir, logger) {
  const fm = frontmatter({ rootSdk: 'Docs', title: PROJECT_NAME, category: OTHER_CATEGORY.label });
  const items = PACKAGE_ORDER.map(name =>
    link(name, `/sdks/${PACKAGES[name].slug}/api-reference/${OTHER_CATEGORY.url}/${packageFileSlug(name)}`)
  );
  const body = `${heading(2, 'Packages')}\n\n${bulletList(items)}`;
  const md = sectionsToMarkdown([fm, heading(1, PROJECT_NAME), body]) + '\n';
  await writeFormatted(path.join(outDir, 'modules.md'), md, logger);
}

// ---------------------------------------------------------------------------
// Index page bodies (grouped member lists)
// ---------------------------------------------------------------------------

function renderIndexGroups(units) {
  const groups = new Map();
  for (const u of units) {
    const group = u.categoryTag ?? kindGroupName(u.ref.kind);
    if (!groups.has(group)) groups.set(group, []);
    groups.get(group).push(u);
  }

  const order = [...INDEX_CATEGORY_ORDER];
  for (const g of groups.keys()) if (!order.includes(g)) order.push(g);

  const sections = [];
  for (const group of order) {
    const items = groups.get(group);
    if (!items || items.length === 0) continue;
    const list = bulletList(items.map(u => link(u.ref.name, urlForUnit(u))));
    sections.push(`${heading(2, group)}\n\n${list}`);
  }
  return sections.join('\n\n');
}

function readReadme(filePath, logger) {
  try {
    return fs.readFileSync(filePath, 'utf-8').replace(/\r\n/g, '\n').trim();
  } catch {
    logger.warn(`[emitter] README not found: ${filePath}`);
    return '';
  }
}
