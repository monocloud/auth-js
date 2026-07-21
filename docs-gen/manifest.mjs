// Single source of truth for the controlled markdown emitter.
//
// Everything that decides *what* gets emitted and *how it is labelled* lives
// here, so the rendering layer (render/*) stays mechanical. This is the file
// you edit to retune the docs: package labels, category mapping, URL shape,
// and the render toggles (show/hide Returns, Examples, parameter format, …).

// ---------------------------------------------------------------------------
// Packages
// ---------------------------------------------------------------------------
//
// Listed in canonical-owner priority order. `slug` is the URL segment used by
// the Docs site (/sdks/<slug>/…); `rootSdk` is the human label written into
// frontmatter and used by the site to group a type under the right SDK.

export const PACKAGES = {
  '@monocloud/auth-core': { slug: 'nodejs', rootSdk: 'Node.js', dir: 'core' },
  '@monocloud/auth-web-js': { slug: 'web-js', rootSdk: 'JavaScript', dir: 'web-js' },
  '@monocloud/auth-react': { slug: 'react', rootSdk: 'React', dir: 'react' },
  '@monocloud/auth-node-core': { slug: 'nodejs-core', rootSdk: 'Node.js Core', dir: 'node-core' },
  '@monocloud/auth-nextjs': { slug: 'nextjs', rootSdk: 'Next.js', dir: 'nextjs' },
  '@monocloud/backend-node': { slug: 'nodejs-backend', rootSdk: 'Node.js Backend', dir: 'node-backend' },
};

// Order packages appear in the top-level modules.md package list.
export const PACKAGE_ORDER = Object.keys(PACKAGES);

// Project name (typedoc `name`) — used for the README/modules H1 + title.
export const PROJECT_NAME = 'MonoCloud Authentication SDK';

// Framework-specific entry points (backend-node) route to their own SDK slug.
// Keyed by the module's leading path segment.
export const FRAMEWORK_SLUGS = {
  express: 'express-backend',
  fastify: 'fastify-backend',
};

// Module path segment -> framework label (frontmatter `framework:`).
export const FRAMEWORK_LABELS = {
  express: 'Express',
  fastify: 'Fastify',
};

// ---------------------------------------------------------------------------
// Categories
// ---------------------------------------------------------------------------
//
// Keyed by the source-level JSDoc `@category` tag value. `folder` is the
// on-disk directory; `label` is the frontmatter `category:` value; `prefix`
// is the H1 title prefix ("Class: Foo"); `url` is the path segment used when
// linking to a member of this category. A reflection with no `@category` tag
// falls into OTHER_CATEGORY below.

export const CATEGORIES = {
  Classes: { folder: 'Classes', label: 'Classes', prefix: 'Class', url: 'classes' },
  Components: { folder: 'Components', label: 'Components', prefix: 'Component', url: 'components' },
  'Error Classes': { folder: 'Error_Classes', label: 'Error Classes', prefix: 'Error Class', url: 'error-classes' },
  Functions: { folder: 'Functions', label: 'Functions', prefix: 'Function', url: 'functions' },
  Hooks: { folder: 'Hooks', label: 'Hooks', prefix: 'Hook', url: 'hooks' },
  Types: { folder: 'Types', label: 'Types', prefix: 'Type', url: 'types' },
  'Types (Enums)': { folder: 'Types_(Enums)', label: 'Enums', prefix: 'Enum', url: 'enums' },
  'Types (Handler)': { folder: 'Types_(Handler)', label: 'Handler Types', prefix: 'Handler Type', url: 'handler-types' },
};

// Bucket for reflections without an `@category` tag (utility functions) and
// for module/package index pages. NOTE: `url` is intentionally undefined to
// reproduce the current site's link shape (…/api-reference/undefined/<name>).
// Set `url: 'other'` here once the Docs site adds an `other` route.
export const OTHER_CATEGORY = {
  folder: 'Other',
  label: 'Other',
  prefix: null,
  url: undefined,
};

// Order categories appear in module index pages ("## Classes", "## Types", …).
export const INDEX_CATEGORY_ORDER = [
  'Classes',
  'Components',
  'Error Classes',
  'Functions',
  'Hooks',
  'Types',
  'Types (Enums)',
  'Types (Handler)',
];

// ---------------------------------------------------------------------------
// Render options — the control surface
// ---------------------------------------------------------------------------
//
// Defaults reproduce the current production output exactly. Flip these to
// change what the renderers emit; nothing else needs to change.

export const RENDER_OPTIONS = {
  // Returns -----------------------------------------------------------------
  showReturns: true, // emit the "Returns" section for functions/methods/hooks
  showReturnsForComponents: false, // components never show a Returns section

  // Examples / remarks ------------------------------------------------------
  showExamples: true, // emit `@example` blocks
  showRemarks: true, // emit `@remarks` content

  // Parameters / properties -------------------------------------------------
  parametersFormat: 'table', // 'table' (only table is implemented today)
  dropEmptyTableColumns: true, // drop a table column when every cell is blank
  showParameters: true,

  // Members -----------------------------------------------------------------
  showInheritedFrom: true, // emit "Inherited from" under constructors/methods
  showImplementationOf: false, // current pipeline strips "Implementation of"
  showExtendedBy: false, // current pipeline strips "Extended by"

  // Titles / headings -------------------------------------------------------
  // Per-category H1 prefix override. `null`/missing -> use CATEGORIES prefix.
  titlePrefixOverrides: {},

  // Frontmatter -------------------------------------------------------------
  emitDescription: true, // emit the SEO `description:` frontmatter key
  descriptionMaxLength: 160,
  descriptionHardMaxLength: 200,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** `@monocloud/auth-core` -> `_monocloud_auth-core` */
export function packageFileSlug(pkgName) {
  return pkgName.replace(/@/g, '_').replace(/\//g, '_');
}

/** A submodule reflection name (`frameworks/express`) -> `frameworks_express`. */
export function moduleSegment(moduleName) {
  return moduleName.replace(/\//g, '_');
}

/** Resolve category meta from a `@category` tag value (or null -> Other). */
export function categoryMeta(tagValue) {
  if (tagValue && CATEGORIES[tagValue]) return CATEGORIES[tagValue];
  return OTHER_CATEGORY;
}

/** Map a frontmatter category label back to its URL segment (for links). */
export function urlSegmentForLabel(label) {
  for (const meta of Object.values(CATEGORIES)) {
    if (meta.label === label) return meta.url;
  }
  return OTHER_CATEGORY.url; // undefined for Other
}
