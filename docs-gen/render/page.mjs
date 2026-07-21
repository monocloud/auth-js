// Top-level page assembler for a single documentable reflection:
// frontmatter + H1 + body. Body placement (declaration line, description,
// sections) is owned by the per-kind renderers.

import { ReflectionKind } from 'typedoc';
import { frontmatter, heading, sectionsToMarkdown } from './markdown.mjs';
import { categoryMeta, OTHER_CATEGORY, RENDER_OPTIONS } from '../manifest.mjs';
import { renderClassBody } from './class.mjs';
import { renderTypeBody } from './type-alias.mjs';
import { renderEnumBody } from './enum.mjs';
import { renderFunctionBody } from './function.mjs';
import { renderHookBody } from './hook.mjs';
import { renderComponentBody } from './component.mjs';
import { renderDescription } from './comment.mjs';

/**
 * @param {object} args
 * @param {import('typedoc').DeclarationReflection} args.ref
 * @param {string|null} args.categoryTag  raw @category tag value (null -> Other)
 * @param {string} args.rootSdk           frontmatter rootSdk label
 * @param {string} [args.framework]       frontmatter framework label
 * @param {string} [args.description]     SEO description (already computed)
 * @param {import('./type.mjs').RenderContext} args.ctx
 */
export function renderPage({ ref, categoryTag, rootSdk, framework, description, ctx }) {
  const meta = categoryMeta(categoryTag);

  const fm = frontmatter({
    rootSdk,
    title: ref.name,
    category: meta.label,
    framework,
    description: RENDER_OPTIONS.emitDescription && description ? description : undefined,
  });

  const body = renderBody(ref, meta, ctx);
  return sectionsToMarkdown([fm, heading(1, h1Title(ref, meta)), body]) + '\n';
}

function h1Title(ref, meta) {
  const prefix = RENDER_OPTIONS.titlePrefixOverrides[meta.label] ?? meta.prefix;
  if (!prefix) {
    return ref.name.includes('/') ? ref.name.split('/').pop() : ref.name;
  }
  if (prefix === 'Component') return `Component: &lt;${ref.name}&gt;`;
  return `${prefix}: ${ref.name}`;
}

function renderBody(ref, meta, ctx) {
  switch (meta.label) {
    case 'Classes':
      return renderClassBody(ref, ctx);
    case 'Error Classes':
      return renderClassBody(ref, ctx, { extendedBy: true });
    case 'Components':
      return renderComponentBody(ref, ctx);
    case 'Hooks':
      return renderHookBody(ref, ctx);
    case 'Functions':
      return renderFunctionBody(ref, ctx);
    case 'Enums':
      return renderEnumBody(ref, ctx);
    case 'Types':
    case 'Handler Types':
      if (ref.kind === ReflectionKind.Function) return renderFunctionBody(ref, ctx);
      return renderTypeBody(ref, ctx);
    default:
      // Other: utility functions render as a function body; anything else
      // falls back to its description.
      if (ref.signatures?.length) return renderFunctionBody(ref, ctx);
      return renderDescription(ref.comment, ctx);
  }
}
