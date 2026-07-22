// Flat ("declarations") member rendering.
//
// typedoc-plugin-markdown renders a container's members as a grouped Properties
// table + Methods section when the reflection has `groups`. When `groups` is
// empty (e.g. interfaces/classes brought in via `export type { … }` re-exports),
// it falls back to rendering each member as its own `## name` section. This
// module reproduces that flat layout.

import { ReflectionKind } from 'typedoc';
import { heading, inlineCode, sectionsToMarkdown } from './markdown.mjs';
import { renderType } from './type.mjs';
import { renderDescription, renderExamples, partsToMarkdown } from './comment.mjs';
import {
  renderSignature,
  renderMemberSignatures,
  renderParamsOrProps,
  renderReturns,
} from './signature.mjs';
import { renderInheritedFrom, renderOverrides, propsTable } from './members.mjs';

/** Whether typedoc grouped this reflection's members (-> table) or not. */
export function hasGroups(ref) {
  return Array.isArray(ref.groups) && ref.groups.length > 0;
}

export function renderFlatMembers(ref, ctx) {
  const blocks = [];
  for (const m of ref.children ?? []) {
    if (m.flags?.isPrivate) continue;
    const b = renderFlatMember(m, ref, ctx);
    if (b) blocks.push(b);
  }
  return blocks.join('\n\n---\n\n');
}

function renderFlatMember(m, owner, ctx) {
  switch (m.kind) {
    case ReflectionKind.Constructor: {
      const sig = m.signatures?.[0];
      if (!sig) return '';
      return `${heading(2, 'Constructor')}\n\n${renderSignature(sig, {
        displayName: owner.name,
        asNew: true,
        headingLevel: 3,
        owner: m,
        ctx,
      })}`;
    }
    case ReflectionKind.Method:
      return `${heading(2, `${m.name}()`)}\n\n${renderMemberSignatures(m, m.name, 3, ctx)}`;
    case ReflectionKind.Property:
    case ReflectionKind.Variable:
      return renderFlatProperty(m, ctx);
    case ReflectionKind.Accessor:
      return renderFlatAccessor(m, ctx);
    default:
      return '';
  }
}

function modifierPrefix(m) {
  const mods = [];
  if (m.flags?.isProtected) mods.push('`protected`');
  if (m.flags?.isStatic) mods.push('`static`');
  if (m.flags?.isReadonly) mods.push('`readonly`');
  if (m.flags?.isOptional) mods.push('`optional`');
  return mods.length ? `${mods.join(' ')} ` : '';
}

function inheritFooter(m, ctx) {
  // Flat members are level-2 headings, so their inheritance line is level 3.
  return renderInheritedFrom(m, ctx, 3) || renderOverrides(m, ctx, 3);
}

function renderFlatProperty(m, ctx) {
  const isCallable = m.type?.type === 'reflection' && m.type.declaration?.signatures?.length;
  const def = m.defaultValue ? ` = ${inlineCode(m.defaultValue)}` : '';
  const declLine = `> ${modifierPrefix(m)}**${m.name}**: ${renderType(m.type, ctx)}${def}`;
  const head = `${heading(2, m.name)}\n${declLine}`;
  const desc = renderDescription(m.comment, ctx);
  const footer = inheritFooter(m, ctx);

  if (isCallable) {
    const sigs = m.type.declaration.signatures
      .map(sig => renderCallSignature(sig, ctx))
      .join('\n\n');
    return sectionsToMarkdown([head, desc, sigs, footer]);
  }

  return sectionsToMarkdown([
    head,
    desc,
    renderObjectNameTable(m.type, ctx),
    renderDefaultValueSection(m.comment, ctx),
    renderExamples(m.comment, ctx, 3),
    footer,
  ]);
}

// A property typed as an (array of) object literal expands to a "Name" table.
function renderObjectNameTable(type, ctx) {
  let decl = null;
  if (type?.type === 'reflection') decl = type.declaration;
  else if (type?.type === 'array' && type.elementType?.type === 'reflection')
    decl = type.elementType.declaration;
  if (!decl || decl.signatures?.length) return '';
  const props = (decl.children ?? []).filter(c => c.kind === ReflectionKind.Property);
  return propsTable(props, ctx, 'Name');
}

function renderDefaultValueSection(comment, ctx) {
  const tag = (comment?.blockTags ?? []).find(
    t => t.tag === '@default' || t.tag === '@defaultValue'
  );
  if (!tag) return '';
  const content = partsToMarkdown(tag.content ?? [], ctx).trim();
  return content ? `${heading(3, 'Default Value')}\n\n${content}` : '';
}

// A nameless call signature inside a callable property: `> (p): R`, its own
// description, then level-4 Parameters/Returns.
function renderCallSignature(sig, ctx) {
  const params = (sig.parameters ?? [])
    .map(p => `${inlineCode(`${p.name}${p.flags?.isOptional ? '?' : ''}`)}: ${renderType(p.type, ctx)}`)
    .join(', ');
  const line = `> (${params}): ${renderType(sig.type, ctx)}`;
  return sectionsToMarkdown([
    heading(3, 'Call Signature'),
    line,
    renderDescription(sig.comment, ctx),
    renderParamsOrProps(sig.parameters ?? [], ctx, 4),
    renderReturns(sig, ctx, 4),
  ]);
}

function renderFlatAccessor(m, ctx) {
  const get = m.getSignature;
  const declLine = `> ${modifierPrefix(m)}**${m.name}**: ${get ? renderType(get.type, ctx) : '`unknown`'}`;
  return sectionsToMarkdown([
    `${heading(2, m.name)}\n${declLine}`,
    renderDescription((get ?? m).comment, ctx),
    inheritFooter(m, ctx),
  ]);
}
