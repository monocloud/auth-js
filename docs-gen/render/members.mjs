// Property/member tables shared by class, interface and type-alias renderers.

import { ReflectionKind } from 'typedoc';
import { table, escapeTableCell, heading, inlineCode, link } from './markdown.mjs';
import { renderType } from './type.mjs';
import { renderSummary, partsToMarkdown } from './comment.mjs';

// Block tags appended inline into a member's table-cell description. Only
// @example is surfaced (matches the previous output); its fenced code block
// is inlined to a code span since it lives inside a table cell.
const INLINE_CELL_TAGS = [['@example', 'Example']];

/** Description for a member table cell: summary + inline @example. */
export function renderMemberDescription(comment, ctx) {
  if (!comment) return '';
  let out = renderSummary(comment, ctx);
  for (const [tag, label] of INLINE_CELL_TAGS) {
    for (const t of comment.blockTags ?? []) {
      if (t.tag !== tag) continue;
      const content = inlineCodeExample(partsToMarkdown(t.content ?? [], ctx));
      out = `${out} **${label}** ${content}`.trim();
    }
  }
  return out;
}

// Strip a single fenced code block down to an inline code span.
function inlineCodeExample(text) {
  const m = text.trim().match(/^```[^\n]*\n([\s\S]*?)\n?```$/);
  const inner = (m ? m[1] : text).trim();
  return inner.includes('`') ? `\`\` ${inner} \`\`` : `\`${inner}\``;
}

/**
 * Render a properties table.
 * @param {import('typedoc').DeclarationReflection[]} props
 * @param {object} [opts] { level=2, title='Properties' }
 */
export function renderPropertiesTable(props, ctx, opts = {}) {
  const { level = 2, title = 'Properties', header = 'Property' } = opts;
  const t = propsTable(props, ctx, header);
  if (!t) return '';
  return `${heading(level, title)}\n\n${t}`;
}

/** Just the table (no heading). `header` is the first column label. */
export function propsTable(props, ctx, header = 'Property') {
  if (!props || props.length === 0) return '';
  // Modifiers (readonly/protected/…) are hidden in table mode (the previous
  // pipeline set tableColumnSettings.hideModifiers); only the optional `?` is
  // kept since it's part of the name.
  const rows = props.map(p => {
    const opt = p.flags?.isOptional ? '?' : '';
    return [
      inlineCode(`${p.name}${opt}`),
      renderType(memberType(p), ctx),
      escapeTableCell(renderMemberDescription(memberComment(p), ctx)),
    ];
  });
  return table([header, 'Type', 'Description'], rows);
}

/**
 * Collect the property reflections a props-type resolves to, handling a direct
 * reference, an anonymous object, or an intersection (whose members are merged
 * and sorted) — e.g. a component whose props are `Foo & { ref }`.
 */
export function collectProps(type) {
  if (!type) return [];
  if (type.type === 'reference' && type.reflection) {
    const t = type.reflection;
    const decl = t.type?.type === 'reflection' ? t.type.declaration : t;
    return (decl?.children ?? []).filter(c => c.kind === ReflectionKind.Property);
  }
  if (type.type === 'reflection') {
    return (type.declaration?.children ?? []).filter(c => c.kind === ReflectionKind.Property);
  }
  if (type.type === 'intersection') {
    const merged = new Map();
    for (const member of type.types) {
      for (const p of collectProps(member)) if (!merged.has(p.name)) merged.set(p.name, p);
    }
    return [...merged.values()].sort((a, b) => a.name.localeCompare(b.name));
  }
  return [];
}

/** A property may carry its type directly or via a get-signature (accessor). */
function memberType(p) {
  if (p.type) return p.type;
  if (p.getSignature?.type) return p.getSignature.type;
  return p.setSignature?.parameters?.[0]?.type;
}

function memberComment(p) {
  return p.comment ?? p.getSignature?.comment ?? p.signatures?.[0]?.comment;
}

/**
 * Split a container's children into { props, methods, ctors, accessors },
 * skipping private/external members.
 */
export function partitionMembers(ref) {
  const props = [];
  const methods = [];
  const ctors = [];
  const accessors = [];
  for (const child of ref.children ?? []) {
    // Inherited members (e.g. the Error constructor) carry isExternal but are
    // still documented; only private members are dropped here (excludePrivate
    // already removed them at the TypeDoc level).
    if (child.flags?.isPrivate) continue;
    switch (child.kind) {
      case ReflectionKind.Property:
      case ReflectionKind.Variable:
        props.push(child);
        break;
      case ReflectionKind.Accessor:
        accessors.push(child);
        break;
      case ReflectionKind.Method:
        methods.push(child);
        break;
      case ReflectionKind.Constructor:
        ctors.push(child);
        break;
    }
  }
  return { props, methods, ctors, accessors };
}

/** Render the "Inherited from" line for a member, or '' when not inherited. */
export function renderInheritedFrom(reflection, ctx, level = 4) {
  const ref = reflection.inheritedFrom;
  if (!ref) return '';
  return inheritanceLine('Inherited from', ref, ctx, level);
}

/** Render the "Overrides" line for a member, or ''. */
export function renderOverrides(reflection, ctx, level = 4) {
  const ref = reflection.overwrites;
  if (!ref) return '';
  return inheritanceLine('Overrides', ref, ctx, level);
}

function inheritanceLine(label, refType, ctx, level) {
  // refType.name is like "MonoCloudAuthBaseError.constructor".
  const target = refType.reflection;
  const fullName = refType.name ?? '';
  const [className, memberName] = splitOwnerMember(fullName, target);

  let body;
  if (target && className && memberName) {
    const owner = target.parent;
    const ownerUrl = owner && ctx.linkFor ? ctx.linkFor(owner) : null;
    const memberUrl = ownerUrl ? `${ownerUrl}#${memberName.toLowerCase()}` : null;
    const ownerPart = ownerUrl ? link(inlineCode(className), ownerUrl) : inlineCode(className);
    const memberPart = memberUrl ? link(inlineCode(memberName), memberUrl) : inlineCode(memberName);
    body = `${ownerPart}.${memberPart}`;
  } else {
    body = inlineCode(fullName);
  }
  return `${heading(level, label)}\n\n${body}`;
}

function splitOwnerMember(fullName, target) {
  const dot = fullName.lastIndexOf('.');
  if (dot > 0) return [fullName.slice(0, dot), fullName.slice(dot + 1)];
  if (target?.parent) return [target.parent.name, target.name];
  return [null, null];
}
