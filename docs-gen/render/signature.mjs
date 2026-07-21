// Render function/method/constructor signatures: the `> **name**(…)` line,
// description, Parameters table, Returns, Inherited-from and Examples.

import { ReflectionKind } from 'typedoc';
import { RENDER_OPTIONS } from '../manifest.mjs';
import { table, escapeTableCell, heading, inlineCode, sectionsToMarkdown } from './markdown.mjs';
import { renderType } from './type.mjs';
import {
  renderDescription,
  renderExamples,
  returnsDescription,
  renderThrows,
  renderSummary,
  renderRemarks,
  renderSee,
} from './comment.mjs';
import {
  renderMemberDescription,
  renderInheritedFrom,
  renderOverrides,
  renderPropertiesTable,
} from './members.mjs';

/**
 * @param {import('typedoc').SignatureReflection} sig
 * @param {object} opts
 * @param {string} opts.displayName
 * @param {boolean} [opts.asNew] render as `new <Name>(…)` (constructors)
 * @param {boolean} [opts.static]
 * @param {number} [opts.headingLevel=3] level for Parameters/Returns/Examples
 * @param {boolean} [opts.showReturns]
 * @param {import('typedoc').DeclarationReflection} [opts.owner] member reflection
 *        carrying inheritedFrom/overwrites (constructors/methods)
 * @param {RenderContext} opts.ctx
 */
export function renderSignature(sig, opts) {
  const { ctx, headingLevel = 3, owner } = opts;
  const showReturns = opts.showReturns ?? RENDER_OPTIONS.showReturns;

  const sigLine = renderSignatureLine(sig, opts);
  const desc = renderDescription(sig.comment, ctx);
  const typeParams = renderTypeParametersSection(sig.typeParameters, ctx, headingLevel);
  const params = RENDER_OPTIONS.showParameters
    ? renderParamsOrProps(sig.parameters ?? [], ctx, headingLevel)
    : '';
  const returns = showReturns ? renderReturns(sig, ctx, headingLevel) : '';
  const remarks = renderRemarks(sig.comment, ctx, headingLevel);
  const examples = renderExamples(sig.comment, ctx, headingLevel);
  const see = renderSee(sig.comment, ctx, headingLevel);
  const throws = renderThrows(sig.comment, ctx, headingLevel);
  const inherited =
    RENDER_OPTIONS.showInheritedFrom && owner
      ? renderInheritedFrom(owner, ctx, headingLevel) || renderOverrides(owner, ctx, headingLevel)
      : '';

  return sectionsToMarkdown([
    sigLine,
    desc,
    typeParams,
    params,
    returns,
    remarks,
    examples,
    see,
    throws,
    inherited,
  ]);
}

/** Render several signatures (overloads) separated by horizontal rules. */
export function renderSignatures(signatures, opts) {
  if (!signatures || signatures.length === 0) return '';
  return signatures.map(sig => renderSignature(sig, opts)).join('\n\n---\n\n');
}

/**
 * Render a member's signatures under its `name()` heading. A single signature
 * renders inline at `baseLevel`; multiple overloads each get a "Call Signature"
 * heading at `baseLevel` with sub-sections at `baseLevel + 1`.
 */
export function renderMemberSignatures(member, displayName, baseLevel, ctx) {
  const sigs = member.signatures ?? [];
  if (sigs.length === 0) return '';
  const base = { displayName, static: !!member.flags?.isStatic, owner: member, ctx };
  if (sigs.length === 1) {
    return renderSignature(sigs[0], { ...base, headingLevel: baseLevel });
  }
  return sigs
    .map(
      sig =>
        `${heading(baseLevel, 'Call Signature')}\n\n${renderSignature(sig, {
          ...base,
          headingLevel: baseLevel + 1,
        })}`
    )
    .join('\n\n');
}

// Signature line ------------------------------------------------------------

function renderSignatureLine(sig, opts) {
  const { displayName, asNew = false, static: isStatic = false, ctx } = opts;
  const modifiers = isStatic ? '`static` ' : '';
  const typeParams = renderTypeParametersInline(sig.typeParameters);
  const params = renderInlineParameters(sig.parameters ?? [], ctx);
  const returnType = renderType(sig.type, ctx);
  const namePart = asNew ? `**new ${displayName}**` : `**${displayName}**`;
  return `> ${modifiers}${namePart}${typeParams}(${params}): ${returnType}`;
}

// A parameter with a default value is optional even if `isOptional` is unset.
const paramOptional = p => p.flags?.isOptional || p.defaultValue != null;

function renderInlineParameters(params, ctx) {
  return params
    .map(p => {
      const opt = paramOptional(p) ? '?' : '';
      const rest = p.flags?.isRest ? '...' : '';
      return `${rest}${inlineCode(`${p.name}${opt}`)}: ${renderType(p.type, ctx)}`;
    })
    .join(', ');
}

// In the signature line, type parameters appear as names only (`\<T\>`);
// their constraints/defaults live in the "Type Parameters" section below.
export function renderTypeParametersInline(typeParams) {
  if (!typeParams || typeParams.length === 0) return '';
  return `\\<${typeParams.map(tp => inlineCode(tp.name)).join(', ')}\\>`;
}

export function renderTypeParametersSection(typeParams, ctx, level) {
  if (!typeParams || typeParams.length === 0) return '';
  const rows = typeParams.map(tp => {
    let cell = inlineCode(tp.name);
    if (tp.type) cell += ` _extends_ ${renderType(tp.type, ctx)}`;
    // Note: the default type (`= X`) is intentionally not shown — matches the
    // previous output.
    return [cell, escapeTableCell(renderSummary(tp.comment, ctx))];
  });
  // The Description column is dropped automatically when no type param is
  // documented (drop-empty-columns).
  return `${heading(level, 'Type Parameters')}\n\n${table(['Type Parameter', 'Description'], rows)}`;
}

// A single `props` parameter that references a documented type renders as a
// "Props" section (the props type's properties); everything else is a normal
// "Parameters" table. Anonymous object-literal `props` stay as Parameters.
export function renderParamsOrProps(params, ctx, level) {
  if (params.length === 1 && params[0].name === 'props') {
    const decl = resolveReferencedProps(params[0].type);
    if (decl) {
      const props = (decl.children ?? []).filter(c => c.kind === ReflectionKind.Property);
      if (props.length) return renderPropertiesTable(props, ctx, { title: 'Props', level });
    }
  }
  return renderParametersTable(params, ctx, level);
}

function resolveReferencedProps(type) {
  if (type?.type !== 'reference' || !type.reflection) return null;
  const t = type.reflection;
  if (t.type?.type === 'reflection') return t.type.declaration; // alias of object
  return t; // interface
}

// Parameters table (with anonymous object-literal expansion) -----------------

export function renderParametersTable(params, ctx, level) {
  if (params.length === 0) return '';
  const rows = [];
  for (const p of params) {
    // In the table (unlike the signature line) a default value alone does NOT
    // add `?` — only an explicitly optional parameter does.
    const opt = p.flags?.isOptional ? '?' : '';
    const rest = p.flags?.isRest ? '...' : '';
    rows.push([
      inlineCode(`${rest}${p.name}${opt}`),
      renderType(p.type, ctx),
      escapeTableCell(renderMemberDescription(p.comment, ctx)),
    ]);
    expandObjectParam(`${p.name}`, p.type, ctx, rows);
  }
  return `${heading(level, 'Parameters')}\n\n${table(['Parameter', 'Type', 'Description'], rows)}`;
}

function expandObjectParam(prefix, type, ctx, rows, depth = 0) {
  if (depth > 3) return;
  const decl = type?.type === 'reflection' ? type.declaration : null;
  if (!decl || decl.signatures?.length) return; // skip callables
  for (const child of decl.children ?? []) {
    if (child.kind !== ReflectionKind.Property) continue;
    const opt = child.flags?.isOptional ? '?' : '';
    rows.push([
      inlineCode(`${prefix}.${child.name}${opt}`),
      renderType(child.type, ctx),
      escapeTableCell(renderMemberDescription(child.comment, ctx)),
    ]);
    expandObjectParam(`${prefix}.${child.name}`, child.type, ctx, rows, depth + 1);
  }
}

// Returns -------------------------------------------------------------------

export function renderReturns(sig, ctx, level) {
  if (!sig.type) return '';
  const typeStr = renderType(sig.type, ctx);
  const desc = returnsDescription(sig.comment, ctx);
  return sectionsToMarkdown([heading(level, 'Returns'), typeStr, desc]);
}
