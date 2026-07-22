// Interface and type-alias bodies (categories: Types, Handler Types).
//
// Dispatch is by reflection kind, not category:
//   Interface  -> Extends / Properties / Methods / Indexable
//   TypeAlias  -> `> Name = <type>` line, then type-dependent sections:
//                   function type  -> Parameters + Returns (handler types)
//                   object literal -> Type Declaration table
//                 plus trailing Examples.

import { ReflectionKind } from 'typedoc';
import { heading, sectionsToMarkdown, bulletList, inlineCode } from './markdown.mjs';
import { renderType } from './type.mjs';
import { renderDescription, renderExamples, partsToMarkdown } from './comment.mjs';
import { renderPropertiesTable, propsTable, partitionMembers, collectProps } from './members.mjs';
import { hasGroups, renderFlatMembers } from './flat-members.mjs';
import {
  renderMemberSignatures,
  renderParamsOrProps,
  renderReturns,
  renderTypeParametersSection,
  renderTypeParametersInline,
} from './signature.mjs';

export function renderTypeBody(ref, ctx) {
  if (ref.kind === ReflectionKind.Interface) return renderInterfaceBody(ref, ctx);
  return renderAliasBody(ref, ctx);
}

// Interfaces ----------------------------------------------------------------

function renderInterfaceBody(ref, ctx) {
  const top = [
    renderDescription(ref.comment, ctx),
    renderHeritage('Extends', ref.extendedTypes, ctx),
    renderTypeParametersSection(ref.typeParameters, ctx, 2),
    renderIndexable(ref, ctx),
  ];

  // No groups -> flat `## member` sections (typically `export type` re-exports).
  if (!hasGroups(ref)) {
    return sectionsToMarkdown([...top, renderFlatMembers(ref, ctx)]);
  }

  const { props, methods } = partitionMembers(ref);
  return sectionsToMarkdown([
    ...top,
    renderPropertiesTable(props, ctx),
    renderInterfaceMethods(methods, ctx),
  ]);
}

// Multiple heritage types -> single bullet joined by `.` (see class.mjs).
function renderHeritage(label, types, ctx) {
  if (!types || types.length === 0) return '';
  return `${heading(2, label)}\n\n- ${types.map(t => renderType(t, ctx)).join('.')}`;
}

function renderInterfaceMethods(methods, ctx) {
  if (!methods || methods.length === 0) return '';
  const blocks = methods.map(
    m => `${heading(3, `${m.name}()`)}\n\n${renderMemberSignatures(m, m.name, 4, ctx)}`
  );
  return `${heading(2, 'Methods')}\n\n${blocks.join('\n\n---\n\n')}`;
}

function renderIndexable(ref, ctx) {
  const idx = ref.indexSignatures?.[0];
  if (!idx) return '';
  const key = idx.parameters?.[0];
  const line = `> \\[${inlineCode(key?.name ?? 'key')}: ${renderType(key?.type, ctx)}\\]: ${renderType(idx.type, ctx)}`;
  const summary = renderDescription(idx.comment, ctx);
  return sectionsToMarkdown([heading(2, 'Indexable'), line, summary]);
}

// Type aliases --------------------------------------------------------------

function renderAliasBody(ref, ctx) {
  const t = ref.type;
  const aliasLine = t
    ? `> **${ref.name}**${renderTypeParametersInline(ref.typeParameters)} = ${renderType(t, ctx)}`
    : '';
  const desc = renderDescription(ref.comment, ctx);

  const sections = [aliasLine, desc, renderTypeParametersSection(ref.typeParameters, ctx, 2)];

  if (t?.type === 'reflection' && t.declaration?.signatures?.length) {
    // Function-typed alias (handler types): expand the signature.
    const sig = t.declaration.signatures[0];
    sections.push(renderParamsOrProps(sig.parameters ?? [], ctx, 2));
    sections.push(renderReturns(sig, ctx, 2));
  } else if (t?.type === 'union') {
    sections.push(renderUnionDeclaration(t, ctx));
  } else {
    // Object-literal or intersection alias -> a "Type Declaration" table of
    // the resolved properties (header "Name").
    const props = collectProps(t);
    if (props.length) {
      sections.push(`${heading(2, 'Type Declaration')}\n\n${propsTable(props, ctx, 'Name')}`);
    }
  }

  sections.push(renderExamples(ref.comment, ctx, 2));
  return sectionsToMarkdown(sections);
}

// Union type alias -> "## Type Declaration" with one `> member` block per
// union member, its per-member summary, and (for object-literal members) a
// properties table headed "Name".
function renderUnionDeclaration(union, ctx) {
  const summaries = union.elementSummaries ?? [];
  // The union-members section only appears when members are individually
  // documented (per-member summaries). A plain `A | B` union shows just the
  // alias line.
  if (!summaries.some(s => s && s.length > 0)) return '';
  const blocks = union.types.map((member, i) => {
    const parts = [`> ${renderType(member, ctx)}`];
    const summary = summaries[i] ? partsToMarkdown(summaries[i], ctx).replace(/\n\n/g, ' ').trim() : '';
    if (summary) parts.push(summary);
    if (member.type === 'reflection') {
      const props = (member.declaration?.children ?? []).filter(c => c.kind === ReflectionKind.Property);
      const tbl = propsTable(props, ctx, 'Name');
      if (tbl) parts.push(tbl);
    }
    return parts.join('\n\n');
  });
  return `${heading(2, 'Type Declaration')}\n\n${blocks.join('\n\n')}`;
}
