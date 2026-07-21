// Category "Types (Enums)": real TS enums and string-literal-union aliases.
//
//   real enum            -> `## Members` table
//   literal-union alias  -> `> Name = "a" | "b"` line + `## Type Declaration`
//                           bulleted list (value + per-member summary).

import { ReflectionKind } from 'typedoc';
import { table, escapeTableCell, heading, inlineCode, sectionsToMarkdown } from './markdown.mjs';
import { renderType } from './type.mjs';
import { renderDescription, renderSummary, partsToMarkdown } from './comment.mjs';

export function renderEnumBody(ref, ctx) {
  if (ref.kind === ReflectionKind.Enum) return renderRealEnum(ref, ctx);
  return sectionsToMarkdown([
    ref.type ? `> **${ref.name}** = ${renderType(ref.type, ctx)}` : '',
    renderDescription(ref.comment, ctx),
    renderLiteralUnionList(ref, ctx),
  ]);
}

function renderRealEnum(ref, ctx) {
  const members = (ref.children ?? []).filter(c => c.kind === ReflectionKind.EnumMember);
  const desc = renderDescription(ref.comment, ctx);
  if (members.length === 0) return desc;
  const rows = members.map(m => [
    inlineCode(m.name),
    renderType(m.type, ctx),
    escapeTableCell(renderSummary(m.comment, ctx)),
  ]);
  const tbl = `${heading(2, 'Members')}\n\n${table(['Member', 'Value', 'Description'], rows)}`;
  return sectionsToMarkdown([desc, tbl]);
}

function renderLiteralUnionList(ref, ctx) {
  const t = ref.type;
  if (t?.type !== 'union') return '';
  const summaries = t.elementSummaries ?? [];
  const lines = [];
  t.types.forEach((member, i) => {
    if (member.type !== 'literal') return;
    const value = member.value; // raw value, unquoted, in a code span
    const text = summaries[i]
      ? partsToMarkdown(summaries[i], ctx).replace(/\n\n/g, ' ').trim()
      : '';
    lines.push(text ? `- ${inlineCode(String(value))} - ${text}` : `- ${inlineCode(String(value))}`);
  });
  if (lines.length === 0) return '';
  return `${heading(2, 'Type Declaration')}\n\n${lines.join('\n')}`;
}
