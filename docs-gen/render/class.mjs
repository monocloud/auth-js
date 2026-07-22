// Class / error-class body. Section order matches the existing output:
//   <description> ## Extends ## Implements ## Constructors ## Properties ## Methods
// "Extended by" and "Implementation of" are intentionally omitted.

import { heading, sectionsToMarkdown, bulletList, inlineCode } from './markdown.mjs';
import { renderType } from './type.mjs';
import {
  renderSignature,
  renderMemberSignatures,
  renderTypeParametersSection,
  renderParametersTable,
  renderReturns,
} from './signature.mjs';
import { renderDescription } from './comment.mjs';
import { renderPropertiesTable, partitionMembers } from './members.mjs';
import { hasGroups, renderFlatMembers } from './flat-members.mjs';

/**
 * @param {object} [opts]
 * @param {boolean} [opts.extendedBy] render the reverse "Extended by" list
 *        (kept only for Error Classes; Classes/Types strip it).
 */
export function renderClassBody(ref, ctx, opts = {}) {
  const heritage = [
    renderDescription(ref.comment, ctx),
    renderHeritage('Extends', ref.extendedTypes, ctx),
    opts.extendedBy ? renderExtendedBy(ref, ctx) : '',
    renderHeritage('Implements', ref.implementedTypes, ctx),
    renderTypeParametersSection(ref.typeParameters, ctx, 2),
  ];

  // No groups -> flat `## member` sections (typically `export type` re-exports).
  if (!hasGroups(ref)) {
    return sectionsToMarkdown([...heritage, renderFlatMembers(ref, ctx)]);
  }

  const { props, methods, ctors, accessors } = partitionMembers(ref);
  return sectionsToMarkdown([
    ...heritage,
    renderConstructors(ctors, ref, ctx),
    renderPropertiesTable(props, ctx),
    renderAccessors(accessors, ctx),
    renderMethods(methods, ctx),
  ]);
}

function renderAccessors(accessors, ctx) {
  if (!accessors || accessors.length === 0) return '';
  const blocks = accessors.map(a => {
    const parts = [heading(3, a.name)];
    if (a.getSignature) {
      parts.push(heading(4, 'Get Signature'));
      parts.push(`> **get** **${a.name}**(): ${renderType(a.getSignature.type, ctx)}`);
      const d = renderDescription(a.getSignature.comment, ctx);
      if (d) parts.push(d);
      parts.push(renderReturns(a.getSignature, ctx, 5));
    }
    if (a.setSignature) {
      const param = a.setSignature.parameters?.[0];
      parts.push(heading(4, 'Set Signature'));
      const paramStr = param ? `${inlineCode(param.name)}: ${renderType(param.type, ctx)}` : '';
      parts.push(`> **set** **${a.name}**(${paramStr}): ${renderType(a.setSignature.type, ctx)}`);
      const d = renderDescription(a.setSignature.comment, ctx);
      if (d) parts.push(d);
      parts.push(renderParametersTable(a.setSignature.parameters ?? [], ctx, 5));
      parts.push(renderReturns(a.setSignature, ctx, 5));
    }
    return parts.filter(Boolean).join('\n\n');
  });
  return `${heading(2, 'Accessors')}\n\n${blocks.join('\n\n---\n\n')}`;
}

// Multiple heritage types render as a SINGLE bullet joined by `.`
// (typedoc-plugin-markdown's quirk for the Extends/Implements lists).
function renderHeritage(label, types, ctx) {
  if (!types || types.length === 0) return '';
  return `${heading(2, label)}\n\n- ${types.map(t => renderType(t, ctx)).join('.')}`;
}

function renderExtendedBy(ref, ctx) {
  const subs = ref.extendedBy ?? [];
  if (subs.length === 0) return '';
  return `${heading(2, 'Extended by')}\n\n${bulletList(subs.map(t => renderType(t, ctx)))}`;
}

function renderConstructors(ctors, classRef, ctx) {
  if (ctors.length === 0) return '';
  const blocks = [];
  for (const ctor of ctors) {
    for (const sig of ctor.signatures ?? []) {
      blocks.push(
        renderSignature(sig, {
          displayName: classRef.name,
          asNew: true,
          headingLevel: 4,
          owner: ctor,
          ctx,
        })
      );
    }
  }
  if (blocks.length === 0) return '';
  return `${heading(2, 'Constructors')}\n\n${heading(3, 'Constructor')}\n\n${blocks.join('\n\n---\n\n')}`;
}

function renderMethods(methods, ctx) {
  if (methods.length === 0) return '';
  const blocks = methods.map(
    m => `${heading(3, `${m.name}()`)}\n\n${renderMemberSignatures(m, m.name, 4, ctx)}`
  );
  return `${heading(2, 'Methods')}\n\n${blocks.join('\n\n---\n\n')}`;
}
