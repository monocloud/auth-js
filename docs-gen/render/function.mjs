// Standalone functions (and "Other" utility functions). A single signature
// renders inline under the H1 with level-2 sub-sections; multiple overloads
// each get a "## Call Signature" heading with level-3 sub-sections.

import { heading } from './markdown.mjs';
import { renderSignature } from './signature.mjs';

export function renderFunctionBody(ref, ctx) {
  const sigs = ref.signatures ?? [];
  if (sigs.length === 0) return '';

  if (sigs.length === 1) {
    return renderSignature(sigs[0], { displayName: ref.name, headingLevel: 2, ctx });
  }

  return sigs
    .map(
      sig =>
        `${heading(2, 'Call Signature')}\n\n${renderSignature(sig, {
          displayName: ref.name,
          headingLevel: 3,
          ctx,
        })}`
    )
    .join('\n\n');
}
