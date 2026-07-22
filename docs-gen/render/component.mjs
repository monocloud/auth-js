// React components. No signature line, no Returns. Layout:
//   <description>  ## Props (from the single `props` parameter)  ## Examples

import { sectionsToMarkdown } from './markdown.mjs';
import { renderDescription, renderExamples } from './comment.mjs';
import { renderPropertiesTable, collectProps } from './members.mjs';

export function renderComponentBody(ref, ctx) {
  const sig = ref.signatures?.[0];
  const comment = sig?.comment ?? ref.comment;
  // The props are the component's first (and only) parameter — it may be named
  // `props` or destructured, and typed as a reference or an intersection.
  const props = collectProps(sig?.parameters?.[0]?.type);
  return sectionsToMarkdown([
    renderDescription(comment, ctx),
    renderPropertiesTable(props, ctx, { title: 'Props', level: 2 }),
    renderExamples(comment, ctx, 2),
  ]);
}
