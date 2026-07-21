// Render JSDoc comments to markdown.
//
// A TypeDoc Comment has `summary` (CommentDisplayPart[]) and `blockTags`
// ({ tag, content, name? }[]). We resolve inline `{@link}` tags to real Docs
// URLs (they show up as links in the current output) and group `@example`
// blocks under a single pluralised heading, matching the existing pipeline.

import { RENDER_OPTIONS } from '../manifest.mjs';
import { heading, link, inlineCode } from './markdown.mjs';

/** Render CommentDisplayPart[] to markdown, resolving inline links. */
export function partsToMarkdown(parts, ctx) {
  if (!parts) return '';
  return parts
    .map(p => {
      if (p.kind === 'inline-tag') return renderInlineTag(p, ctx);
      // text + code parts are emitted verbatim
      return p.text ?? '';
    })
    .join('');
}

function renderInlineTag(part, ctx) {
  const tag = part.tag;
  if (tag === '@link' || tag === '@linkcode' || tag === '@linkplain') {
    const target = part.target;
    // Inline links resolve to the EXACT target declaration (e.g. an error class
    // in auth-core), not a same-SDK copy.
    const resolveLink = ctx?.linkForExact ?? ctx?.linkFor;
    const url =
      target && typeof target === 'object' && resolveLink
        ? resolveLink(target)
        : typeof target === 'string'
          ? target
          : null;
    const text = (part.text ?? '').trim() || '';
    if (url) return link(text, url);
    return text;
  }
  // Other inline tags (e.g. {@inheritDoc}) collapse to their text.
  return part.text ?? '';
}

/** Summary (lead description) only. */
export function renderSummary(comment, ctx) {
  if (!comment) return '';
  return partsToMarkdown(comment.summary ?? [], ctx).trim();
}

/**
 * The lead description = the summary only. `@remarks`, `@example`, `@see` are
 * rendered as their own sections (see renderRemarks/renderExamples/renderSee).
 */
export function renderDescription(comment, ctx) {
  return renderSummary(comment, ctx);
}

/** `@remarks` rendered as a "Remarks" section. */
export function renderRemarks(comment, ctx, level) {
  if (!comment || !RENDER_OPTIONS.showRemarks) return '';
  const body = (comment.blockTags ?? [])
    .filter(t => t.tag === '@remarks')
    .map(t => partsToMarkdown(t.content ?? [], ctx).trim())
    .filter(Boolean)
    .join('\n\n');
  return body ? `${heading(level, 'Remarks')}\n\n${body}` : '';
}

/** `@see` rendered as a "See" section (one bullet per tag when multiple). */
export function renderSee(comment, ctx, level) {
  const tags = (comment?.blockTags ?? []).filter(t => t.tag === '@see');
  if (tags.length === 0) return '';
  const items = tags.map(t => partsToMarkdown(t.content ?? [], ctx).trim()).filter(Boolean);
  if (items.length === 0) return '';
  const body = items.length === 1 ? items[0] : items.map(i => `- ${i}`).join('\n');
  return `${heading(level, 'See')}\n\n${body}`;
}

/**
 * Render grouped @example blocks as a single section. Heading is "Example"
 * for one block, "Examples" for several.
 *
 * @param {number} level heading level (2 or 3)
 */
export function renderExamples(comment, ctx, level) {
  if (!comment || !RENDER_OPTIONS.showExamples) return '';
  const examples = (comment.blockTags ?? [])
    .filter(t => t.tag === '@example')
    .map(t => partsToMarkdown(t.content ?? [], ctx).trim())
    .filter(Boolean);
  if (examples.length === 0) return '';
  const title = examples.length > 1 ? 'Examples' : 'Example';
  return `${heading(level, title)}\n\n${examples.join('\n\n')}`;
}

/** @returns description text (the prose after `@returns`), if any. */
export function returnsDescription(comment, ctx) {
  const tag = (comment?.blockTags ?? []).find(t => t.tag === '@returns');
  return tag ? partsToMarkdown(tag.content ?? [], ctx).trim() : '';
}

/** Render `@throws` blocks — each gets its own "Throws" heading. */
export function renderThrows(comment, ctx, level) {
  const tags = (comment?.blockTags ?? []).filter(t => t.tag === '@throws');
  if (tags.length === 0) return '';
  return tags
    .map(t => {
      const body = partsToMarkdown(t.content ?? [], ctx).trim();
      return body ? `${heading(level, 'Throws')}\n\n${body}` : '';
    })
    .filter(Boolean)
    .join('\n\n');
}
