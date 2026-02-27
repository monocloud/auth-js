import { Converter, PageEvent } from 'typedoc';

const CODE_FENCE_OPENING_LINE_REGEX = /(^|\n)(\s*`{3,}\s*)([^\s`\n]+)([^\n]*)/g;

const stripInfoTokenPathSuffix = token => {
  // Convert info strings like `tsx:src/app/page.tsx` to `tsx`.
  const colonIndex = token.indexOf(':');
  if (colonIndex <= 0) return token;
  return token.slice(0, colonIndex);
};

const normalizeCodeFenceInfo = text => {
  return text.replace(
    CODE_FENCE_OPENING_LINE_REGEX,
    (_full, lineStart, fencePrefix, infoToken, tail) =>
      `${lineStart}${fencePrefix}${stripInfoTokenPathSuffix(infoToken)}${tail}`
  );
};

const normalizeDisplayParts = parts => {
  if (!Array.isArray(parts)) return;

  for (const part of parts) {
    if (part.kind !== 'text' && part.kind !== 'code') continue;
    part.text = normalizeCodeFenceInfo(part.text);
  }
};

const normalizeReflectionContent = reflection => {
  if (!reflection) return;

  if (reflection.comment) {
    normalizeDisplayParts(reflection.comment.summary);
    for (const tag of reflection.comment.blockTags) {
      normalizeDisplayParts(tag.content);
    }
  }

  if (Array.isArray(reflection.readme)) {
    normalizeDisplayParts(reflection.readme);
  }

  if (Array.isArray(reflection.content)) {
    normalizeDisplayParts(reflection.content);
  }
};

const BASE_ERROR_HTML_PAGE_REGEX = /MonoCloudAuthBaseError\.html$/;

const stripMonoCloudAuthBaseErrorConstructorFromHtml = page => {
  if (!page?.url || !page?.contents || !BASE_ERROR_HTML_PAGE_REGEX.test(page.url))
    return;

  page.contents = page.contents
    .replace(
      /<section class="tsd-index-section"><h3 class="tsd-index-heading">Constructors<\/h3><div class="tsd-index-list">[\s\S]*?<\/div><\/section>/g,
      ''
    )
    .replace(
      /<details class="tsd-panel-group tsd-member-group tsd-accordion" open><summary class="tsd-accordion-summary" data-key="section-Constructors">[\s\S]*?<\/details>/g,
      ''
    )
    .replace(
      /<details open class="tsd-accordion tsd-page-navigation-section"><summary class="tsd-accordion-summary" data-key="section-Constructors">[\s\S]*?<\/details>/g,
      ''
    )
    .replace(
      /<section class="tsd-panel-group tsd-index-group">[\s\S]*?<div class="tsd-accordion-details"><\/div><\/details><\/section><\/section>/g,
      ''
    )
    .replace(
      /<details open class="tsd-accordion tsd-page-navigation">[\s\S]*?<div class="tsd-accordion-details"><\/div><\/details>/g,
      ''
    );
};

/** @param {import('typedoc').Application} app */
export const load = app => {
  app.converter.on(Converter.EVENT_RESOLVE, (_context, reflection) => {
    normalizeReflectionContent(reflection);
  });

  app.renderer.on(PageEvent.END, page => {
    stripMonoCloudAuthBaseErrorConstructorFromHtml(page);
  });
};
