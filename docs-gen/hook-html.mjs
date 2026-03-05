import { Converter } from 'typedoc';

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

/** @param {import('typedoc').Application} app */
export const load = app => {
  app.converter.on(Converter.EVENT_RESOLVE, (context, reflection) => {
    normalizeReflectionContent(reflection);

    // Skip inherited Error constructor
    if (
      reflection.name === 'constructor' &&
      reflection.inheritedFrom &&
      reflection.inheritedFrom.name.includes('Error')
    ) {
      context.project.removeReflection(reflection);
    }
  });
};
