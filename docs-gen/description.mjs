// SEO `description:` frontmatter. Ported verbatim from the previous
// hook.mjs::processDescription so the generated meta descriptions are
// byte-for-byte identical. Parameterised by the frontmatter category label
// (drives the fallback sentence) and the root SDK label.

import { RENDER_OPTIONS } from './manifest.mjs';

const KIND_LABEL_BY_CATEGORY = {
  Classes: 'class',
  Components: 'component',
  'Error Classes': 'error class',
  Functions: 'function',
  Hooks: 'hook',
  Types: 'type',
  Enums: 'enum',
  'Handler Types': 'handler type',
};

const EXCLUDED_LINE_RE =
  /^(\s*(\*|-|\d+\.)|>|#+|\||Default Value|Inherited from|Overrides|protected|private|public|@param|@returns)/;

const isExcludedLine = text => EXCLUDED_LINE_RE.test(text.trim());

const startsWithExcludedBlock = text => {
  const firstLine = text.split('\n').find(line => line.trim().length > 0);
  return firstLine ? EXCLUDED_LINE_RE.test(firstLine.trim()) : true;
};

function categoryFallback(model, categoryLabel, rootPackage) {
  const kindLabel = KIND_LABEL_BY_CATEGORY[categoryLabel];
  if (!kindLabel) return '';
  return `${model.name} is a ${kindLabel} in the MonoCloud ${rootPackage} SDK.`;
}

/**
 * @param {import('typedoc').DeclarationReflection} model
 * @param {string} categoryLabel frontmatter category label (e.g. "Functions")
 * @param {string} rootPackage root SDK label (e.g. "Next.js")
 */
export function computeDescription(model, categoryLabel, rootPackage) {
  const MAX = RENDER_OPTIONS.descriptionMaxLength;
  const HARD_MAX = RENDER_OPTIONS.descriptionHardMaxLength;

  let rawText = model.comment?.summary?.map(x => x.text).join('') || '';

  if (!rawText.trim() && model.signatures && model.signatures.length > 0) {
    for (const sig of model.signatures) {
      const sigText = sig.comment?.summary?.map(x => x.text).join('') || '';
      if (sigText.trim().length > 20 && !startsWithExcludedBlock(sigText)) {
        rawText = sigText;
        break;
      }
    }
  }

  rawText = rawText.replace(/```[\s\S]*?```/g, '');

  let cleaned = rawText
    .replace(/\[\s*['"`]\/?\(\(\?![\s\S]*?\]/g, '')
    .replace(/['"`]\/?\(\(\?![\s\S]*?['"`]/g, '')
    .split(/\n/)
    .filter(line => !isExcludedLine(line))
    .join(' ')
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
    .replace(/([*_]{1,3})(\S.*?\S{0,1})\1/g, '$2')
    .replace(/`([^`]+)`/g, '$1')
    .replace(/\s+/g, ' ')
    .replace(/\s+([.!?,'":;]+)(?=\s|$)/g, '$1')
    .trim();

  if (cleaned.length < 20) {
    return categoryFallback(model, categoryLabel, rootPackage);
  }

  const sentences = cleaned.split(/(?<=[.!?(:)])\s+/);
  const filteredSentences = sentences.filter(s => {
    const trimmed = s.trim();
    if (trimmed.length === 0) return false;
    if (trimmed.endsWith(':')) return false;
    if (trimmed.includes('((?!') || trimmed.startsWith("['/")) return false;
    const words = trimmed.split(/\s+/);
    if (words.length === 1 && trimmed.match(/^[.!?,'":;\-]/)) return false;
    return true;
  });

  let d = filteredSentences.join(' ');

  if (d.length > MAX) {
    const sentenceEndRe = /[.!?](?=\s+[A-Z])/g;
    let lastSentenceEnd = -1;
    let match;
    while ((match = sentenceEndRe.exec(d)) !== null) {
      if (match.index >= MAX) break;
      lastSentenceEnd = match.index;
    }
    if (lastSentenceEnd !== -1) {
      d = d.substring(0, lastSentenceEnd + 1);
    } else if (d.length <= HARD_MAX) {
      // keep the single long sentence whole
    } else {
      const clipped = d.substring(0, MAX);
      const lastSpace = clipped.lastIndexOf(' ');
      d = lastSpace > 0 ? clipped.substring(0, lastSpace) : clipped;
    }
  }

  d = d.replace(/\s*\([^)]*$/, '');
  return d.replace(/"/g, "'").trim();
}
