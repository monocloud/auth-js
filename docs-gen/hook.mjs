import { MarkdownPageEvent } from 'typedoc-plugin-markdown';
import { ReflectionKind } from 'typedoc';
import { registerInlineReferences } from './inline-references.mjs';

// Target length for meta descriptions — Google's desktop snippet display tops
// out around 160 chars. Above this we try to truncate at a sentence boundary.
const DESCRIPTION_MAX_LENGTH = 160;

// Hard ceiling. When a description has no sentence boundary within the target
// (typically a single long sentence in the source JSDoc), we let it run up to
// here rather than cut it mid-clause. Google still indexes the full text; only
// the visible snippet gets ellipsised. Anything beyond this is truncated to
// the last word boundary within the target.
const DESCRIPTION_HARD_MAX_LENGTH = 200;

const ROOT_SDK_NAME_REPLACEMENTS = [
  ['@monocloud/auth-nextjs', 'Next.js'],
  ['@monocloud/auth-node-core', 'Node.js Core'],
  ['@monocloud/auth-core', 'Node.js'],
  ['@monocloud/backend-node', 'Node.js Backend'],
];

const Type = {
  Class: 'Classes',
  Components: 'Components',
  Error_Classes: 'Error_Classes',
  Functions: 'Functions',
  Hooks: 'Hooks',
  Other: 'Other',
  Types: 'Types',
  Types_Enums: 'Types_(Enums)',
  Types_Handler: 'Types_(Handler)',
};

const getType = url => {
  if (url.includes(Type.Components)) return Type.Components;
  if (url.includes(Type.Error_Classes)) return Type.Error_Classes;
  if (url.includes(Type.Class)) return Type.Class;
  if (url.includes(Type.Functions)) return Type.Functions;
  if (url.includes(Type.Hooks)) return Type.Hooks;
  if (url.includes(Type.Types_Enums)) return Type.Types_Enums;
  if (url.includes(Type.Types_Handler)) return Type.Types_Handler;
  if (url.includes(Type.Types)) return Type.Types;
  return Type.Other;
};

const getFramework = url => {
  if (url.includes("frameworks_express")) return "Express";
  if (url.includes("frameworks_fastify")) return "Fastify";
  return undefined;
}

function getRootPackageName(reflection) {
  if (!reflection) return 'Docs';
  let current = reflection;
  let rootName = 'Docs';

  while (current) {
    if (current.kind === ReflectionKind.Module) {
      rootName = current.name;
    }
    if (current.kind === ReflectionKind.Project) {
      break;
    }
    current = current.parent;
  }

  if (ROOT_SDK_NAME_REPLACEMENTS) {
    for (const [original, replacement] of ROOT_SDK_NAME_REPLACEMENTS) {
      if (rootName === original) {
        rootName = replacement;
        break;
      }
    }
  }

  return rootName;
}

const EXCLUDED_LINE_RE = /^(\s*(\*|-|\d+\.)|>|#+|\||Default Value|Inherited from|Overrides|protected|private|public|@param|@returns)/;

const isExcludedLine = (text) => EXCLUDED_LINE_RE.test(text.trim());

// Whole-summary gate: only checks the first non-empty line so that a callout,
// heading, or list later in the summary doesn't disqualify a perfectly good
// lead sentence. The per-line filter below still drops those non-prose lines.
const startsWithExcludedBlock = (text) => {
  const firstLine = text.split('\n').find(line => line.trim().length > 0);
  return firstLine ? EXCLUDED_LINE_RE.test(firstLine.trim()) : true;
};

const getCategoryFallback = (model, type, rootPackage) => {
  const kindLabel = {
    [Type.Class]: 'class',
    [Type.Components]: 'component',
    [Type.Error_Classes]: 'error class',
    [Type.Functions]: 'function',
    [Type.Hooks]: 'hook',
    [Type.Types]: 'type',
    [Type.Types_Enums]: 'enum',
    [Type.Types_Handler]: 'handler type',
  }[type];
  // Module-level aggregate pages have no meaningful per-page summary;
  // omit the description rather than emit a fake one.
  if (!kindLabel) return '';
  return `${model.name} is a ${kindLabel} in the MonoCloud ${rootPackage} SDK.`;
};

const processDescription = (model, type, rootPackage) => {
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

  // Strip fenced code blocks (and their contents) before per-line processing
  // so configuration samples don't leak fragments like ":.env.local" into the
  // description.
  rawText = rawText.replace(/```[\s\S]*?```/g, '');

  // The two regexes below strip Next.js-style middleware matcher regexes
  // (e.g. ['/((?!_next/static|...).*)/']) that appear in JSDoc and would
  // otherwise survive markdown stripping as unreadable fragments.
  let cleaned = rawText
    .replace(/\[\s*['"`]\/?\(\(\?![\s\S]*?\]/g, '')
    .replace(/['"`]\/?\(\(\?![\s\S]*?['"`]/g, '')
    .split(/\n/)
    .filter(line => !isExcludedLine(line))
    .join(' ')
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
    .replace(/([\*_]{1,3})(\S.*?\S{0,1})\1/g, '$2')
    .replace(/`([^`]+)`/g, '$1')
    .replace(/\s+/g, ' ')
    .replace(/\s+([.!?,'":;]+)(?=\s|$)/g, '$1')
    .trim();

  if (cleaned.length < 20) {
    return getCategoryFallback(model, type, rootPackage);
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

  if (d.length > DESCRIPTION_MAX_LENGTH) {
    // Find the last real sentence boundary within the target: a `.!?` followed
    // by whitespace + an uppercase letter. This avoids splitting abbreviations
    // like "Next.js", "e.g.", or "i.e." mid-token.
    const sentenceEndRe = /[.!?](?=\s+[A-Z])/g;
    let lastSentenceEnd = -1;
    let match;
    while ((match = sentenceEndRe.exec(d)) !== null) {
      if (match.index >= DESCRIPTION_MAX_LENGTH) break;
      lastSentenceEnd = match.index;
    }

    if (lastSentenceEnd !== -1) {
      d = d.substring(0, lastSentenceEnd + 1);
    } else if (d.length <= DESCRIPTION_HARD_MAX_LENGTH) {
      // Single long sentence within the hard ceiling — keep it whole rather
      // than end mid-clause. Google will ellipsise the snippet but still
      // indexes the full text.
    } else {
      // Beyond the hard ceiling — back off to the last word boundary within
      // the target so we never end mid-word.
      const clipped = d.substring(0, DESCRIPTION_MAX_LENGTH);
      const lastSpace = clipped.lastIndexOf(' ');
      d = lastSpace > 0 ? clipped.substring(0, lastSpace) : clipped;
    }
  }

  // Defensive: drop a trailing unclosed parenthetical that survived truncation.
  d = d.replace(/\s*\([^)]*$/, '');

  return d.replace(/"/g, "'").trim();
};

/** @param {import('typedoc').Application} app */
export const load = app => {
  registerInlineReferences(app);

  app.renderer.on(MarkdownPageEvent.END, page => {
    if (!page.contents) return;

    let titleText = page.model.name;

    const type = getType(page.url);

    if (type === Type.Components) {
      titleText = `Component: &lt;${page.model.name}&gt;`;
    } else if (type === Type.Functions) {
      titleText = `Function: ${page.model.name}`;
    } else if (type === Type.Hooks) {
      titleText = `Hook: ${page.model.name}`;
    } else if (type === Type.Error_Classes) {
      titleText = `Error Class: ${page.model.name}`;
    } else if (type === Type.Types) {
      titleText = `Type: ${page.model.name}`;
    } else if (type === Type.Types_Enums) {
      titleText = `Enum: ${page.model.name}`;
    } else if (type === Type.Types_Handler) {
      titleText = `Handler Type: ${page.model.name}`;
    } else if (type === Type.Class) {
      titleText = `Class: ${page.model.name}`;
    } else {
      if (page.model.name.includes('/')) {
        titleText = page.model.name.split('/').pop();
      } else {
        titleText = page.model.name;
      }
    }

    const rootPackage = getRootPackageName(page.model).replace(/"/g, '');
    const rootSdk = `rootSdk: ${rootPackage}`;
    const title = `title: "${page.model.name}"`;
    const category = `category: ${type === Type.Types_Enums ? 'Enums' : type === Type.Types_Handler ? 'Handler Types' : type === Type.Error_Classes ? 'Error Classes' : type}`;
    const framework = getFramework(page.url);
    const frameWorkName = framework ? `framework: ${framework}` : undefined;
    const description = processDescription(page.model, type, rootPackage);
    const descMeta = description ? `description: "${description}"` : undefined;

    const h1Title = `# ${titleText}\n\n`;

    if (page.contents.startsWith('---')) {
      const endOfFrontmatter = page.contents.indexOf('\n---', 3);
      if (endOfFrontmatter !== -1) {
        const frontmatterContent = page.contents.slice(0, endOfFrontmatter);
        const restOfFile = page.contents.slice(endOfFrontmatter);

        page.contents = `${frontmatterContent}${rootSdk}\n${title}\n${category}${frameWorkName ? `\n${frameWorkName}` : ''}${descMeta ? `\n${descMeta}` : ''}\n---\n\n${h1Title}${restOfFile.trimStart()}`;
      }
    } else {
      page.contents = `---\n${rootSdk}\n${title}\n${category}${frameWorkName ? `\n${frameWorkName}` : ''}${descMeta ? `\n${descMeta}` : ''}\n---\n\n${h1Title}${page.contents}`;
    }

    if (type === Type.Types_Enums) {
      const typesLen = page.model.type.types.length;
      const items = [];
      for (let i = 0; i < typesLen; i++) {
        const text = page.model.type.elementSummaries[i]
          .map(x => x.text)
          .join('');

        const item = {
          value: page.model.type.types[i].value,
          type: page.model.type.types[i].type,
          description: text.replace(/\n\n/g, ' '),
        };

        items.push(item);
      }

      const str = items
        .map(item => `- \`${item.value}\` - ${item.description}`)
        .join('\n');

      page.contents += `\n\n## Type Declaration\n\n${str}`;
    }

    if (type === Type.Class || type === Type.Types) {
      // Remove Extended By
      page.contents = page.contents.replace(
        /(?:^|\n)## Extended by[\s\S]*?(?=\n## |$)/g,
        ''
      );
    }

    if (type === Type.Components) {
      const signatureRegex = /> \*\*.*?\*\*[\s\S]*?(\n\n|$)/;
      page.contents = page.contents.replace(signatureRegex, '');

      // Remove Returns
      page.contents = page.contents.replace(
        /##\s+Returns[\s\S]*?(?=\n##\s|$)/g,
        ''
      );
    }
  });
};
