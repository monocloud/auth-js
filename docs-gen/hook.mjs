import { MarkdownPageEvent } from 'typedoc-plugin-markdown';
import { ReflectionKind } from 'typedoc';

const ROOT_SDK_NAME_REPLACEMENTS = [
  ['@monocloud/auth-nextjs', 'Next.js'],
  ['@monocloud/auth-node-core', 'Node.js Core'],
  ['@monocloud/auth-core', 'Node.js'],
  ['@monocloud/auth-js-core', 'js-core'],
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

/** @param {import('typedoc').Application} app */
export const load = app => {
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

    const h1Title = `# ${titleText}\n\n`;

    if (page.contents.startsWith('---')) {
      const endOfFrontmatter = page.contents.indexOf('\n---', 3);
      if (endOfFrontmatter !== -1) {
        const frontmatterContent = page.contents.slice(0, endOfFrontmatter);
        const restOfFile = page.contents.slice(endOfFrontmatter);

        page.contents = `${frontmatterContent}${rootSdk}\n${title}\n${category}\n---\n\n${h1Title}${restOfFile.trimStart()}`;
      }
    } else {
      page.contents = `---\n${rootSdk}\n${title}\n${category}\n---\n\n${h1Title}${page.contents}`;
    }

    if (type === Type.Types_Enums) {
      const typesLen = page.model.type.types.length;
      const items = [];

      for (let i = 0; i < typesLen; i++) {
        const summary = page.model.type.elementSummaries?.[i];

        if (summary) {
          const text = summary.map(x => x.text).join('');

          const item = {
            value: page.model.type.types[i].value,
            type: page.model.type.types[i].type,
            description: text.replace(/\n\n/g, ' '),
          };

          items.push(item);
        }
      }

      const str = items
        .map(item => `- \`${item.value}\` - ${item.description}`)
        .join('\n');

      page.contents += `\n\n## Type Declaration\n\n${str}`;
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
