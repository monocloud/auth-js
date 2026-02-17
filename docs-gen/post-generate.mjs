import fs from 'node:fs';
import path from 'node:path';
import { glob } from 'glob';

const SDK_SLUGS = {
  default: 'docs',
  '_monocloud_auth-nextjs': 'nextjs',
  '_monocloud_auth-node-core': 'nodejs-core',
  '_monocloud_auth-core': 'nodejs',
};

const CATEGORY_MAP = {
  Classes: 'classes',
  Functions: 'functions',
  Types: 'types',
  Enums: 'enums',
  'Handler Types': 'handler-types',
  Components: 'components',
  Hooks: 'hooks',
  'Error Classes': 'error-classes',
};

const DOCS_DIR = './docs/markdown';

async function main() {
  console.log('🔍 Starting post-processing...');
  const files = await glob(`${DOCS_DIR}/**/*.md{,x}`);

  const fileIndex = new Map();
  console.log('   Index building...');

  for (const filePath of files) {
    const content = fs.readFileSync(filePath, 'utf-8');

    const sdkMatch = content.match(/^rootSdk:\s*(.*)/m);
    const catMatch = content.match(/^category:\s*(.*)/m);

    const rootSdk = sdkMatch ? sdkMatch[1].trim() : 'default';
    const category = catMatch ? catMatch[1].trim() : 'other';

    fileIndex.set(path.resolve(filePath), { rootSdk, category });
  }

  console.log('   Processing links and tables...');
  for (const filePath of files) {
    await processFile(filePath, fileIndex);
  }

  console.log('✅ Post-processing complete.');
}

function rewriteLinks(content, sourceFileDir, fileIndex) {
  const linkRegex = /\[([^\]]+)\]\((?:<([^>]+)>|([^)]+))\)/g;

  return content.replace(
    linkRegex,
    (fullLink, linkText, urlWithBrackets, urlStandard) => {
      const rawLinkUrl = urlWithBrackets || urlStandard;

      if (!rawLinkUrl) return fullLink;
      let linkUrl = rawLinkUrl.trim();

      if (
        linkUrl.startsWith('http') ||
        linkUrl.startsWith('#') ||
        linkUrl.startsWith('/')
      ) {
        return fullLink;
      }

      const hashIndex = linkUrl.indexOf('#');
      let cleanPath = linkUrl;
      let urlHash = '';

      if (hashIndex !== -1) {
        cleanPath = linkUrl.substring(0, hashIndex);
        urlHash = linkUrl.substring(hashIndex);
      }

      const targetAbsPath = path.resolve(sourceFileDir, cleanPath);
      const targetMeta = fileIndex.get(targetAbsPath);

      if (!targetMeta) {
        return fullLink;
      }

      const { category } = targetMeta;

      const typeName = path
        .basename(cleanPath, path.extname(cleanPath))
        .toLowerCase()
        .split('.');

      const finalSdkSlug = SDK_SLUGS[typeName[0]] || SDK_SLUGS['default'];

      const newUrl = `/sdks/${finalSdkSlug}/api-reference/${CATEGORY_MAP[category]}/${typeName.at(-1)}`;

      return `[${linkText}](${newUrl}${urlHash})`;
    }
  );
}

async function processFile(filePath, fileIndex) {
  let content = fs.readFileSync(filePath, 'utf-8');
  let hasChanges = false;
  const fileDir = path.dirname(filePath);

  if (content.includes('<a id=')) {
    content = content.replace(/<a id="[^"]*"><\/a>\s*/g, '');
    hasChanges = true;
  }

  const propsLinkRegex =
    /(#{2,})\s+Parameters[\s\S]*?\|\s*`props`\s*\|\s*\[.*?\]\((.*?)\)/;
  const match = content.match(propsLinkRegex);

  if (match) {
    const [fullMatch, headingLevel, relativeLinkPath] = match;
    const cleanLinkPath = relativeLinkPath.replace(/^<|>$/g, '');
    const typeFilePath = path.resolve(fileDir, cleanLinkPath);

    if (fs.existsSync(typeFilePath)) {
      let typeFileContent = fs.readFileSync(typeFilePath, 'utf-8');

      const typeFileDir = path.dirname(typeFilePath);
      typeFileContent = rewriteLinks(typeFileContent, typeFileDir, fileIndex);

      typeFileContent = typeFileContent.replace(/<a id="[^"]*"><\/a>\s*/g, '');

      const tableRegex =
        /(#{2,})\s+(Properties|Type declaration)[\s\S]*?(\|[\s\S]*?)(?=\n#{2,} |$)/;
      const tableMatch = typeFileContent.match(tableRegex);

      if (tableMatch) {
        const [, , , tableData] = tableMatch;
        const newSection = `${headingLevel} Props\n\n${tableData}\n`;
        const entireParamsBlockRegex =
          /(#{2,})\s+Parameters[\s\S]*?(?=\n#{2,} |$)/;
        content = content.replace(entireParamsBlockRegex, newSection);
        hasChanges = true;
      }
    }
  }

  const newContent = rewriteLinks(content, fileDir, fileIndex);

  if (newContent !== content) {
    content = newContent;
    hasChanges = true;
  }

  if (hasChanges) {
    fs.writeFileSync(filePath, content, 'utf-8');
  }
}

main().catch(console.error);
