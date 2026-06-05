import fs from 'node:fs';
import path from 'node:path';
import { glob } from 'glob';

const SDK_SLUGS = {
  default: 'docs',
  '_monocloud_auth-nextjs': 'nextjs',
  '_monocloud_auth-react': 'react',
  '_monocloud_auth-node-core': 'nodejs-core',
  '_monocloud_auth-core': 'nodejs',
  '_monocloud_backend-node': 'nodejs-backend',
  '_monocloud_auth-web-js': 'web-js',
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

const FRAMEWORK_SLUGS = {
  express: 'express-backend',
  fastify: 'fastify-backend',
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
    const fwMatch = content.match(/^framework:\s*(.*)/m);

    const rootSdk = sdkMatch ? sdkMatch[1].trim() : 'default';
    const category = catMatch ? catMatch[1].trim() : 'other';
    const framework = fwMatch ? fwMatch[1].trim() : null;

    fileIndex.set(path.resolve(filePath), { rootSdk, category, framework });
  }

  // Build framework lookup: (category, className, framework) → filePath
  const frameworkIndex = new Map();
  for (const [absPath, meta] of fileIndex.entries()) {
    if (!meta.framework) continue;
    const className = path
      .basename(absPath, path.extname(absPath))
      .toLowerCase()
      .split('.')
      .at(-1);
    frameworkIndex.set(
      `${meta.category}|${className}|${meta.framework}`,
      absPath
    );
  }

  console.log('   Processing links and tables...');
  for (const filePath of files) {
    await processFile(filePath, fileIndex, frameworkIndex);
  }

  console.log('✅ Post-processing complete.');
}

function rewriteLinks(
  content,
  sourceFileDir,
  fileIndex,
  sourceFramework,
  frameworkIndex
) {
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

      const targetClassName = typeName.at(-1);

      // Determine effective framework for URL construction
      let effectiveFramework = targetMeta.framework;

      // If source is framework-specific and target is NOT, check for sibling
      if (sourceFramework && !effectiveFramework) {
        const key = `${category}|${targetClassName}|${sourceFramework}`;
        if (frameworkIndex.has(key)) {
          effectiveFramework = sourceFramework;
        }
      }

      // Use framework slug if applicable, otherwise standard SDK slug
      const finalSdkSlug = effectiveFramework
        ? FRAMEWORK_SLUGS[effectiveFramework.toLowerCase()] ||
          SDK_SLUGS[typeName[0]] ||
          SDK_SLUGS['default']
        : SDK_SLUGS[typeName[0]] || SDK_SLUGS['default'];

      const newUrl = `/sdks/${finalSdkSlug}/api-reference/${CATEGORY_MAP[category]}/${targetClassName}`;

      return `[${linkText}](${newUrl}${urlHash})`;
    }
  );
}

async function processFile(filePath, fileIndex, frameworkIndex) {
  let content = fs.readFileSync(filePath, 'utf-8');
  let hasChanges = false;
  const fileDir = path.dirname(filePath);
  const sourceMeta = fileIndex.get(path.resolve(filePath));
  const sourceFramework = sourceMeta?.framework || null;

  if (content.includes('<a id=')) {
    content = content.replace(/<a id="[^"]*"><\/a>\s*/g, '');
    hasChanges = true;
  }

  const stripped = content
    .replace(/^(#{1,6}\s+\S+)\?\s*$/gm, '$1')
    .replace(/\*\*([^*\s]+)\?\*\*(?=:)/g, '**$1**');
  if (stripped !== content) {
    content = stripped;
    hasChanges = true;
  }

  const unionTransformed = content.replace(
    /\n(#{2,6})\s+Union Members\b([\s\S]*?)(?=\n##\s|$)/g,
    (_, hashes, body) => {
      const transformed = body
        .replace(/\n#{3,6}\s+Type Literal\s*\n/g, '\n')
        .replace(/\n---\n/g, '\n')
        .replace(/^(\\\{[^\n]*\\\})\s*$/gm, '> $1\n')
        .replace(/^(`[^`\n]+`)\s*$/gm, '> $1\n');
      return `\n${hashes} Type Declaration${transformed}`;
    }
  );
  if (unionTransformed !== content) {
    content = unionTransformed;
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
      typeFileContent = rewriteLinks(
        typeFileContent,
        typeFileDir,
        fileIndex,
        sourceFramework,
        frameworkIndex
      );

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

  const newContent = rewriteLinks(
    content,
    fileDir,
    fileIndex,
    sourceFramework,
    frameworkIndex
  );

  if (newContent !== content) {
    content = newContent;
    hasChanges = true;
  }

  if (hasChanges) {
    fs.writeFileSync(filePath, content, 'utf-8');
  }
}

main().catch(console.error);
