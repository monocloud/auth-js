// Markdown primitives. Pure string helpers shared by every renderer.
//
// These intentionally mirror the shapes typedoc-plugin-markdown produced so
// the generated pages render identically on the Docs site (same headings,
// tables, code fences and links).

import { RENDER_OPTIONS } from '../manifest.mjs';

/** Build a YAML frontmatter block from an ordered object. */
export function frontmatter(obj) {
  const lines = ['---'];
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined || v === null) continue;
    lines.push(`${k}: ${formatYamlValue(k, v)}`);
  }
  lines.push('---');
  return lines.join('\n');
}

function formatYamlValue(key, v) {
  if (typeof v !== 'string') return String(v);
  // `title` and `description` are always quoted (matches existing output).
  if (key === 'title' || key === 'description') {
    return `"${v.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
  }
  return v;
}

export function heading(level, text) {
  return `${'#'.repeat(level)} ${text}`;
}

export function inlineCode(text) {
  if (!text.includes('`')) return `\`${text}\``;
  return `\`\` ${text} \`\``;
}

export function codeBlock(text, lang = '') {
  return `\`\`\`${lang}\n${text}\n\`\`\``;
}

export function link(text, url) {
  return `[${text}](${url})`;
}

export function bulletList(items) {
  return items.map(i => `- ${i}`).join('\n');
}

/**
 * Escape a value for use inside a markdown table cell. Newlines collapse to
 * spaces and pipes are escaped so they don't break the column. `<`/`>` are
 * left untouched because cell content is pre-rendered markdown (links, code).
 */
export function escapeTableCell(text) {
  return String(text ?? '')
    .replace(/\s+/g, ' ') // collapse newlines + space runs to a single space
    .replace(/\|/g, '\\|')
    .trim();
}

/**
 * Render a GFM table. Columns whose every body cell is blank are dropped
 * (when RENDER_OPTIONS.dropEmptyTableColumns is on) — this reproduces
 * typedoc-plugin-markdown omitting e.g. an all-empty "Description" column.
 *
 * @param {string[]} headers
 * @param {string[][]} rows
 */
export function table(headers, rows) {
  if (rows.length === 0) return '';

  let cols = headers.map((_, i) => i);
  if (RENDER_OPTIONS.dropEmptyTableColumns) {
    // Emptiness is judged on the ORIGINAL cells (before the `-` placeholder).
    cols = cols.filter(i => rows.some(r => (r[i] ?? '').trim().length > 0));
    // Always keep at least the first column.
    if (cols.length === 0) cols = [0];
  }

  const h = cols.map(i => headers[i] ?? '');
  // In a kept column, an empty body cell renders as `-` (matches the previous
  // output). All-empty columns were already dropped above.
  const body = rows.map(r =>
    cols.map(i => {
      const cell = r[i] ?? '';
      return cell.trim() === '' ? '-' : cell;
    })
  );
  const all = [h, ...body];
  const widths = h.map((_, c) => Math.max(...all.map(r => (r[c] ?? '').length)));

  const renderRow = r =>
    `| ${r.map((cell, i) => (cell ?? '').padEnd(widths[i])).join(' | ')} |`;
  const sep = `| ${widths.map(w => '-'.repeat(Math.max(w, 3))).join(' | ')} |`;
  return [renderRow(h), sep, ...body.map(renderRow)].join('\n');
}

/** Join non-empty markdown chunks with exactly one blank line between them. */
export function sectionsToMarkdown(parts) {
  return parts.filter(p => p && String(p).trim().length > 0).join('\n\n');
}

/** URL-name convention used by the Docs site: lowercased member name. */
export function slugifyName(name) {
  return name.toLowerCase();
}
