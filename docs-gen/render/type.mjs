// Render a TypeDoc Type AST node to a markdown fragment.
//
// Convention (mirrors typedoc-plugin-markdown): every leaf token (intrinsic
// name, literal, reference name) is wrapped in a code span, and structural
// punctuation markdown would otherwise eat (`<`, `>`, `|`) is backslash-
// escaped, so the result is safe in prose, tables, or quote blocks.

import { inlineCode, link } from './markdown.mjs';

const LT = '\\<';
const GT = '\\>';
const OR = '\\|';

/**
 * @typedef {object} RenderContext
 * @property {(reflection: import('typedoc').Reflection) => string | null} linkFor
 */

export function renderType(type, ctx) {
  if (!type) return inlineCode('unknown');
  const fn = HANDLERS[type.type];
  if (!fn) return inlineCode(safeToString(type));
  return fn(type, ctx);
}

const HANDLERS = {
  intrinsic: t => inlineCode(t.name),

  literal: t => {
    if (typeof t.value === 'string') return inlineCode(`"${t.value}"`);
    if (t.value === null) return inlineCode('null');
    if (typeof t.value === 'object' && t.value && 'value' in t.value)
      return inlineCode(`${t.value.negative ? '-' : ''}${t.value.value}n`);
    return inlineCode(String(t.value));
  },

  reference: (t, ctx) => {
    const url = t.reflection ? ctx.linkFor(t.reflection) : null;
    const head = url ? link(inlineCode(t.name), url) : inlineCode(t.name);
    const args = t.typeArguments?.length
      ? `${LT}${t.typeArguments.map(a => renderType(a, ctx)).join(', ')}${GT}`
      : '';
    return `${head}${args}`;
  },

  array: (t, ctx) => `${wrapForArray(renderType(t.elementType, ctx))}[]`,

  tuple: (t, ctx) =>
    `[${(t.elements ?? []).map(e => renderType(e, ctx)).join(', ')}]`,

  namedTupleMember: (t, ctx) =>
    `${t.name}${t.isOptional ? '?' : ''}: ${renderType(t.element, ctx)}`,

  union: (t, ctx) =>
    t.types
      .map(x => {
        const r = renderType(x, ctx);
        // Parenthesize function types inside a union: `A \| ((x) => B)`.
        if (x.type === 'reflection' && x.declaration?.signatures?.length === 1) {
          return `(${r})`;
        }
        return r;
      })
      .join(` ${OR} `),

  intersection: (t, ctx) => t.types.map(x => renderType(x, ctx)).join(' & '),

  conditional: (t, ctx) =>
    `${renderType(t.checkType, ctx)} extends ${renderType(t.extendsType, ctx)} ? ${renderType(t.trueType, ctx)} : ${renderType(t.falseType, ctx)}`,

  indexedAccess: (t, ctx) =>
    `${renderType(t.objectType, ctx)}[${renderType(t.indexType, ctx)}]`,

  inferred: t => `infer ${inlineCode(t.name)}`,

  predicate: (t, ctx) => {
    const prefix = t.asserts ? 'asserts ' : '';
    const target = t.targetType ? ` is ${renderType(t.targetType, ctx)}` : '';
    return `${prefix}${inlineCode(t.name)}${target}`;
  },

  query: (t, ctx) => `typeof ${renderType(t.queryType, ctx)}`,

  rest: (t, ctx) => `...${renderType(t.elementType, ctx)}`,

  optional: (t, ctx) => `${renderType(t.elementType, ctx)}?`,

  templateLiteral: (t, ctx) => {
    const parts = [t.head];
    for (const [innerType, suffix] of t.tail ?? []) {
      parts.push('${', renderType(innerType, ctx), '}', suffix);
    }
    return inlineCode(`\`${parts.join('')}\``);
  },

  typeOperator: (t, ctx) => `${t.operator} ${renderType(t.target, ctx)}`,

  mapped: (t, ctx) => {
    const param = t.parameter;
    const paramType = renderType(t.parameterType, ctx);
    return `\\{ [${inlineCode(param)} in ${paramType}]: ${renderType(t.templateType, ctx)} \\}`;
  },

  reflection: (t, ctx) => renderReflectionType(t, ctx),

  unknown: t => inlineCode(t.name ?? 'unknown'),
};

// Inline anonymous types ----------------------------------------------------

function renderReflectionType(t, ctx) {
  const decl = t.declaration;
  if (!decl) return inlineCode('object');

  if (decl.signatures?.length) {
    // Single call signature -> arrow form `(p) => R`. Multiple (overloaded
    // callable) -> brace/colon form `\{(p): R; (p): R; \}`.
    if (decl.signatures.length === 1) {
      return renderCallableInline(decl.signatures[0], ctx, '=>');
    }
    return `\\{${decl.signatures.map(s => renderCallableInline(s, ctx, ':')).join('; ')}; \\}`;
  }

  const props = decl.children ?? [];
  const indexSig = decl.indexSignatures?.[0];
  const parts = [];
  if (indexSig) {
    const key = indexSig.parameters?.[0];
    parts.push(
      `\\[${inlineCode(key?.name ?? 'key')}: ${renderType(key?.type, ctx)}\\]: ${renderType(indexSig.type, ctx)}`
    );
  }
  for (const p of props) {
    const opt = p.flags?.isOptional ? '?' : '';
    parts.push(`${inlineCode(p.name + opt)}: ${renderType(p.type, ctx)}`);
  }
  if (parts.length === 0) return inlineCode('{}');
  return `\\{ ${parts.join('; ')}; \\}`;
}

function renderCallableInline(sig, ctx, sep) {
  const params = (sig.parameters ?? [])
    .map(p => {
      const opt = p.flags?.isOptional ? '?' : '';
      return `${inlineCode(p.name + opt)}: ${renderType(p.type, ctx)}`;
    })
    .join(', ');
  const ret = renderType(sig.type, ctx);
  return sep === '=>' ? `(${params}) => ${ret}` : `(${params}): ${ret}`;
}

// Helpers -------------------------------------------------------------------

function wrapForArray(rendered) {
  if (rendered.includes(OR) || rendered.includes(' & ')) return `(${rendered})`;
  return rendered;
}

function safeToString(t) {
  try {
    return t.toString?.() ?? `${t.type ?? 'unknown'}`;
  } catch {
    return String(t.type ?? 'unknown');
  }
}
