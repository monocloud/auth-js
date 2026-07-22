// Small reflection helpers shared by the emitter and link resolver.

import { ReflectionKind } from 'typedoc';

/** Read the `@category` tag value from a reflection (or its signatures). */
export function readCategoryTag(ref) {
  const read = comment => {
    for (const t of comment?.blockTags ?? []) {
      if (t.tag === '@category') return t.content?.map(p => p.text).join('').trim();
    }
    return null;
  };
  return (
    read(ref.comment) ??
    (ref.signatures ?? []).map(s => read(s.comment)).find(Boolean) ??
    null
  );
}

/** Module path segment -> framework label, or undefined. */
export function frameworkForSegment(seg) {
  if (!seg) return undefined;
  if (seg.includes('express')) return 'Express';
  if (seg.includes('fastify')) return 'Fastify';
  return undefined;
}

// Default typedoc group name per kind, used as the index-page heading for
// members that carry no `@category` tag (utility functions).
const KIND_GROUP = {
  [ReflectionKind.Class]: 'Classes',
  [ReflectionKind.Interface]: 'Interfaces',
  [ReflectionKind.TypeAlias]: 'Type Aliases',
  [ReflectionKind.Enum]: 'Enumerations',
  [ReflectionKind.Function]: 'Functions',
  [ReflectionKind.Variable]: 'Variables',
};

export function kindGroupName(kind) {
  return KIND_GROUP[kind] ?? 'Other';
}
