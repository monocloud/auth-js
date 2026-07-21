// Emit-time link resolution. URLs are computed up front (no post-processing
// pass over the markdown) and a reference is always resolved to the copy that
// lives in the *current* SDK when one exists — matching the previous
// post-generate behaviour, which linked within the source page's SDK.

import { ReferenceReflection } from 'typedoc';
import { categoryMeta } from './manifest.mjs';
import { readCategoryTag } from './reflect.mjs';

/** Canonical URL for an emitted type unit. */
export function urlForUnit(unit) {
  // unit.meta.url is undefined for the "Other" bucket; the template literal
  // intentionally renders it as the literal "undefined" segment to reproduce
  // the current site's link shape.
  return `/sdks/${unit.slug}/api-reference/${unit.meta.url}/${unit.ref.name.toLowerCase()}`;
}

/**
 * Build resolvers over all emitted type units.
 *
 * `resolve` (type references): a re-exported type's reflection points at the
 * ORIGINAL declaration, but the previous pipeline linked to the copy in the
 * current SDK — so prefer a same-SDK copy, falling back to the exact target.
 *
 * `resolveExact` (inline `{@link}` tags): TypeDoc resolves these to the actual
 * target declaration (e.g. an error class defined in auth-core), and the
 * previous pipeline linked there — so use the exact target, with a same-SDK
 * fallback only when it isn't itself an emitted page.
 */
export function buildLinkResolver(units) {
  const byId = new Map();
  const byContent = new Map();

  for (const u of units) {
    const url = urlForUnit(u);
    byId.set(u.ref.id, { unit: u, url });
    const key = `${u.ref.name}::${u.meta.label}`;
    if (!byContent.has(key)) byContent.set(key, []);
    byContent.get(key).push({ unit: u, url });
  }

  const deref = reflection => {
    let r = reflection;
    if (r instanceof ReferenceReflection) r = r.tryGetTargetReflectionDeep?.() ?? r;
    return r;
  };

  const sameSdkCopy = (r, curPkg, curFw) => {
    const label = categoryMeta(readCategoryTag(r)).label;
    const cands = byContent.get(`${r.name}::${label}`);
    if (!cands || cands.length === 0) return null;
    const fw = curFw ?? null;
    const pick =
      cands.find(c => c.unit.pkgName === curPkg && (c.unit.framework ?? null) === fw) ||
      cands.find(c => c.unit.pkgName === curPkg) ||
      (fw && cands.find(c => (c.unit.framework ?? null) === fw)) ||
      cands[0];
    return pick.url;
  };

  function resolve(reflection, curPkg, curFw, selfId) {
    const r = deref(reflection);
    if (!r) return null;
    if (selfId != null && r.id === selfId) return null;
    return sameSdkCopy(r, curPkg, curFw) ?? byId.get(r.id)?.url ?? null;
  }

  function resolveExact(reflection, curPkg, curFw, selfId) {
    const r = deref(reflection);
    if (!r) return null;
    if (selfId != null && r.id === selfId) return null;
    const hit = byId.get(r.id);
    if (hit) {
      // Same package as the page -> prefer the copy in the current SDK/framework
      // (e.g. the express-backend copy). Different package -> link to the exact
      // target (e.g. an error class in auth-core).
      if (hit.unit.pkgName === curPkg) return sameSdkCopy(r, curPkg, curFw) ?? hit.url;
      return hit.url;
    }
    // A `{@link}` to a class/interface member (method/property/accessor) links
    // to that member's anchor on its owner's page — or just `#anchor` when the
    // owner is the current page.
    const owner = r.parent;
    if (owner) {
      const anchor = `#${r.name.toLowerCase()}`;
      if (selfId != null && owner.id === selfId) return anchor;
      const ownerUrl = byId.get(owner.id)?.url ?? sameSdkCopy(owner, curPkg, curFw);
      if (ownerUrl) return ownerUrl + anchor;
    }
    return sameSdkCopy(r, curPkg, curFw);
  }

  return { resolve, resolveExact };
}
