// React hooks render exactly like a single-/multi-signature function: the
// signature line under the H1, description, Returns, then Examples.

import { renderFunctionBody } from './function.mjs';

export function renderHookBody(ref, ctx) {
  return renderFunctionBody(ref, ctx);
}
