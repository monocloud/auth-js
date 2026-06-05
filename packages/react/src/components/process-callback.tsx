'use client';

import React, { useEffect, useRef, useState } from 'react';
import { useProcessCallback } from '../use-process-callback';
import type { ProcessCallbackProps } from '../types';

type State =
  | { status: 'processing' }
  | { status: 'done' }
  | { status: 'error'; error: Error };

/**
 * `<ProcessCallback/>` completes a pending sign-in or sign-out callback on the
 * current URL and synchronizes the authentication state.
 *
 * Render it on the dedicated route that MonoCloud redirects back to (for
 * example, `/callback`) and disable automatic processing on the provider with
 * `autoProcessCallback={false}`. It renders no UI of its own beyond the optional
 * `loading`, `error`, and `children` slots. Navigation after a successful
 * callback is controlled by the provider-level `postCallback` option, not by
 * this component.
 *
 * @example Dedicated callback route
 *
 * ```tsx title="Dedicated callback route"
 * "use client";
 *
 * import { ProcessCallback } from "@monocloud/auth-react";
 *
 * export default function Callback() {
 *   return (
 *     <ProcessCallback
 *       loading={<p>Completing sign in…</p>}
 *       error={(err) => <p>Sign in failed: {err.message}</p>}
 *     />
 *   );
 * }
 * ```
 *
 * @param props - Props for customizing the rendered states.
 * @returns The `loading`, `error`, or `children` content depending on the
 * processing state.
 *
 * @category Components
 */
export const ProcessCallback = ({
  loading = null,
  error,
  children = null,
}: ProcessCallbackProps): React.ReactNode => {
  const processCallback = useProcessCallback();
  const [state, setState] = useState<State>({ status: 'processing' });
  const ran = useRef(false);

  useEffect(() => {
    /* v8 ignore start -- StrictMode double-invocation guard */
    if (ran.current) {
      return;
    }
    /* v8 ignore stop */
    ran.current = true;

    processCallback()
      .then(() => setState({ status: 'done' }))
      .catch((e: Error) => setState({ status: 'error', error: e }));
  }, [processCallback]);

  if (state.status === 'processing') {
    return <>{loading}</>;
  }

  if (state.status === 'error') {
    return (
      <>{typeof error === 'function' ? error(state.error) : (error ?? null)}</>
    );
  }

  return <>{children}</>;
};
