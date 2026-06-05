---
rootSdk: @monocloud/auth-react
title: "ProcessCallback"
category: Components
description: "<ProcessCallback/> completes a pending sign-in or sign-out callback on the current URL and synchronizes the authentication state."
---

# Component: &lt;ProcessCallback&gt;

`<ProcessCallback/>` completes a pending sign-in or sign-out callback on the
current URL and synchronizes the authentication state.

Render it on the dedicated route that MonoCloud redirects back to (for
example, `/callback`) and disable automatic processing on the provider with
`autoProcessCallback={false}`. It renders no UI of its own beyond the optional
`loading`, `error`, and `children` slots. Navigation after a successful
callback is controlled by the provider-level `postCallback` option, not by
this component.

## Props

| Property                          | Type                                               | Description                                                          |
| --------------------------------- | -------------------------------------------------- | -------------------------------------------------------------------- |
| `children?` | `ReactNode`                                        | Content rendered after the callback has been processed successfully. |
| `error?`       | `ReactNode` \| ((`error`: `Error`) => `ReactNode`) | Content rendered when callback processing fails.                     |
| `loading?`   | `ReactNode`                                        | Content rendered while the callback is being processed.              |


## Example

```tsx title="Dedicated callback route"
"use client";

import { ProcessCallback } from "@monocloud/auth-react";

export default function Callback() {
  return (
    <ProcessCallback
      loading={<p>Completing sign in…</p>}
      error={(err) => <p>Sign in failed: {err.message}</p>}
    />
  );
}
```
