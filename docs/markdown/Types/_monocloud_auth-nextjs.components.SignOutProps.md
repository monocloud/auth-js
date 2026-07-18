---
rootSdk: Next.js
title: "SignOutProps"
category: Types
description: "Props for the <SignOut /> component."
---

# Type: SignOutProps

Props for the `<SignOut />` component.

## Properties

| Property                                    | Type        | Description                                                                                                                                           |
| ------------------------------------------- | ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `children`            | `ReactNode` | Content rendered inside the link (for example, button text).                                                                                          |
| `federated?`         | `boolean`   | If `true`, also signs the user out of the MonoCloud server session, ensuring the user is fully logged out of MonoCloud and not just your application. |
| `idTokenHint?`     | `string`    | A previously issued ID token to send as the `id_token_hint` on the logout request, overriding the ID token from the current session.                  |
| `postLogoutUrl?` | `string`    | URL to redirect the user to after they have been signed out.                                                                                          |
