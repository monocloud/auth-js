---
rootSdk: Next.js
title: "ProtectedComponentProps"
category: Types
description: "Props for the <Protected /> component."
---

# Type: ProtectedComponentProps

Props for the `<Protected />` component.

## Properties

| Property                                                | Type                                                                                      | Description                                                                                                                                                                 |
| ------------------------------------------------------- | ----------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `children`                        | `ReactNode`                                                                               | Content to render when access is allowed.                                                                                                                                   |
| `fallback?`                       | `ReactNode`                                                                               | Content to render when the user is not authenticated.                                                                                                                       |
| `groups?`                           | `string`[]                                                                                | Groups required to view the protected content. By default, the user must belong to **any** of the specified groups.                                                         |
| `groupsClaim?`                 | `string`                                                                                  | Name of the claim that contains groups in the user profile.                                                                                                                 |
| `matchAllGroups?`           | `boolean`                                                                                 | If `true`, the user must belong to **all** specified `groups` (instead of any).                                                                                             |
| `onGroupAccessDenied?` | (`user`: [`MonoCloudUser`](/sdks/nextjs/api-reference/types/monoclouduser)) => `ReactNode` | Rendered when the user is authenticated but does not meet the `groups` requirement. If omitted, nothing is rendered (or `fallback` is used only for unauthenticated users). |
