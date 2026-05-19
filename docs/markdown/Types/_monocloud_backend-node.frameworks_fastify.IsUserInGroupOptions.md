---
rootSdk: Node.js Backend
title: "IsUserInGroupOptions"
category: Types
framework: Fastify
description: "Options for configuring group membership validation on access tokens."
---

# Type: IsUserInGroupOptions

Options for configuring group membership validation on access tokens.

## groupsClaim?

> `optional` **groupsClaim**: `string`

The claim name in the token that contains group memberships.

### Default Value

```ts
"groups";
```

---

## matchAll?

> `optional` **matchAll**: `boolean`

When `true`, requires the token to contain all specified groups.
When `false`, requires at least one of the specified groups.

### Default Value

```ts
false;
```
