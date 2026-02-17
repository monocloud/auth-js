---
rootSdk: Next.js
title: "ProtectedRouteMatcher"
category: Types
---

# Type: ProtectedRouteMatcher

> **ProtectedRouteMatcher** = `string` \| `RegExp` \| \{ `groups`: `string`[]; `routes`: (`string` \| `RegExp`)[]; \}

Defines how routes are matched and protected by authentication and optional group-based authorization.

## Type Declaration

`string`

`RegExp`

\{ `groups`: `string`[]; `routes`: (`string` \| `RegExp`)[]; \}

| Name     | Type                     | Description                                                                                                                                          |
| -------- | ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `groups` | `string`[]               | Optional group-based access control. When provided, only users belonging to **at least one** of the specified group IDs or names are allowed access. |
| `routes` | (`string` \| `RegExp`)[] | Route patterns that should be protected. Each entry may be: - A relative route path - A regular expression used to match routes                      |
