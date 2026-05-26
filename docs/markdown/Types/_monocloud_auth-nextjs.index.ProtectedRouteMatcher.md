---
rootSdk: Next.js
title: "ProtectedRouteMatcher"
category: Types
description: "Defines how routes are matched and protected by authentication and optional group-based authorization."
---

# Type: ProtectedRouteMatcher

> **ProtectedRouteMatcher** = `string` \| `RegExp` \| \{ `groups`: `string`[]; `routes`: (`string` \| `RegExp`)[]; \}

Defines how routes are matched and protected by authentication and optional group-based authorization.

## Type Declaration

> `string`

A single relative route path to protect.


> `RegExp`

A regular expression used to match routes to protect.


> \{ `groups`: `string`[]; `routes`: (`string` \| `RegExp`)[]; \}

An object with fine-grained control over routes and group-based access.

| Name     | Type                     | Description                                                                                                                                          |
| -------- | ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `groups` | `string`[]               | Optional group-based access control. When provided, only users belonging to **at least one** of the specified group IDs or names are allowed access. |
| `routes` | (`string` \| `RegExp`)[] | Route patterns that should be protected. Each entry may be a relative route path or a regular expression used to match routes.                       |
