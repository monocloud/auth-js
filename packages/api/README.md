<div align="center">
  <a href="https://www.monocloud.com?utm_source=github&utm_medium=auth_js" target="_blank" rel="noopener noreferrer">
    <picture>
      <img src="https://raw.githubusercontent.com/monocloud/auth-js/refs/heads/main/packages/api/banner.svg" alt="MonoCloud Banner">
    </picture>
  </a>
  <div align="right">
    <a href="https://www.npmjs.com/package/@monocloud/api-core" target="_blank">
      <img src="https://img.shields.io/npm/v/@monocloud/api-core" alt="NPM" />
    </a>
    <a href="https://opensource.org/licenses/MIT">
      <img src="https://img.shields.io/:license-MIT-blue.svg?style=flat" alt="License: MIT" />
    </a>
    <a href="https://github.com/monocloud/auth-js/actions/workflows/build.yml">
      <img src="https://github.com/monocloud/auth-js/actions/workflows/build.yml/badge.svg" alt="Build Status" />
    </a>
  </div>
</div>

## Introduction

**MonoCloud API Client for JavaScript — validate access tokens issued by a MonoCloud authorization server.**

[MonoCloud](https://www.monocloud.com?utm_source=github&utm_medium=auth_js) is a modern, developer-friendly Identity & Access Management platform.

This package provides a **framework-agnostic API client** for validating access tokens using MonoCloud. It supports both **JWT access tokens** (validated locally via JWKS) and **opaque access tokens** (validated via [OAuth 2.0 Token Introspection (RFC 7662)](https://datatracker.ietf.org/doc/html/rfc7662)).

> This package focuses on **resource server token validation**. For browser/server authentication flows, see [`@monocloud/auth-core`](https://www.npmjs.com/package/@monocloud/auth-core).

## Documentation

- **Documentation:** [https://www.monocloud.com/docs](https://www.monocloud.com/docs?utm_source=github&utm_medium=auth_js)
- **API Reference:** [https://monocloud.github.io/auth-js](https://monocloud.github.io/auth-js?utm_source=github&utm_medium=auth_js)

## Supported Platforms

- **Node.js >= 16.0.0** (Requires `fetch` and Web Crypto API)
- **Modern Browsers**

## Requirements

- A **MonoCloud Tenant**
- A **Client** configured with a client secret for introspection

## Installation

```bash
npm install @monocloud/api-core
```

### Initialization

```typescript
import { MonoCloudApiClient } from '@monocloud/api-core';

const apiClient = new MonoCloudApiClient(
  'https://<your-tenant-domain>',
  '<your-client-id>',
  {
    clientSecret: '<your-client-secret>',
    audience: '<your-api-audience>',
  }
);
```

## Usage

### Validate an Access Token

Validate a JWT or opaque access token. The client automatically detects the token format.

```typescript
try {
  const claims = await apiClient.validateAccessToken(accessToken);

  console.log(claims.sub);   // Subject (user identifier)
  console.log(claims.scope); // Scopes granted
  console.log(claims.iss);   // Issuer
} catch (error) {
  // Token is invalid, expired, or introspection failed
  console.error('Token validation failed:', error.message);
}
```

## When should I use `api-core`?

Use **`@monocloud/api-core`** if you are building a **resource server / API** that needs to validate incoming access tokens.

This package is a good fit if you:

- Need to **validate JWT access tokens** against the authorization server's JWKS
- Need to **validate opaque access tokens** via the introspection endpoint
- Want **automatic token format detection** (JWT vs. opaque)
- Are building a **framework-agnostic API middleware**
- Want a **self-contained client** with no external dependencies

For browser/server authentication flows (login, logout, session management), use [`@monocloud/auth-core`](https://www.npmjs.com/package/@monocloud/auth-core) instead.

## Contributing & Support

### Issues & Feedback

- Use **GitHub Issues** for bug reports and feature requests.
- For tenant or account-specific help, contact MonoCloud Support through your dashboard.

### Security

Do **not** report security issues publicly. Please follow the contact instructions at: [https://www.monocloud.com/contact](https://www.monocloud.com/contact?utm_source=github&utm_medium=auth_js)

## License

Licensed under the **MIT License**. See the included [`LICENSE`](https://github.com/monocloud/auth-js/blob/main/LICENSE) file.
