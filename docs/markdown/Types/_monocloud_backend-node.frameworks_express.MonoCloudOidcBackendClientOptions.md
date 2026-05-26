---
rootSdk: Node.js Backend
title: "MonoCloudOidcBackendClientOptions"
category: Types
framework: Express
description: "Configuration options used to initialize the MonoCloudOidcBackendClient."
---

# Type: MonoCloudOidcBackendClientOptions

Configuration options used to initialize the MonoCloudOidcBackendClient.

## Extends

- [`MonoCloudClientOptionsBase`](/sdks/nodejs/api-reference/types/monocloudclientoptionsbase)

## clientAuthMethod
> `optional` **clientAuthMethod**: [`ClientAuthMethod`](/sdks/express-backend/api-reference/enums/clientauthmethod)

Client authentication method used when communicating with the token endpoint.

### Default Value

```ts
"client_secret_basic";
```

### Inherited from

[`MonoCloudClientOptionsBase`](/sdks/nodejs/api-reference/types/monocloudclientoptionsbase).[`clientAuthMethod`](/sdks/nodejs/api-reference/types/monocloudclientoptionsbase#clientauthmethod)

---

## clientId
> `optional` **clientId**: `string`

Client identifier of the application registered in MonoCloud.

---

## clientSecret
> `optional` **clientSecret**: `string` \| [`Jwk`](/sdks/express-backend/api-reference/types/jwk)

Client secret or key material used for client authentication.

When `clientAuthMethod` is `client_secret_jwt` and a plain-text secret is provided, the default signing algorithm is `HS256`.

To use a different algorithm, provide a symmetric JSON Web Key (JWK) (`kty: "oct"`) with the desired algorithm specified in its `alg` property.

### Inherited from

[`MonoCloudClientOptionsBase`](/sdks/nodejs/api-reference/types/monocloudclientoptionsbase).[`clientSecret`](/sdks/nodejs/api-reference/types/monocloudclientoptionsbase#clientsecret)

---

## clockSkew
> `optional` **clockSkew**: `number`

Number of seconds to adjust the current time to account for clock differences.

### Default Value

```ts
0;
```

---

## clockTolerance
> `optional` **clockTolerance**: `number`

Additional time tolerance in seconds for time-based claim validation.

### Default Value

```ts
300;
```

---

## fetcher
> `optional` **fetcher**: \{(`input`: `URL` \| `RequestInfo`, `init?`: `RequestInit`): `Promise`\<`Response`\>; (`input`: `string` \| `URL` \| `Request`, `init?`: `RequestInit`): `Promise`\<`Response`\>; \}

Optional custom `fetch` implementation used for network requests.

### Call Signature

> (`input`: `URL` \| `RequestInfo`, `init?`: `RequestInit`): `Promise`\<`Response`\>

[MDN Reference](https://developer.mozilla.org/docs/Web/API/Window/fetch)

#### Parameters

| Parameter | Type                   |
| --------- | ---------------------- |
| `input`   | `URL` \| `RequestInfo` |
| `init?`   | `RequestInit`          |

#### Returns

`Promise`\<`Response`\>

### Call Signature

> (`input`: `string` \| `URL` \| `Request`, `init?`: `RequestInit`): `Promise`\<`Response`\>

[MDN Reference](https://developer.mozilla.org/docs/Web/API/Window/fetch)

#### Parameters

| Parameter | Type                           |
| --------- | ------------------------------ |
| `input`   | `string` \| `URL` \| `Request` |
| `init?`   | `RequestInit`                  |

#### Returns

`Promise`\<`Response`\>

### Inherited from

[`MonoCloudClientOptionsBase`](/sdks/nodejs/api-reference/types/monocloudclientoptionsbase).[`fetcher`](/sdks/nodejs/api-reference/types/monocloudclientoptionsbase#fetcher)

---

## groupOptions
> `optional` **groupOptions**: [`IsUserInGroupOptions`](/sdks/express-backend/api-reference/types/isuseringroupoptions)

Options for group membership validation applied to all token validations performed by this client.

---

## jwksCacheDuration
> `optional` **jwksCacheDuration**: `number`

Duration (in seconds) to cache the JSON Web Key Set (JWKS) retrieved from the authorization server.

### Default Value

```ts
300;
```

### Inherited from

[`MonoCloudClientOptionsBase`](/sdks/nodejs/api-reference/types/monocloudclientoptionsbase).[`jwksCacheDuration`](/sdks/nodejs/api-reference/types/monocloudclientoptionsbase#jwkscacheduration)

---

## metadataCacheDuration
> `optional` **metadataCacheDuration**: `number`

Duration (in seconds) to cache OpenID Connect discovery metadata.

### Default Value

```ts
300;
```

### Inherited from

[`MonoCloudClientOptionsBase`](/sdks/nodejs/api-reference/types/monocloudclientoptionsbase).[`metadataCacheDuration`](/sdks/nodejs/api-reference/types/monocloudclientoptionsbase#metadatacacheduration)
