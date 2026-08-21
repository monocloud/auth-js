---
'@monocloud/auth-nextjs': patch
---

- the back-channel logout route (`/api/auth/backchannel-logout` by default) is now dispatched by `monoCloudAuth()` and `authMiddleware()`; it previously answered `404` even when `onBackChannelLogout` was configured. The route remains `404` until the callback is configured on a client instance (`new MonoCloudNextClient({ onBackChannelLogout })`).
- the `onError` handler passed to `monoCloudAuth()` and `authMiddleware()` now also covers back-channel logout errors.
- App Router catch-all routes mounting `monoCloudAuth()` must export it for `POST` as well, since back-channel logout notifications are `POST` requests.
