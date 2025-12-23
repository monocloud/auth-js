export {
  MonoCloudAuthBaseError,
  MonoCloudValidationError,
  MonoCloudHttpError,
  MonoCloudOPError,
  MonoCloudTokenError,
  type MonoCloudOptions,
} from '@monocloud/auth-node-core';

export type {
  ProtectPagePageReturnType,
  ProtectOptions,
  MonoCloudMiddlewareOptions,
  IsUserInGroupOptions,
  ExtraAuthParams,
  MonoCloudAuthOptions,
  GroupOptions,
  MonoCloudMiddleware,
  Protect,
  ProtectApi,
  ProtectPage,
  RedirectToSignInOptions,
  RedirectToSignOutOptions,
  ProtectAppApi,
  ProtectAppPage,
  ProtectAppPageOptions,
  ProtectPageApi,
  ProtectPagePage,
  NextPageRouterApiOnAccessDeniedHandler,
  ProtectPagePageOptions,
  AppRouterApiOnAccessDeniedHandlerFn,
  ProtectPagePageOnAccessDeniedType,
} from './types';

export { MonoCloudNextClient } from './monocloud-next-client';
