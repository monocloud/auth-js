'use client';

import type { MonoCloudWebJSClient } from '@monocloud/auth-web-js';
import { createContext } from 'react';
import type { MonoCloudAuth } from './types';

export const MonoCloudAuthContext = createContext<MonoCloudAuth | undefined>(
  undefined
);

export const MonoCloudClientContext = createContext<
  MonoCloudWebJSClient | undefined
>(undefined);

export const MonoCloudProcessCallbackContext = createContext<
  (() => Promise<void>) | undefined
>(undefined);
