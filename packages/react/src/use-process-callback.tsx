'use client';

import { MonoCloudJsError } from '@monocloud/auth-web-js';
import { useContext } from 'react';
import { MonoCloudProcessCallbackContext } from './context';

export const useProcessCallback = (): (() => Promise<void>) => {
  const processCallback = useContext(MonoCloudProcessCallbackContext);

  if (!processCallback) {
    throw new MonoCloudJsError(
      '<ProcessCallback /> can only be used inside a <MonoCloudAuthProvider>...</MonoCloudAuthProvider>.'
    );
  }

  return processCallback;
};
