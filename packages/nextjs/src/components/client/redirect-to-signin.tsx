'use client';

import { useEffect } from 'react';
import { redirectToSignIn } from '../../client/protect';
import { ExtraAuthParams } from '../../types';

/**
 * Props for the `<RedirectToSignIn />` Component
 */
export interface RedirectToSignInProps extends ExtraAuthParams {
  /**
   * The url where the user will be redirected to after sign in.
   */
  returnUrl?: string;
}

/**
 * A client side component that will redirect users to the sign in page.
 *
 * @type RedirectToSignInProps
 */
export const RedirectToSignIn = ({
  returnUrl,
  ...authParams
}: RedirectToSignInProps): null => {
  useEffect(() => {
    redirectToSignIn({ returnUrl, ...authParams });
  }, [authParams, returnUrl]);
  return null;
};
