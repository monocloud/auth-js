import { MonoCloudAuthBaseError } from './monocloud-auth-base-error';

/**
 * OAuth error returned by the authorization server during an authentication or token request.
 *
 * These errors correspond to standard OAuth / OpenID Connect error responses such as `invalid_request`, `access_denied`, or `invalid_grant`.
 *
 * @category Error Classes
 */
export class MonoCloudOPError extends MonoCloudAuthBaseError {
  /** OAuth error code returned by the authorization server. */
  error: string;

  /** Human-readable description of the error. */
  errorDescription?: string;

  constructor(error: string, errorDescription?: string) {
    super(error);
    this.error = error;
    this.errorDescription = errorDescription;
  }
}
