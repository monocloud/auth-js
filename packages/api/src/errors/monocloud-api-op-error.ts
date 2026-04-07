import { MonoCloudApiError } from './monocloud-api-error';

/**
 * OAuth error returned by the authorization server during an introspection or token request.
 *
 * These errors correspond to standard OAuth / OpenID Connect error responses such as `invalid_request`, `invalid_token`, or `invalid_client`.
 *
 * @category Error Classes
 */
export class MonoCloudApiOPError extends MonoCloudApiError {
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
