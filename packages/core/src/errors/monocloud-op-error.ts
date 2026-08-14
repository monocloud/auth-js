import { MonoCloudRawResponse } from '../types';
import { MonoCloudAuthBaseError } from './monocloud-auth-base-error';

/**
 * OAuth error returned by the authorization server.
 *
 * @category Error Classes
 */
export class MonoCloudOPError extends MonoCloudAuthBaseError {
  /**
   * OAuth error code returned by the authorization server.
   *
   * When the response carries no readable error body, this is inferred from the endpoint and status code instead.
   */
  error: string;

  /** Human-readable description of the error. */
  errorDescription?: string;

  constructor(
    error: string,
    errorDescription?: string,
    raw?: MonoCloudRawResponse
  ) {
    super(error, raw);
    this.error = error;
    this.errorDescription = errorDescription;
  }
}
