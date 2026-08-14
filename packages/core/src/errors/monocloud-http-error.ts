import { MonoCloudAuthBaseError } from './monocloud-auth-base-error';

/**
 * Error thrown when a request to the MonoCloud authorization server fails.
 *
 * This error typically indicates a network failure, an unexpected HTTP response, or an unsuccessful response returned by the authorization server.
 *
 * @category Error Classes
 */
export class MonoCloudHttpError extends MonoCloudAuthBaseError {
  /**
   * HTTP status code of the response that caused the error.
   *
   * Undefined when no response was received, such as a network failure.
   */
  get status(): number | undefined {
    return this.raw?.status;
  }

  /**
   * HTTP status text of the response that caused the error.
   */
  get statusText(): string | undefined {
    return this.raw?.statusText;
  }
}
