import { MonoCloudRawResponse } from '../types';

/**
 * Base class for all MonoCloud authentication errors.
 *
 * All errors thrown by the MonoCloud SDK extend this class, allowing applications to safely detect and handle MonoCloud-specific failures using `instanceof`.
 *
 * @category Error Classes
 */
export class MonoCloudAuthBaseError extends Error {
  /**
   * The raw HTTP response this error was derived from.
   */
  readonly raw?: MonoCloudRawResponse;

  constructor(message?: string, raw?: MonoCloudRawResponse) {
    super(message);
    this.raw = raw;
  }
}
