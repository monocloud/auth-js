import { MonoCloudTokenErrorCode } from '../types';
import { MonoCloudAuthBaseError } from './monocloud-auth-base-error';

/**
 * Error thrown when a token operation fails.
 *
 * @category Error Classes
 */
export class MonoCloudTokenError extends MonoCloudAuthBaseError {
  /** Code identifying why the token operation failed. */
  readonly code: MonoCloudTokenErrorCode;

  constructor(
    message?: string,
    code: MonoCloudTokenErrorCode = 'invalid_token'
  ) {
    super(message);
    this.code = code;
  }
}
