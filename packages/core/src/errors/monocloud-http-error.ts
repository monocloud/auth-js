import { MonoCloudAuthBaseError } from './monocloud-auth-base-error';

/**
 * Error thrown when a request to the MonoCloud authorization server fails.
 *
 * This error typically indicates a network failure, an unexpected HTTP response, or an unsuccessful response returned by the authorization server.
 *
 * @category Error Classes
 */
export class MonoCloudHttpError extends MonoCloudAuthBaseError {}
