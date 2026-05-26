import { MonoCloudAuthBaseError } from '@monocloud/auth-core';

/**
 * Error thrown when a general JavaScript or internal SDK failure occurs.
 *
 * This error indicates an unexpected issue within the browser that does not fall under network, validation, or OAuth-specific categories.
 *
 * @category Error Classes
 * @hideconstructor
 */
export class MonoCloudJsError extends MonoCloudAuthBaseError {}
