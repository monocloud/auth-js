/**
 * Base class for all MonoCloud authentication errors.
 *
 * All errors thrown by the MonoCloud SDK extend this class, allowing applications to safely detect and handle MonoCloud-specific failures using `instanceof`.
 *
 * @category Error Classes
 */
export class MonoCloudAuthBaseError extends Error {}
