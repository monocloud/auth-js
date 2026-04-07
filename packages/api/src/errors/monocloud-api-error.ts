/**
 * Base class for all MonoCloud API errors.
 *
 * All errors thrown by the MonoCloud API SDK extend this class, allowing applications to safely detect and handle MonoCloud-specific failures using `instanceof`.
 *
 * @category Error Classes
 */
export class MonoCloudApiError extends Error {}
