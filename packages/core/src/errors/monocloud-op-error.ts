import { MonoCloudAuthBaseError } from './monocloud-auth-base-error';

export class MonoCloudOPError extends MonoCloudAuthBaseError {
  error: string;

  errorDescription?: string;

  constructor(error: string, errorDescription?: string) {
    super(error);
    this.error = error;
    this.errorDescription = errorDescription;
  }
}
