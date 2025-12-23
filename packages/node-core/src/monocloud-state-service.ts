import { decryptAuthState, encryptAuthState } from '@monocloud/auth-core/utils';
import { MonoCloudOptionsBase, MonoCloudState, SameSiteValues } from './types';
import {
  CookieOptions,
  IMonoCloudCookieRequest,
  IMonoCloudCookieResponse,
} from './types/internal';

export class MonoCloudStateService {
  constructor(private readonly options: MonoCloudOptionsBase) {}

  async setState(
    res: IMonoCloudCookieResponse,
    state: MonoCloudState,
    overrideSameSite?: SameSiteValues
  ): Promise<void> {
    await res.setCookie(
      this.options.state.cookie.name,
      await encryptAuthState(state, this.options.cookieSecret),
      this.getCookieOptions(overrideSameSite)
    );
  }

  async getState(
    req: IMonoCloudCookieRequest,
    res: IMonoCloudCookieResponse
  ): Promise<MonoCloudState | undefined> {
    // Get the cookie
    const cookie = await req.getCookie(this.options.state.cookie.name);

    // Handle no cookie
    if (!cookie) {
      return undefined;
    }

    let decryptedResult: MonoCloudState;

    try {
      // Decrypt the cookie value
      decryptedResult = await decryptAuthState(
        cookie,
        this.options.cookieSecret
      );
    } catch {
      return undefined;
    }

    // Remove the cookie
    await res.setCookie(this.options.state.cookie.name, '', {
      ...this.getCookieOptions(),
      expires: new Date(0),
    });

    // return the state
    return decryptedResult;
  }

  private getCookieOptions(sameSite?: SameSiteValues): CookieOptions {
    return {
      domain: this.options.state.cookie.domain,
      httpOnly: this.options.state.cookie.httpOnly,
      sameSite: sameSite ?? this.options.state.cookie.sameSite,
      secure: this.options.state.cookie.secure,
      path: this.options.state.cookie.path,
    };
  }
}
