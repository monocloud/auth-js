import { decryptAuthState, encryptAuthState } from '@monocloud/auth-core/utils';
import { sha256 } from '@monocloud/auth-core/internal';
import { MonoCloudOptionsBase, MonoCloudState, SameSiteValues } from './types';
import {
  CookieOptions,
  IMonoCloudCookieRequest,
  IMonoCloudCookieResponse,
} from './types/internal';

export class MonoCloudStateService {
  constructor(private readonly options: MonoCloudOptionsBase) {}

  async setState(
    req: IMonoCloudCookieRequest,
    res: IMonoCloudCookieResponse,
    state: MonoCloudState,
    overrideSameSite?: SameSiteValues
  ): Promise<void> {
    const cookieName = await this.getCookieName(state.state);

    await this.evictSurplusStates(req, res, cookieName);

    await res.setCookie(
      cookieName,
      await encryptAuthState(
        state,
        this.options.cookieSecret,
        this.options.state.duration
      ),
      this.getCookieOptions(overrideSameSite)
    );
  }

  async getState(
    req: IMonoCloudCookieRequest,
    res: IMonoCloudCookieResponse,
    state: string
  ): Promise<MonoCloudState | undefined> {
    const cookieName = await this.getCookieName(state);
    const cookie = await req.getCookie(cookieName);

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
      await this.removeCookie(res, cookieName);
      return undefined;
    }

    // Remove the cookie
    await this.removeCookie(res, cookieName);

    // return the state
    return decryptedResult;
  }

  async removeStaleStates(
    req: IMonoCloudCookieRequest,
    res: IMonoCloudCookieResponse
  ): Promise<void> {
    await this.pruneStates(
      res,
      await this.getStateCookies(req),
      this.options.state.maxConcurrent
    );
  }

  async removeAllStates(
    req: IMonoCloudCookieRequest,
    res: IMonoCloudCookieResponse
  ): Promise<void> {
    for (const [name] of await this.getStateCookies(req)) {
      await this.removeCookie(res, name);
    }
  }

  private async getCookieName(state: string): Promise<string> {
    return `${this.options.state.cookie.name}.${await sha256(state)}`;
  }

  private async getStateCookies(
    req: IMonoCloudCookieRequest
  ): Promise<Map<string, string>> {
    const { name } = this.options.state.cookie;

    const cookies = await req.getAllCookies();

    return new Map(
      [...cookies].filter(
        ([cookieName]) =>
          cookieName === name ||
          (cookieName.startsWith(`${name}.`) &&
            /^[\w-]+$/.test(cookieName.slice(name.length + 1)))
      )
    );
  }

  private async evictSurplusStates(
    req: IMonoCloudCookieRequest,
    res: IMonoCloudCookieResponse,
    cookieName: string
  ): Promise<void> {
    const cookies = await this.getStateCookies(req);

    // The cookie is going to be overwritten and does not count towards the limit.
    cookies.delete(cookieName);

    await this.pruneStates(res, cookies, this.options.state.maxConcurrent - 1);
  }

  /**
   * Retains the latest usable transactions, up to the specified capacity.
   */
  private async pruneStates(
    res: IMonoCloudCookieResponse,
    cookies: Map<string, string>,
    capacity: number
  ): Promise<void> {
    const names = [...cookies.keys()];

    const surplus = Math.max(names.length - capacity, 0);

    for (const name of names.slice(0, surplus)) {
      await this.removeCookie(res, name);
    }

    for (const name of names.slice(surplus)) {
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      if (!(await this.isUsable(cookies.get(name)!))) {
        await this.removeCookie(res, name);
      }
    }
  }

  private async isUsable(value: string): Promise<boolean> {
    try {
      await decryptAuthState(value, this.options.cookieSecret);
      return true;
    } catch {
      return false;
    }
  }

  private async removeCookie(
    res: IMonoCloudCookieResponse,
    name: string
  ): Promise<void> {
    await res.setCookie(name, '', {
      ...this.getCookieOptions(),
      maxAge: undefined,
      expires: new Date(0),
    });
  }

  private getCookieOptions(sameSite?: SameSiteValues): CookieOptions {
    return {
      domain: this.options.state.cookie.domain,
      httpOnly: this.options.state.cookie.httpOnly,
      sameSite: sameSite ?? this.options.state.cookie.sameSite,
      secure: this.options.state.cookie.secure,
      path: this.options.state.cookie.path,
      maxAge: this.options.state.duration,
    };
  }
}
