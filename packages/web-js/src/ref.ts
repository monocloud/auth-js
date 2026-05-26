import { MonoCloudJsError } from './monocloud-js-error';

export class Ref {
  constructor(
    private readonly mode: 'silent' | 'popup',
    private readonly ref: Window | HTMLIFrameElement | undefined
  ) {}

  getRef<T>(): T {
    return this.ref as T;
  }

  setUrl(url: string): void {
    switch (this.mode) {
      case 'popup': {
        this.getRef<Window>().location.href = url;
        break;
      }

      case 'silent': {
        this.getRef<HTMLIFrameElement>().setAttribute('src', url);
        break;
      }
    }
  }

  // eslint-disable-next-line consistent-return
  getWindow(): Window {
    switch (this.mode) {
      case 'silent': {
        const { contentWindow } = this.getRef<HTMLIFrameElement>();
        if (!contentWindow) {
          throw new MonoCloudJsError('Iframe contentWindow is unavailable');
        }
        return contentWindow;
      }

      case 'popup':
        return this.getRef();
    }
  }

  close(): void {
    switch (this.mode) {
      case 'silent': {
        const iframe = this.getRef<HTMLIFrameElement>();
        if (iframe.isConnected) {
          iframe.remove();
        }
        break;
      }

      case 'popup': {
        const popupRef = this.getRef<Window>();

        if (!popupRef.closed) {
          popupRef.close();
        }
        break;
      }
    }
  }
}
