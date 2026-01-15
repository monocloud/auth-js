export class MockStorage {
  protected store: Record<string, string> = {};

  constructor(init?: Record<string, string>) {
    if (init) {
      this.store = init;
    }
  }

  getItem(key: string): Promise<string | null> {
    return Promise.resolve(this.store[key] ?? null);
  }

  removeItem(key: string): Promise<void> {
    // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
    delete this.store[key];
    return Promise.resolve();
  }

  setItem(key: string, value: string): Promise<void> {
    this.store[key] = value;
    return Promise.resolve();
  }

  clear(): void {
    this.store = {};
  }
}
