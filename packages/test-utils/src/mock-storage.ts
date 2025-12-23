export class MockStorage {
  private store: Record<string, string> = {};

  constructor(init?: Record<string, string>) {
    if (init) {
      this.store = init;
    }
  }

  getItem(key: string): string | null {
    return this.store[key] ?? null;
  }

  removeItem(key: string): void {
    // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
    delete this.store[key];
  }

  setItem(key: string, value: string): void {
    this.store[key] = value;
  }

  clear(): void {
    this.store = {};
  }
}
