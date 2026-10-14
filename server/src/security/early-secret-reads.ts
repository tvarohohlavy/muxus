import type { AuthPromptResponse } from '@muxus/shared';
import { SecretProviderError } from '../secret-providers/provider.js';
import type { PasswordVault } from './password-vault.js';

/** How long a value read early waits to be used before it is dropped. */
export const EARLY_READ_KEEP_MS = 60_000;

/** The answer an early read gets when its provider asks the user something. */
const NOBODY_TO_ASK: AuthPromptResponse = { answers: [], skipped: true };

interface EarlyRead {
  readonly value: Promise<string | undefined>;
  /** Whether the provider wanted to ask the user something. */
  readonly asked: () => boolean;
  expiry?: NodeJS.Timeout;
}

/**
 * Password-manager reads started before they are needed, for one terminal
 * session. A manager can take a second or more per read (the 1Password CLI
 * does on Windows); reading a login's secrets as the session starts lets
 * that wait overlap the connection instead of following it.
 *
 * Each read started serves one use. A value stays only in memory and is
 * dropped once used, when the reads are closed, or when nobody took it
 * within a minute. Vault secrets are not read early: they decrypt at once
 * and may need the master password. An early read cannot ask the user
 * anything; when the provider wanted to, the read is made again when the
 * value is needed, so the question appears there.
 */
export class EarlySecretReads {
  private readonly reads = new Map<string, EarlyRead[]>();
  private readonly controller = new AbortController();
  private readonly keepMs: number;

  constructor(
    private readonly vault: Pick<PasswordVault, 'externalSecret' | 'secretValue'>,
    options: {
      /** Ends every read, as `close` does; the session's own end. */
      signal?: AbortSignal;
      keepMs?: number;
    } = {},
  ) {
    this.keepMs = options.keepMs ?? EARLY_READ_KEEP_MS;
    const { signal } = options;
    if (signal?.aborted) this.close();
    else signal?.addEventListener('abort', () => this.close(), { once: true });
  }

  /** Start reading these secrets, in order. Vault secrets and missing ones are skipped. */
  start(secretIds: Iterable<string>): void {
    for (const id of secretIds) {
      if (this.controller.signal.aborted) return;
      if (!this.vault.externalSecret(id)) continue;
      let asked = false;
      const read: EarlyRead = {
        value: this.vault.secretValue(id, undefined, {
          signal: this.controller.signal,
          ask: async () => {
            asked = true;
            return NOBODY_TO_ASK;
          },
        }),
        asked: () => asked,
      };
      const queue = this.reads.get(id);
      if (queue) queue.push(read);
      else this.reads.set(id, [read]);
      // A failure is reported by the step that takes the read.
      const keep = () => {
        if (!this.reads.get(id)?.includes(read)) return;
        read.expiry = setTimeout(() => this.remove(id, read), this.keepMs);
        read.expiry.unref();
      };
      void read.value.then(keep, keep);
    }
  }

  /**
   * A secret's value for one use: the oldest early read of it, or `readNow`
   * when there is none, or when the early read wanted to ask the user
   * something. `signal` stops waiting for an early read, as for any read.
   */
  async read(
    secretId: string,
    readNow: () => Promise<string | undefined>,
    signal?: AbortSignal,
  ): Promise<string | undefined> {
    const early = this.take(secretId);
    if (!early) return readNow();
    try {
      return await abortable(early.value, signal);
    } catch (err) {
      if (early.asked() && !signal?.aborted && !this.controller.signal.aborted) return readNow();
      throw err;
    }
  }

  /** Cancel the reads still running and drop every value not used yet. */
  close(): void {
    this.controller.abort();
    for (const queue of this.reads.values()) {
      for (const read of queue) clearTimeout(read.expiry);
    }
    this.reads.clear();
  }

  private take(secretId: string): EarlyRead | undefined {
    const queue = this.reads.get(secretId);
    const read = queue?.shift();
    if (queue?.length === 0) this.reads.delete(secretId);
    clearTimeout(read?.expiry);
    return read;
  }

  private remove(secretId: string, read: EarlyRead): void {
    const queue = this.reads.get(secretId);
    const index = queue?.indexOf(read) ?? -1;
    if (index < 0) return;
    queue!.splice(index, 1);
    if (queue!.length === 0) this.reads.delete(secretId);
    clearTimeout(read.expiry);
  }
}

/** The promise's outcome, unless the signal fires first. */
function abortable<T>(promise: Promise<T>, signal: AbortSignal | undefined): Promise<T> {
  if (!signal) return promise;
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(new SecretProviderError('cancelled', 'Cancelled.'));
    if (signal.aborted) {
      onAbort();
      return;
    }
    signal.addEventListener('abort', onAbort, { once: true });
    promise.then(resolve, reject).finally(() => signal.removeEventListener('abort', onAbort));
  });
}
