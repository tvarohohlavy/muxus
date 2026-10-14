import type { AuthPromptResponse } from '@muxus/shared';
import { SecretProviderError, type SecretProviderProblem } from '../secret-providers/provider.js';
import type { PasswordVault } from './password-vault.js';

/** How long a value read early waits to be used, once the session is connected. */
export const EARLY_READ_KEEP_MS = 60_000;

/** The answer an early read gets when its provider asks the user something. */
const NOBODY_TO_ASK: AuthPromptResponse = { answers: [], skipped: true };

/** Failures that may be gone by the time the value is needed: the manager was busy, closed or locked. */
const PASSING_PROBLEMS: ReadonlySet<SecretProviderProblem> = new Set(['timeout', 'unreachable', 'locked']);

/** An early read not made: the secret moved while the read waited its turn. */
class SecretMoved extends Error {}

interface EarlyRead {
  readonly value: Promise<string | undefined>;
  /** Where the manager kept the secret when the read started. */
  readonly location: string;
  /** Whether the provider wanted to ask the user something. */
  readonly asked: () => boolean;
  settled: boolean;
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
 * within a minute of the session connecting or of the read finishing,
 * whichever is later. Vault secrets are not read early: they decrypt at
 * once and may need the master password.
 *
 * A session reads one secret at a time from each manager, so when several
 * sessions open together, every session's first secret from a manager
 * (usually its login password) is read before any session's second.
 *
 * An early read is not used, and the secret is read again when needed,
 * when the provider wanted to ask the user something (nobody could answer
 * yet, so the question should appear where the value is needed), when the
 * secret was deleted or pointed elsewhere since, or when the read failed
 * for a reason that may have passed (the manager was busy, closed or
 * locked) before anyone needed it.
 */
export class EarlySecretReads {
  private readonly reads = new Map<string, EarlyRead[]>();
  /** Per provider, this session's newest read: the next one starts after it. */
  private readonly tails = new Map<string, Promise<unknown>>();
  private readonly controller = new AbortController();
  private readonly keepMs: number;
  private isConnected = false;

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
      const external = this.vault.externalSecret(id);
      if (!external) continue;
      let asked = false;
      const value = (this.tails.get(external.provider) ?? Promise.resolve()).then(() => {
        // The vault looks the secret up again, in this same turn, to read it.
        if (this.vault.externalSecret(id)?.location !== external.location) throw new SecretMoved();
        return this.vault.secretValue(id, undefined, {
          signal: this.controller.signal,
          ask: async () => {
            asked = true;
            return NOBODY_TO_ASK;
          },
        });
      });
      this.tails.set(external.provider, value.then(ignore, ignore));
      const read: EarlyRead = { value, location: external.location, asked: () => asked, settled: false };
      const queue = this.reads.get(id);
      if (queue) queue.push(read);
      else this.reads.set(id, [read]);
      // A failure is reported by the step that takes the read.
      const settle = () => {
        read.settled = true;
        this.keep(id, read);
      };
      void value.then(settle, settle);
    }
  }

  /** The session is connected: from now, a value nobody takes within the time is dropped. */
  connected(): void {
    this.isConnected = true;
    for (const [id, queue] of this.reads) {
      for (const read of queue) if (read.settled) this.keep(id, read);
    }
  }

  /**
   * A secret's value for one use: the oldest early read of it that can
   * still be used, or `readNow` when there is none, or when the early read
   * cannot stand (see the class comment). `signal` stops waiting for an
   * early read, as for any read.
   */
  async read(
    secretId: string,
    readNow: () => Promise<string | undefined>,
    signal?: AbortSignal,
  ): Promise<string | undefined> {
    for (;;) {
      const early = this.take(secretId);
      if (!early) return readNow();
      // Deleted, or pointed at another item, since the read started.
      if (this.vault.externalSecret(secretId)?.location !== early.location) continue;
      const settledBeforeUse = early.settled;
      let value: string | undefined;
      try {
        value = await abortable(early.value, signal);
      } catch (err) {
        if (err instanceof SecretMoved) {
          if (this.stopped(signal)) throw cancelled();
          continue;
        }
        if (this.stopped(signal)) throw err;
        if (early.asked()) return readNow();
        // Another early read of this secret may have got the value.
        if (this.reads.has(secretId)) continue;
        const passed =
          settledBeforeUse && err instanceof SecretProviderError && PASSING_PROBLEMS.has(err.problem);
        if (passed) return readNow();
        throw err;
      }
      if (!early.asked()) return value;
      if (this.stopped(signal)) throw cancelled();
      return readNow();
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

  private stopped(signal: AbortSignal | undefined): boolean {
    return signal?.aborted === true || this.controller.signal.aborted;
  }

  private keep(secretId: string, read: EarlyRead): void {
    if (!this.isConnected || read.expiry || !this.reads.get(secretId)?.includes(read)) return;
    read.expiry = setTimeout(() => this.remove(secretId, read), this.keepMs);
    read.expiry.unref();
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

function ignore(): void {}

function cancelled(): SecretProviderError {
  return new SecretProviderError('cancelled', 'Cancelled.');
}

/** The promise's outcome, unless the signal fires first. */
function abortable<T>(promise: Promise<T>, signal: AbortSignal | undefined): Promise<T> {
  if (!signal) return promise;
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(cancelled());
    if (signal.aborted) {
      onAbort();
      return;
    }
    signal.addEventListener('abort', onAbort, { once: true });
    promise.then(resolve, reject).finally(() => signal.removeEventListener('abort', onAbort));
  });
}
