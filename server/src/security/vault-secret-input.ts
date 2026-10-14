import type { AuthPromptInfo, AuthPromptResponse } from '@muxus/shared';
import type { TerminalInputWriter } from '../ws/terminal-inputs.js';
import type { EarlySecretReads } from './early-secret-reads.js';
import type { PasswordVault } from './password-vault.js';

/** A secret as keystrokes: its text, then Enter (a carriage return, as the key sends) when asked. */
export function secretKeystrokes(value: string, enter: boolean): Buffer {
  return Buffer.from(enter ? `${value}\r` : value, 'utf8');
}

/**
 * Type a named secret into terminal sessions as if it were typed. The value
 * goes from the vault (or the password manager holding it) straight to each
 * writer; it is never returned, logged or given to a session recorder, so
 * only what the remote side echoes can reach session history or a log file.
 * The vault's own errors (locked, wrong master password) and the manager's
 * pass through so callers can ask for the master password and try again, or
 * explain.
 *
 * A password manager's value read early for this use is taken from
 * `earlySecrets` instead of being read again.
 *
 * Resolves to the number of sessions that took the secret, or undefined when
 * the secret is no longer in the vault.
 */
export async function typeVaultSecret(
  vault: PasswordVault,
  secretId: string,
  writers: readonly TerminalInputWriter[],
  options: {
    enter: boolean;
    masterPassword?: string;
    signal?: AbortSignal;
    ask?: (prompt: AuthPromptInfo) => Promise<AuthPromptResponse>;
    earlySecrets?: EarlySecretReads;
  },
): Promise<number | undefined> {
  const readNow = () =>
    vault.secretValue(secretId, options.masterPassword, {
      signal: options.signal,
      ask: options.ask,
    });
  const value = await (options.earlySecrets
    ? options.earlySecrets.read(secretId, readNow, options.signal)
    : readNow());
  if (value === undefined) return undefined;
  return typeSecretValue(value, writers, options.enter);
}

/** Type a value straight into sessions, past every recorder; resolves to how many took it. */
export function typeSecretValue(
  value: string,
  writers: readonly TerminalInputWriter[],
  enter: boolean,
): number {
  let typed = 0;
  for (const write of writers) {
    if (write(secretKeystrokes(value, enter))) typed++;
  }
  return typed;
}
