import type {
  AuthPromptInfo,
  AuthPromptResponse,
  SecretProviderDescriptor,
  SecretProviderStatus,
} from '@muxus/shared';

/**
 * Why a provider could not give a value. Muxus treats them all the same way
 * (it falls back to asking the user); the kind is for logs, tests and
 * clients that want to word things differently.
 */
export type SecretProviderProblem =
  /** The provider, or the tool it runs, is not there. */
  | 'not-installed'
  /** Its app or service did not answer. */
  | 'unreachable'
  /** It needs the user to sign in or unlock it first. */
  | 'locked'
  /** The user, or the manager, refused access. */
  | 'denied'
  /** Nothing is stored at that locator. */
  | 'not-found'
  | 'timeout'
  | 'cancelled'
  | 'failed';

/** A failed read, with a message written for the user. */
export class SecretProviderError extends Error {
  constructor(
    readonly problem: SecretProviderProblem,
    message: string,
  ) {
    super(message);
    this.name = 'SecretProviderError';
  }
}

/** What to read: a secret's locator and its options, already checked by the provider. */
export interface SecretReadRequest {
  locator: string;
  options: Readonly<Record<string, string>>;
}

export interface SecretReadContext {
  /** The provider's saved settings; a missing key is unset. */
  settings: Readonly<Record<string, string>>;
  signal?: AbortSignal;
  /**
   * Ask the user something in the session that needs the value, such as a
   * passphrase the manager wants first. Absent where nobody can answer. The
   * answers are not saved.
   */
  ask?: (prompt: AuthPromptInfo) => Promise<AuthPromptResponse>;
}

/**
 * A password manager Muxus asks for a value each time it needs one. Muxus
 * stores only the locator, never the value, and asks again on every use.
 *
 * Reads for one provider run one at a time, so a single approval prompt in
 * the manager can cover a burst of sessions opening together.
 */
export interface SecretProvider {
  readonly descriptor: SecretProviderDescriptor;
  /** Why the locator cannot be used, in words for the user; undefined when it can. */
  locatorProblem(locator: string): string | undefined;
  /** The same for one per-secret option (a key from `descriptor.options`). */
  optionProblem?(key: string, value: string): string | undefined;
  /** The same for one setting (a key from `descriptor.settings`). */
  settingProblem?(key: string, value: string): string | undefined;
  /** Whether the provider can be used now; `refresh` skips any cached answer. */
  status(context: {
    settings: Readonly<Record<string, string>>;
    refresh: boolean;
  }): Promise<SecretProviderStatus>;
  /** The value. Rejects with a SecretProviderError that says why there is none. */
  read(request: SecretReadRequest, context: SecretReadContext): Promise<string>;
}
