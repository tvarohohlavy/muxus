import type { AuthPromptInfo, AuthPromptResponse, LoginSequence } from '@muxus/shared';
import type {
  TerminalClientMessage,
  TerminalServerMessage,
} from '@muxus/shared/ws-protocol';
import {
  CredentialVaultCorruptError,
  InvalidMasterPasswordError,
  InvalidMasterPasswordFormatError,
  VaultUnlockRequiredError,
  type PasswordVault,
} from '../security/password-vault.js';
import { typeSecretValue, typeVaultSecret } from '../security/vault-secret-input.js';
import { SecretProviderError } from '../secret-providers/provider.js';
import type { TerminalInputWriter } from '../ws/terminal-inputs.js';
import {
  LoginSequenceRunner,
  type LoginSequenceProgress,
  type SecretStepResult,
} from './runner.js';

const MASTER_PASSWORD_ATTEMPTS = 3;

export interface LoginSequenceSessionOptions {
  sequence: LoginSequence;
  vault: PasswordVault;
  /** Types into the session's transport directly, never through session logging. */
  write: TerminalInputWriter;
  recorder: { input(data: Buffer): void; system(message: string): void };
  send(message: TerminalServerMessage): void;
  log?: { warn(details: object, message: string): void };
}

/**
 * A login sequence attached to one terminal session: it reports progress to
 * the tab, takes the tab's cancel, and asks for the vault's master password
 * over the session's own prompt round-trip when a step needs a locked vault.
 * When a password manager cannot provide a secret, it asks the user to type
 * it instead. Plain text it sends counts as typed input; a secret goes
 * straight to the transport, so session history and log files only ever hold
 * what the remote side echoes back.
 */
export class LoginSequenceSession {
  private readonly runner: LoginSequenceRunner;
  private answer: ((response: AuthPromptResponse | undefined) => void) | undefined;
  private started = false;

  constructor(private readonly options: LoginSequenceSessionOptions) {
    this.runner = new LoginSequenceRunner(
      options.sequence.steps,
      {
        write: options.write,
        typed: (data) => options.recorder.input(data),
        typeSecret: (secretId, enter, signal) => this.typeSecret(secretId, enter, signal),
        progress: (update) => this.report(update),
      },
      {
        secretName: (secretId) => this.secretName(secretId),
        secretProvider: (secretId) => options.vault.externalSecret(secretId)?.providerLabel,
      },
    );
  }

  output(data: Uint8Array): void {
    this.runner.output(data);
  }

  /** Run the steps; output received since the session attached already counts. */
  start(): void {
    if (this.started) return;
    this.started = true;
    void this.runner.run().catch((err: unknown) => {
      this.options.log?.warn({ err }, 'login sequence failed');
    });
  }

  close(): void {
    this.runner.close();
    this.answer?.(undefined);
  }

  /** Frames meant for the sequence: a cancel, or the answer to its master-password prompt. */
  handleControl(message: TerminalClientMessage): boolean {
    if (message.op === 'cancel-login-sequence') {
      this.runner.cancel();
      return true;
    }
    if (message.op === 'auth-response' && this.answer) {
      this.answer({ answers: message.answers, skipped: message.skipped });
      return true;
    }
    return false;
  }

  private report(update: LoginSequenceProgress): void {
    this.options.send({ op: 'login-sequence', ...update });
    if (update.state === 'failed') {
      this.options.recorder.system(`Login sequence stopped: ${update.message ?? 'a step failed.'}`);
    } else if (update.state === 'cancelled') {
      this.options.recorder.system(`Login sequence cancelled at step ${update.step} of ${update.steps}.`);
    }
  }

  private secretName(secretId: string): string | undefined {
    return this.options.vault.secrets().find((secret) => secret.id === secretId)?.name;
  }

  private async typeSecret(
    secretId: string,
    enter: boolean,
    signal: AbortSignal,
  ): Promise<SecretStepResult> {
    let masterPassword: string | undefined;
    let error: string | undefined;
    for (let attempt = 0; ; attempt++) {
      try {
        const typed = await typeVaultSecret(this.options.vault, secretId, [this.options.write], {
          enter,
          masterPassword,
          signal,
          ask: async (prompt) => (await this.prompt(prompt, signal)) ?? { answers: [], skipped: true },
        });
        if (typed === undefined) return 'its secret is no longer in the password vault.';
        return typed > 0 ? undefined : 'the session no longer takes input.';
      } catch (err) {
        if (err instanceof SecretProviderError) {
          if (signal.aborted) return undefined;
          return this.typeByHand(secretId, enter, err.message, signal);
        }
        if (err instanceof CredentialVaultCorruptError) return 'its secret could not be decrypted.';
        if (err instanceof InvalidMasterPasswordError || err instanceof InvalidMasterPasswordFormatError) {
          error = err.message;
        } else if (!(err instanceof VaultUnlockRequiredError)) {
          throw err;
        }
      }
      if (attempt >= MASTER_PASSWORD_ATTEMPTS) return 'the password vault stayed locked.';
      masterPassword = await this.askMasterPassword(secretId, error, signal);
      if (signal.aborted) return undefined;
      if (masterPassword === undefined) return 'the password vault stayed locked.';
    }
  }

  /**
   * The password manager could not provide the secret (it is missing,
   * locked, or access was not approved): say why and let the user type it
   * instead. The answer goes straight to the session like the secret would
   * have, and is never saved.
   */
  private async typeByHand(
    secretId: string,
    enter: boolean,
    reason: string,
    signal: AbortSignal,
  ): Promise<SecretStepResult> {
    const name = this.secretName(secretId) ?? 'the secret';
    const providerLabel = this.options.vault.externalSecret(secretId)?.providerLabel ?? 'The password manager';
    const value = await this.ask(
      {
        name: `${providerLabel} is unavailable`,
        purpose: 'authentication',
        instructions: `${reason}\n\nType “${name}” to let the login sequence carry on. It is typed into the session and not saved.`,
        prompts: [{ prompt: name, echo: false }],
        skipLabel: 'Stop login sequence',
      },
      signal,
    );
    if (signal.aborted) return undefined;
    if (value === undefined) return `${providerLabel} could not provide “${name}”. ${reason}`;
    return typeSecretValue(value, [this.options.write], enter) > 0
      ? undefined
      : 'the session no longer takes input.';
  }

  private askMasterPassword(
    secretId: string,
    error: string | undefined,
    signal: AbortSignal,
  ): Promise<string | undefined> {
    const name = this.secretName(secretId) ?? 'a saved secret';
    const instructions = `The login sequence is about to type “${name}”. Enter the master password to use it.`;
    return this.ask(
      {
        name: 'Unlock password vault',
        purpose: 'vault-unlock',
        instructions: error ? `${error}\n\n${instructions}` : instructions,
        prompts: [{ prompt: 'Master password', echo: false }],
        skipLabel: 'Stop login sequence',
      },
      signal,
    );
  }

  /** One answer over the session's own prompt round-trip; undefined when skipped or stopped. */
  private async ask(prompt: AuthPromptInfo, signal: AbortSignal): Promise<string | undefined> {
    const response = await this.prompt(prompt, signal);
    return response && !response.skipped ? (response.answers[0] ?? '') : undefined;
  }

  /** A prompt over the session's own round-trip; undefined when the sequence stops first. */
  private prompt(prompt: AuthPromptInfo, signal: AbortSignal): Promise<AuthPromptResponse | undefined> {
    if (signal.aborted) return Promise.resolve(undefined);
    return new Promise((resolve) => {
      const done = (response: AuthPromptResponse | undefined) => {
        signal.removeEventListener('abort', onAbort);
        this.answer = undefined;
        resolve(response);
      };
      const onAbort = () => done(undefined);
      signal.addEventListener('abort', onAbort, { once: true });
      this.answer = done;
      this.options.send({ op: 'auth-prompt', ...prompt });
    });
  }
}
