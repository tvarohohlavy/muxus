import {
  EXTERNAL_SECRET_LOCATOR_MAX_LENGTH,
  EXTERNAL_SECRET_OPTION_MAX_LENGTH,
  SECRET_PROVIDER_SETTING_MAX_LENGTH,
  type AuthPromptInfo,
  type AuthPromptResponse,
  type SecretProviderInfo,
  type SecretProviderStatus,
} from '@muxus/shared';
import { assertSecretFree, type MuxusDatabase } from '../persistence/database.js';
import { SecretProviderError, type SecretProvider } from './provider.js';

/** Longest value Muxus takes from a provider, as for a secret saved in the vault. */
export const EXTERNAL_SECRET_VALUE_MAX_BYTES = 8192;

const PROVIDER_ID = /^[a-z0-9][a-z0-9-]{0,63}$/;

/** A locator, option or setting a provider cannot use; the message is for the user. */
export class SecretProviderInputError extends Error {}

/** No provider with that ID in this build of Muxus. */
export class UnknownSecretProviderError extends SecretProviderInputError {
  constructor(readonly id: string) {
    super(`This version of Muxus has no secret provider “${id}”.`);
  }
}

/**
 * The secret providers this build offers, with their settings. Checks every
 * locator, option and setting before it is stored or used, and runs reads
 * for each provider one at a time.
 */
export class SecretProviders {
  private readonly byId = new Map<string, SecretProvider>();
  private readonly queues = new Map<string, Promise<void>>();

  constructor(
    private readonly database: MuxusDatabase,
    providers: readonly SecretProvider[] = [],
  ) {
    for (const provider of providers) {
      const { id, options, settings } = provider.descriptor;
      if (!PROVIDER_ID.test(id)) throw new Error(`Invalid secret provider ID: ${id}`);
      if (this.byId.has(id)) throw new Error(`Duplicate secret provider: ${id}`);
      // Field keys become stored keys: none may look like a place for a secret.
      assertSecretFree(
        Object.fromEntries([...options, ...settings].map((field) => [field.key, ''])),
        `secretProvider.${id}`,
      );
      this.byId.set(id, provider);
    }
  }

  get(id: string): SecretProvider | undefined {
    return this.byId.get(id);
  }

  /** The provider's name for messages; its ID when this build does not have it. */
  label(id: string): string {
    return this.byId.get(id)?.descriptor.label ?? id;
  }

  /** Every provider with its settings and whether it can be used now. */
  list(refresh = false): Promise<SecretProviderInfo[]> {
    return Promise.all([...this.byId.values()].map((provider) => this.info(provider, refresh)));
  }

  /** The provider's saved settings, limited to the keys it declares. */
  settings(id: string): Record<string, string> {
    const provider = this.byId.get(id);
    if (!provider) return {};
    const saved = this.database.secretProviderSettings(id);
    return Object.fromEntries(
      provider.descriptor.settings.flatMap((field) => {
        const value = saved[field.key];
        return value ? [[field.key, value]] : [];
      }),
    );
  }

  /** Change some settings; an empty or null value unsets one. Answers with the new status. */
  async saveSettings(id: string, input: Record<string, string | null>): Promise<SecretProviderInfo> {
    const provider = this.require(id);
    const next = this.settings(id);
    for (const [key, raw] of Object.entries(input)) {
      if (!provider.descriptor.settings.some((field) => field.key === key)) {
        throw new SecretProviderInputError(`${provider.descriptor.label} has no setting “${key}”.`);
      }
      const value = raw?.trim() ?? '';
      if (!value) {
        delete next[key];
        continue;
      }
      const problem =
        textProblem(value, SECRET_PROVIDER_SETTING_MAX_LENGTH) ?? provider.settingProblem?.(key, value);
      if (problem) throw new SecretProviderInputError(problem);
      next[key] = value;
    }
    this.database.setSecretProviderSettings(id, next);
    return this.info(provider, true);
  }

  /** A secret's locator and options, trimmed and checked, ready to store. */
  checkSecret(
    id: string,
    locator: string,
    options: Record<string, string> = {},
  ): { locator: string; options: Record<string, string> } {
    const provider = this.require(id);
    const { descriptor } = provider;
    const trimmed = locator.trim();
    if (!trimmed) {
      throw new SecretProviderInputError(`Enter the ${descriptor.locator.label.toLocaleLowerCase()}.`);
    }
    const problem =
      textProblem(trimmed, EXTERNAL_SECRET_LOCATOR_MAX_LENGTH) ?? provider.locatorProblem(trimmed);
    if (problem) throw new SecretProviderInputError(problem);
    const checked: Record<string, string> = {};
    for (const [key, raw] of Object.entries(options)) {
      if (!descriptor.options.some((field) => field.key === key)) {
        throw new SecretProviderInputError(`${descriptor.label} has no option “${key}”.`);
      }
      const value = raw.trim();
      if (!value) continue;
      const optionProblem =
        textProblem(value, EXTERNAL_SECRET_OPTION_MAX_LENGTH) ?? provider.optionProblem?.(key, value);
      if (optionProblem) throw new SecretProviderInputError(optionProblem);
      checked[key] = value;
    }
    return { locator: trimmed, options: checked };
  }

  /**
   * Ask a provider for a value. Rejects with a SecretProviderError that says,
   * in words for the user, why there is none. A caller that gives up while an
   * earlier read waits (say, on the manager's approval prompt) stops waiting
   * at once; its own read then sees the abort and never runs.
   */
  read(
    id: string,
    request: { locator: string; options?: Record<string, string> },
    context: {
      signal?: AbortSignal;
      ask?: (prompt: AuthPromptInfo) => Promise<AuthPromptResponse>;
    } = {},
  ): Promise<string> {
    const provider = this.byId.get(id);
    if (!provider) {
      return Promise.reject(
        new SecretProviderError('not-installed', `This version of Muxus cannot read secrets from ${id}.`),
      );
    }
    let checked: { locator: string; options: Record<string, string> };
    try {
      checked = this.checkSecret(id, request.locator, request.options);
    } catch (err) {
      return Promise.reject(new SecretProviderError('failed', (err as Error).message));
    }
    const queued = (this.queues.get(id) ?? Promise.resolve()).then(() =>
      this.readNow(provider, checked, context),
    );
    this.queues.set(
      id,
      queued.then(
        () => undefined,
        () => undefined,
      ),
    );
    const { signal } = context;
    if (!signal) return queued;
    return new Promise<string>((resolve, reject) => {
      const onAbort = () => reject(cancelled());
      if (signal.aborted) {
        onAbort();
        return;
      }
      signal.addEventListener('abort', onAbort, { once: true });
      queued.then(resolve, reject).finally(() => signal.removeEventListener('abort', onAbort));
    });
  }

  private async readNow(
    provider: SecretProvider,
    request: { locator: string; options: Record<string, string> },
    context: {
      signal?: AbortSignal;
      ask?: (prompt: AuthPromptInfo) => Promise<AuthPromptResponse>;
    },
  ): Promise<string> {
    const { label, id } = provider.descriptor;
    if (context.signal?.aborted) throw cancelled();
    let value: string;
    try {
      value = await provider.read(request, {
        settings: this.settings(id),
        ...(context.signal ? { signal: context.signal } : {}),
        ...(context.ask ? { ask: context.ask } : {}),
      });
    } catch (err) {
      if (err instanceof SecretProviderError) throw err;
      if (context.signal?.aborted) throw cancelled();
      throw new SecretProviderError('failed', `${label} could not provide the secret.`);
    }
    if (typeof value !== 'string' || value.length === 0) {
      throw new SecretProviderError('failed', `${label} gave an empty value.`);
    }
    if (Buffer.byteLength(value, 'utf8') > EXTERNAL_SECRET_VALUE_MAX_BYTES) {
      throw new SecretProviderError('failed', `The value from ${label} is too long to type.`);
    }
    return value;
  }

  private async info(provider: SecretProvider, refresh: boolean): Promise<SecretProviderInfo> {
    const settings = this.settings(provider.descriptor.id);
    let status: SecretProviderStatus;
    try {
      status = await provider.status({ settings, refresh });
    } catch (err) {
      status = {
        available: false,
        summary:
          err instanceof SecretProviderError
            ? err.message
            : `Muxus could not check ${provider.descriptor.label}.`,
      };
    }
    return { descriptor: provider.descriptor, settings, status };
  }

  private require(id: string): SecretProvider {
    const provider = this.byId.get(id);
    if (!provider) throw new UnknownSecretProviderError(id);
    return provider;
  }
}

function cancelled(): SecretProviderError {
  return new SecretProviderError('cancelled', 'Cancelled.');
}

/** Stored text must fit and hold no control characters; those never belong in a path or a reference. */
function textProblem(value: string, maxLength: number): string | undefined {
  if (Array.from(value).length > maxLength) return 'That is too long.';
  if (/\p{Cc}/u.test(value)) return 'That contains characters Muxus cannot use.';
  return undefined;
}
