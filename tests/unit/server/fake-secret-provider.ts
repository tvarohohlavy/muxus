import type { SecretProviderDescriptor, SecretProviderStatus } from '@muxus/shared';
import {
  SecretProviderError,
  type SecretProvider,
  type SecretReadContext,
  type SecretReadRequest,
} from '../../../server/src/secret-providers/provider.js';

export const FAKE_PROVIDER_DESCRIPTOR: SecretProviderDescriptor = {
  id: 'fakevault',
  label: 'FakeVault',
  description: 'A password manager for tests.',
  locator: { label: 'Item path', placeholder: 'fake://folder/item' },
  options: [{ key: 'account', label: 'Account' }],
  settings: [{ key: 'cliPath', label: 'CLI location' }],
};

/**
 * A password manager stand-in: values by locator, or one failure for all of
 * them. It records each read, and can hold reads back or ask for a
 * passphrase first, the way a real manager might.
 */
export class FakeSecretProvider implements SecretProvider {
  readonly descriptor: SecretProviderDescriptor;
  readonly reads: Array<{
    locator: string;
    options: Readonly<Record<string, string>>;
    settings: Readonly<Record<string, string>>;
  }> = [];
  failure: SecretProviderError | undefined;
  /** Each read waits for this before it answers. */
  gate: Promise<void> | undefined;
  /** Each read asks for this passphrase first and fails as locked without it. */
  passphrase: string | undefined;

  constructor(
    public fields: Record<string, string> = {},
    options: { failure?: SecretProviderError; descriptor?: Partial<SecretProviderDescriptor> } = {},
  ) {
    this.failure = options.failure;
    this.descriptor = { ...FAKE_PROVIDER_DESCRIPTOR, ...options.descriptor };
  }

  locatorProblem(locator: string): string | undefined {
    return locator.startsWith('fake://') ? undefined : 'An item path starts with fake://.';
  }

  settingProblem(key: string, value: string): string | undefined {
    return key === 'cliPath' && !value.startsWith('/') ? 'Enter the full path to the CLI.' : undefined;
  }

  async status({
    settings,
  }: {
    settings: Readonly<Record<string, string>>;
  }): Promise<SecretProviderStatus> {
    return {
      available: !this.failure,
      summary: this.failure?.message ?? `${this.descriptor.label} is ready.`,
      ...(settings.cliPath ? {} : { detected: { cliPath: '/usr/bin/fakevault' } }),
    };
  }

  async read(request: SecretReadRequest, context: SecretReadContext): Promise<string> {
    this.reads.push({ locator: request.locator, options: request.options, settings: context.settings });
    const { signal } = context;
    if (signal?.aborted) throw cancelled();
    if (this.gate) {
      // Like a real manager, a read that is told to stop stops waiting at once.
      const gate = this.gate;
      await new Promise<void>((resolve, reject) => {
        const onAbort = () => reject(cancelled());
        signal?.addEventListener('abort', onAbort, { once: true });
        gate.then(resolve, reject).finally(() => signal?.removeEventListener('abort', onAbort));
      });
    }
    if (this.failure) throw this.failure;
    if (this.passphrase !== undefined) {
      const response = await context.ask?.({
        name: `Unlock ${this.descriptor.label}`,
        prompts: [{ prompt: 'Passphrase', echo: false }],
      });
      if (response?.answers[0] !== this.passphrase) {
        throw new SecretProviderError('locked', `${this.descriptor.label} stayed locked.`);
      }
    }
    const value = this.fields[request.locator];
    if (value === undefined) {
      throw new SecretProviderError('not-found', `${this.descriptor.label} has nothing at that path.`);
    }
    return value;
  }
}

function cancelled(): SecretProviderError {
  return new SecretProviderError('cancelled', 'Cancelled.');
}
