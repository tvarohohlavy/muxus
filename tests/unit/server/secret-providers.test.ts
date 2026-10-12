import { afterEach, describe, expect, it } from 'vitest';
import { MuxusDatabase } from '../../../server/src/persistence/database.js';
import { SecretProviderError } from '../../../server/src/secret-providers/provider.js';
import {
  EXTERNAL_SECRET_VALUE_MAX_BYTES,
  SecretProviderInputError,
  SecretProviders,
} from '../../../server/src/secret-providers/registry.js';
import { FakeSecretProvider } from './fake-secret-provider.js';

const LOCATOR = 'fake://network/core-sw1';

const databases: MuxusDatabase[] = [];
afterEach(() => {
  for (const database of databases.splice(0)) database.close();
});

function registry(...providers: FakeSecretProvider[]): SecretProviders {
  const database = new MuxusDatabase(':memory:');
  databases.push(database);
  return new SecretProviders(database, providers);
}

describe('SecretProviders', () => {
  it('refuses providers it could not store safely', () => {
    expect(() => registry(new FakeSecretProvider({}, { descriptor: { id: 'Bad ID' } }))).toThrow(
      'Invalid secret provider ID',
    );
    expect(() => registry(new FakeSecretProvider(), new FakeSecretProvider())).toThrow(
      'Duplicate secret provider',
    );
    // A field named like a secret would put one in the database.
    expect(() =>
      registry(
        new FakeSecretProvider({}, { descriptor: { settings: [{ key: 'apiToken', label: 'Token' }] } }),
      ),
    ).toThrow('must not be stored');
  });

  it('checks a locator and its options before they are stored', () => {
    const providers = registry(new FakeSecretProvider());
    expect(providers.checkSecret('fakevault', `  ${LOCATOR}  `, { account: ' work ' })).toEqual({
      locator: LOCATOR,
      options: { account: 'work' },
    });
    // Empty options are dropped, as if not given.
    expect(providers.checkSecret('fakevault', LOCATOR, { account: '  ' })).toEqual({
      locator: LOCATOR,
      options: {},
    });
    expect(() => providers.checkSecret('fakevault', '   ')).toThrow('Enter the item path.');
    expect(() => providers.checkSecret('fakevault', 'op://elsewhere')).toThrow(
      'An item path starts with fake://.',
    );
    expect(() => providers.checkSecret('fakevault', `${LOCATOR}\n`.repeat(2))).toThrow(
      SecretProviderInputError,
    );
    expect(() => providers.checkSecret('fakevault', `fake://${'x'.repeat(1100)}`)).toThrow('too long');
    expect(() => providers.checkSecret('fakevault', LOCATOR, { vault: 'x' })).toThrow(
      'FakeVault has no option “vault”.',
    );
    expect(() => providers.checkSecret('elsewhere', LOCATOR)).toThrow(SecretProviderInputError);
  });

  it('saves settings it can check, and hands back only the declared ones', async () => {
    const provider = new FakeSecretProvider();
    const providers = registry(provider);
    await expect(providers.saveSettings('fakevault', { cliPath: 'fakevault' })).rejects.toThrow(
      'Enter the full path to the CLI.',
    );
    await expect(providers.saveSettings('fakevault', { colour: 'blue' })).rejects.toThrow(
      'FakeVault has no setting “colour”.',
    );

    const saved = await providers.saveSettings('fakevault', { cliPath: ' /opt/fakevault ' });
    expect(saved).toMatchObject({
      descriptor: { id: 'fakevault' },
      settings: { cliPath: '/opt/fakevault' },
      status: { available: true },
    });
    expect(providers.settings('fakevault')).toEqual({ cliPath: '/opt/fakevault' });

    // An empty value unsets the key; the provider then reports what it found itself.
    const cleared = await providers.saveSettings('fakevault', { cliPath: null });
    expect(cleared.settings).toEqual({});
    expect(cleared.status.detected).toEqual({ cliPath: '/usr/bin/fakevault' });
  });

  it('lists every provider with its status, even when the check fails', async () => {
    const broken = new FakeSecretProvider({}, { descriptor: { id: 'broken', label: 'Broken' } });
    broken.status = () => Promise.reject(new Error('boom'));
    const providers = registry(new FakeSecretProvider(), broken);
    const list = await providers.list();
    expect(list.map((info) => [info.descriptor.id, info.status])).toEqual([
      ['fakevault', { available: true, summary: 'FakeVault is ready.', detected: { cliPath: '/usr/bin/fakevault' } }],
      ['broken', { available: false, summary: 'Muxus could not check Broken.' }],
    ]);
    expect(providers.label('broken')).toBe('Broken');
    expect(providers.label('gone')).toBe('gone');
  });

  it('reads a value with the provider’s settings and the caller’s prompt', async () => {
    const provider = new FakeSecretProvider({ [LOCATOR]: 'Cisco-Pass-1' });
    provider.passphrase = 'open sesame';
    const providers = registry(provider);
    await providers.saveSettings('fakevault', { cliPath: '/opt/fakevault' });
    const asked: string[] = [];

    await expect(
      providers.read('fakevault', { locator: LOCATOR, options: { account: 'work' } }, {
        ask: (prompt) => {
          asked.push(prompt.name ?? '');
          return Promise.resolve({ answers: ['open sesame'] });
        },
      }),
    ).resolves.toBe('Cisco-Pass-1');
    expect(asked).toEqual(['Unlock FakeVault']);
    expect(provider.reads).toEqual([
      { locator: LOCATOR, options: { account: 'work' }, settings: { cliPath: '/opt/fakevault' } },
    ]);

    // Nobody to ask: the provider stays locked.
    await expect(providers.read('fakevault', { locator: LOCATOR })).rejects.toMatchObject({
      problem: 'locked',
    });
  });

  it('turns every failure into a SecretProviderError with words for the user', async () => {
    const provider = new FakeSecretProvider({
      'fake://empty': '',
      'fake://huge': 'x'.repeat(EXTERNAL_SECRET_VALUE_MAX_BYTES + 1),
    });
    const providers = registry(provider);

    await expect(providers.read('gone', { locator: LOCATOR })).rejects.toMatchObject({
      problem: 'not-installed',
      message: 'This version of Muxus cannot read secrets from gone.',
    });
    await expect(providers.read('fakevault', { locator: 'op://elsewhere' })).rejects.toMatchObject({
      problem: 'failed',
      message: 'An item path starts with fake://.',
    });
    await expect(providers.read('fakevault', { locator: LOCATOR })).rejects.toMatchObject({
      problem: 'not-found',
    });
    await expect(providers.read('fakevault', { locator: 'fake://empty' })).rejects.toMatchObject({
      problem: 'failed',
      message: 'FakeVault gave an empty value.',
    });
    await expect(providers.read('fakevault', { locator: 'fake://huge' })).rejects.toMatchObject({
      problem: 'failed',
      message: 'The value from FakeVault is too long to type.',
    });
    // A provider bug must not leak its internals into a message.
    provider.read = () => Promise.reject(new TypeError('cannot read properties of undefined'));
    await expect(providers.read('fakevault', { locator: LOCATOR })).rejects.toEqual(
      new SecretProviderError('failed', 'FakeVault could not provide the secret.'),
    );
  });

  it('reads one at a time per provider, so one approval covers a burst', async () => {
    const provider = new FakeSecretProvider({ [LOCATOR]: 'one', 'fake://two': 'two' });
    let open!: () => void;
    provider.gate = new Promise((resolve) => (open = resolve));
    const providers = registry(provider);

    const first = providers.read('fakevault', { locator: LOCATOR });
    const second = providers.read('fakevault', { locator: 'fake://two' });
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(provider.reads.map((read) => read.locator)).toEqual([LOCATOR]);

    open();
    await expect(first).resolves.toBe('one');
    await expect(second).resolves.toBe('two');
    expect(provider.reads.map((read) => read.locator)).toEqual([LOCATOR, 'fake://two']);
  });

  it('stops waiting at once when a queued read is cancelled, and never runs it', async () => {
    const provider = new FakeSecretProvider({ [LOCATOR]: 'one' });
    let open!: () => void;
    provider.gate = new Promise((resolve) => (open = resolve));
    const providers = registry(provider);

    const first = providers.read('fakevault', { locator: LOCATOR });
    const controller = new AbortController();
    const second = providers.read('fakevault', { locator: LOCATOR }, { signal: controller.signal });
    controller.abort();
    await expect(second).rejects.toMatchObject({ problem: 'cancelled' });

    open();
    await expect(first).resolves.toBe('one');
    // A third read still runs once the queue drains.
    await expect(providers.read('fakevault', { locator: LOCATOR })).resolves.toBe('one');
    expect(provider.reads).toHaveLength(2);

    const aborted = new AbortController();
    aborted.abort();
    await expect(
      providers.read('fakevault', { locator: LOCATOR }, { signal: aborted.signal }),
    ).rejects.toMatchObject({ problem: 'cancelled' });
    expect(provider.reads).toHaveLength(2);
  });
});
