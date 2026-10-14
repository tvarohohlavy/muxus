import { afterEach, describe, expect, it, vi } from 'vitest';
import { MuxusDatabase } from '../../../server/src/persistence/database.js';
import { SecretProviderError } from '../../../server/src/secret-providers/provider.js';
import { SecretProviders } from '../../../server/src/secret-providers/registry.js';
import { EarlySecretReads } from '../../../server/src/security/early-secret-reads.js';
import { PasswordVault } from '../../../server/src/security/password-vault.js';
import { FakeSecretProvider } from './fake-secret-provider.js';

const MASTER = 'master-pass-12';

const cleanups: Array<() => void> = [];
afterEach(() => {
  for (const cleanup of cleanups.splice(0)) cleanup();
});

async function setup(provider: FakeSecretProvider) {
  const database = new MuxusDatabase(':memory:');
  const vault = new PasswordVault(database, { providers: new SecretProviders(database, [provider]) });
  await vault.initialize();
  cleanups.push(() => {
    vault.dispose();
    database.close();
  });
  const secret = (locator: string) =>
    vault.createExternalSecret({ provider: 'fakevault', name: locator, locator }).id;
  return { vault, secret };
}

/** A read made at the moment of use, which the early read should spare. */
const notNow = () => vi.fn(() => Promise.reject(new Error('read again')));

function gated(provider: FakeSecretProvider): () => void {
  let open!: () => void;
  provider.gate = new Promise((resolve) => (open = resolve));
  return open;
}

describe('reading secrets early', () => {
  it('reads each password-manager secret it is given, one read per use, in order', async () => {
    const provider = new FakeSecretProvider({ 'fake://a': 'value-a', 'fake://b': 'value-b' });
    const { vault, secret } = await setup(provider);
    await vault.create(MASTER, 'never');
    const saved = await vault.createSecret({ name: 'In the vault', value: 'vault-value' }, MASTER);
    const a = secret('fake://a');
    const b = secret('fake://b');
    const early = new EarlySecretReads(vault);

    early.start([a, saved.id, 'no-such-secret', a, b]);
    await vi.waitFor(() => expect(provider.reads).toHaveLength(3));
    expect(provider.reads.map((read) => read.locator)).toEqual(['fake://a', 'fake://a', 'fake://b']);

    const readNow = notNow();
    await expect(early.read(b, readNow)).resolves.toBe('value-b');
    await expect(early.read(a, readNow)).resolves.toBe('value-a');
    await expect(early.read(a, readNow)).resolves.toBe('value-a');
    expect(readNow).not.toHaveBeenCalled();
    // Used up: the next use, and a vault secret, are read when they come.
    const again = vi.fn(() => Promise.resolve('fresh'));
    await expect(early.read(a, again)).resolves.toBe('fresh');
    await expect(early.read(saved.id, again)).resolves.toBe('fresh');
    expect(again).toHaveBeenCalledTimes(2);
    expect(provider.reads).toHaveLength(3);
    early.close();
  });

  it('gives a failed read to the use that takes it, without reading again', async () => {
    const failure = new SecretProviderError('denied', 'FakeVault did not allow access.');
    const provider = new FakeSecretProvider({}, { failure });
    const { vault, secret } = await setup(provider);
    const a = secret('fake://a');
    const early = new EarlySecretReads(vault);

    early.start([a]);
    const readNow = notNow();
    await expect(early.read(a, readNow)).rejects.toBe(failure);
    expect(readNow).not.toHaveBeenCalled();
    expect(provider.reads).toHaveLength(1);
  });

  it('reads again at the moment of use when the provider wanted to ask the user something', async () => {
    const provider = new FakeSecretProvider({ 'fake://a': 'value-a' });
    provider.passphrase = 'open sesame';
    const { vault, secret } = await setup(provider);
    const a = secret('fake://a');
    const early = new EarlySecretReads(vault);

    early.start([a]);
    const ask = vi.fn(() => Promise.resolve({ answers: ['open sesame'] }));
    await expect(early.read(a, () => vault.secretValue(a, undefined, { ask }))).resolves.toBe('value-a');
    expect(ask).toHaveBeenCalledTimes(1);
    expect(provider.reads).toHaveLength(2);
  });

  it('drops a value nobody took in time', async () => {
    const provider = new FakeSecretProvider({ 'fake://a': 'value-a' });
    const { vault, secret } = await setup(provider);
    const a = secret('fake://a');
    const early = new EarlySecretReads(vault, { keepMs: 20 });

    early.start([a]);
    await new Promise((resolve) => setTimeout(resolve, 80));
    const readNow = vi.fn(() => Promise.resolve('fresh'));
    await expect(early.read(a, readNow)).resolves.toBe('fresh');
    expect(readNow).toHaveBeenCalledTimes(1);
  });

  it('cancels the reads still running when the session ends, and reads nothing after', async () => {
    const provider = new FakeSecretProvider({ 'fake://a': 'value-a' });
    const open = gated(provider);
    const { vault, secret } = await setup(provider);
    const a = secret('fake://a');
    const session = new AbortController();
    const early = new EarlySecretReads(vault, { signal: session.signal });

    early.start([a, a]);
    await vi.waitFor(() => expect(provider.reads).toHaveLength(1));
    const taken = early.read(a, notNow());
    session.abort();
    await expect(taken).rejects.toMatchObject({ problem: 'cancelled' });
    open();

    early.start([a]);
    const readNow = vi.fn(() => Promise.resolve('fresh'));
    await expect(early.read(a, readNow)).resolves.toBe('fresh');
    // The queued second read never reached the provider.
    expect(provider.reads).toHaveLength(1);
  });

  it('stops waiting for an early read when its use is cancelled', async () => {
    const provider = new FakeSecretProvider({ 'fake://a': 'value-a' });
    const open = gated(provider);
    const { vault, secret } = await setup(provider);
    const a = secret('fake://a');
    const early = new EarlySecretReads(vault);

    early.start([a]);
    const step = new AbortController();
    const taken = early.read(a, notNow(), step.signal);
    step.abort();
    await expect(taken).rejects.toMatchObject({ problem: 'cancelled' });
    open();
    early.close();
  });
});
