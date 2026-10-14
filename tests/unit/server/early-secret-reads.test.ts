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

  it('tries a later read of the same secret when the one taken failed', async () => {
    const provider = new FakeSecretProvider({ 'fake://a': 'value-a' });
    provider.nextFailures.push(new SecretProviderError('denied', 'FakeVault did not allow access.'));
    const { vault, secret } = await setup(provider);
    const a = secret('fake://a');
    const early = new EarlySecretReads(vault);

    // One read for a login that a key made unnecessary, one for a sequence step.
    early.start([a]);
    early.start([a]);
    await vi.waitFor(() => expect(provider.reads).toHaveLength(2));
    await expect(early.read(a, notNow())).resolves.toBe('value-a');
    early.close();
  });

  it('reads again when a read failed for a reason that may have passed before anyone needed it', async () => {
    const provider = new FakeSecretProvider({ 'fake://a': 'value-a' });
    provider.nextFailures.push(
      new SecretProviderError('unreachable', 'FakeVault is not running.'),
      new SecretProviderError('timeout', 'FakeVault did not answer in time.'),
    );
    const { vault, secret } = await setup(provider);
    const a = secret('fake://a');
    const early = new EarlySecretReads(vault);

    early.start([a]);
    await vi.waitFor(() => expect(provider.reads).toHaveLength(1));
    await new Promise((resolve) => setImmediate(resolve));
    const readNow = vi.fn(() => vault.secretValue(a));
    await expect(early.read(a, readNow)).rejects.toMatchObject({ problem: 'timeout' });
    expect(readNow).toHaveBeenCalledTimes(1);

    // A failure the use itself waited through is its answer.
    provider.nextFailures.push(new SecretProviderError('timeout', 'FakeVault did not answer in time.'));
    early.start([a]);
    await expect(early.read(a, notNow())).rejects.toMatchObject({ problem: 'timeout' });
    expect(provider.reads).toHaveLength(3);
  });

  it('reads again when the secret was deleted or pointed elsewhere since the read started', async () => {
    const provider = new FakeSecretProvider({ 'fake://a': 'value-a', 'fake://b': 'value-b' });
    const { vault, secret } = await setup(provider);
    const a = secret('fake://a');
    const early = new EarlySecretReads(vault);

    early.start([a]);
    await vi.waitFor(() => expect(provider.reads).toHaveLength(1));
    vault.updateExternalSecret(a, { provider: 'fakevault', name: 'renamed', locator: 'fake://b' });
    await expect(early.read(a, () => vault.secretValue(a))).resolves.toBe('value-b');

    // A rename alone keeps the read.
    early.start([a]);
    await vi.waitFor(() => expect(provider.reads).toHaveLength(3));
    vault.updateExternalSecret(a, { provider: 'fakevault', name: 'renamed again', locator: 'fake://b' });
    await expect(early.read(a, notNow())).resolves.toBe('value-b');

    early.start([a]);
    await vi.waitFor(() => expect(provider.reads).toHaveLength(4));
    vault.deleteCredential(a);
    await expect(early.read(a, () => vault.secretValue(a))).resolves.toBeUndefined();
  });

  it('reads one secret at a time per manager for each session, so every session’s first secret comes first', async () => {
    const provider = new FakeSecretProvider({ 'fake://x1': 'x1', 'fake://y1': 'y1', 'fake://x2': 'x2', 'fake://y2': 'y2' });
    const open = gated(provider);
    const { vault, secret } = await setup(provider);
    const x1 = secret('fake://x1');
    const y1 = secret('fake://y1');
    const x2 = secret('fake://x2');
    const y2 = secret('fake://y2');
    const first = new EarlySecretReads(vault);
    const second = new EarlySecretReads(vault);

    first.start([x1]);
    first.start([y1]);
    second.start([x2]);
    second.start([y2]);
    await vi.waitFor(() => expect(provider.reads).toHaveLength(1));
    open();
    await vi.waitFor(() => expect(provider.reads).toHaveLength(4));
    expect(provider.reads.map((read) => read.locator)).toEqual(['fake://x1', 'fake://x2', 'fake://y1', 'fake://y2']);
    first.close();
    second.close();
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

    // Also when the provider carried on without an answer.
    provider.skippedValue = 'a default';
    early.start([a]);
    await expect(early.read(a, () => vault.secretValue(a, undefined, { ask }))).resolves.toBe('value-a');
    expect(ask).toHaveBeenCalledTimes(2);
    expect(provider.reads).toHaveLength(4);
  });

  it('drops a value nobody took within the time, counted once the session is connected', async () => {
    const provider = new FakeSecretProvider({ 'fake://a': 'value-a' });
    const { vault, secret } = await setup(provider);
    const a = secret('fake://a');
    const early = new EarlySecretReads(vault, { keepMs: 20 });

    early.start([a, a]);
    await vi.waitFor(() => expect(provider.reads).toHaveLength(2));
    // Still connecting (a jump host's prompt can take a while): kept.
    await new Promise((resolve) => setTimeout(resolve, 80));
    await expect(early.read(a, notNow())).resolves.toBe('value-a');

    early.connected();
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
