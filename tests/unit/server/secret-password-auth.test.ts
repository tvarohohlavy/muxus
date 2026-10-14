import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { generateKeyPairSync } from 'node:crypto';
import { Server } from 'ssh2';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import type { AuthPromptInfo, SshProfile } from '@muxus/shared/ws-protocol';
import { MuxusDatabase } from '../../../server/src/persistence/database.js';
import { SecretProviderError } from '../../../server/src/secret-providers/provider.js';
import { SecretProviders } from '../../../server/src/secret-providers/registry.js';
import { EarlySecretReads } from '../../../server/src/security/early-secret-reads.js';
import {
  PasswordVault,
  folderPasswordAccount,
  folderPasswordLabel,
  sshPasswordAccount,
  sshPasswordLabel,
} from '../../../server/src/security/password-vault.js';
import { SshConnectionManager, type ConnectIo } from '../../../server/src/ssh/connection-manager.js';
import {
  folderAuthResolver,
  savedProfileFolderAuthResolver,
} from '../../../server/src/ssh/folder-auth.js';
import { KnownHostsStore } from '../../../server/src/ssh/known-hosts.js';
import { loadConfigDocument } from '../../../server/src/ssh/ssh-config.js';
import { FakeSecretProvider } from './fake-secret-provider.js';

const tmp = mkdtempSync(path.join(os.tmpdir(), 'muxus-secret-password-'));
const PASSWORD = 'Cisco-Pass-1';
const MASTER = 'master-pass-12';
const LOCATOR = 'fake://network/core-sw1';

const HOST_KEY = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
}).privateKey;

const savedEnv = { HOME: process.env.HOME, SSH_AUTH_SOCK: process.env.SSH_AUTH_SOCK };
beforeAll(() => {
  // No real agent and no real ~/.ssh keys: the ladder must reach password auth.
  process.env.HOME = tmp;
  delete process.env.SSH_AUTH_SOCK;
});
afterAll(() => {
  process.env.HOME = savedEnv.HOME;
  if (savedEnv.SSH_AUTH_SOCK !== undefined) process.env.SSH_AUTH_SOCK = savedEnv.SSH_AUTH_SOCK;
  rmSync(tmp, { recursive: true, force: true });
});

/** Password-only sshd stand-in that records each password attempt. */
function startServer(): Promise<{ server: Server; port: number; attempts: boolean[] }> {
  const attempts: boolean[] = [];
  const server = new Server({ hostKeys: [HOST_KEY] }, (conn) => {
    conn.on('error', () => undefined);
    conn.on('authentication', (ctx) => {
      if (ctx.method === 'password') {
        attempts.push(ctx.password === PASSWORD);
        if (ctx.password === PASSWORD) return ctx.accept();
      }
      ctx.reject(['password']);
    });
    conn.on('ready', () => {
      conn.on('session', (acceptSession) => {
        const session = acceptSession();
        session.on('pty', (acceptPty) => acceptPty?.());
        session.on('shell', (acceptShell) => acceptShell().write('core-sw1>\n'));
      });
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve({ server, port: (server.address() as net.AddressInfo).port, attempts });
    });
  });
}

let counter = 0;
const cleanups: Array<() => void> = [];
afterEach(() => {
  for (const cleanup of cleanups.splice(0)) cleanup();
});

async function setup(
  port: number,
  provider: FakeSecretProvider,
  options: { vault?: boolean; hosts?: Array<{ alias: string; user: string }> } = {},
): Promise<{ manager: SshConnectionManager; vault: PasswordVault; database: MuxusDatabase }> {
  const configFile = path.join(tmp, `ssh_config-${counter++}`);
  writeFileSync(
    configFile,
    (options.hosts ?? [{ alias: 'lab', user: 'tester' }])
      .flatMap(({ alias, user }) => [`Host ${alias}`, '  HostName 127.0.0.1', `  User ${user}`, `  Port ${port}`, '  StrictHostKeyChecking no', ''])
      .join('\n'),
  );
  const database = new MuxusDatabase(':memory:');
  const vault = new PasswordVault(database, { providers: new SecretProviders(database, [provider]) });
  await vault.initialize();
  if (options.vault !== false) await vault.create(MASTER, 'never');
  database.updateOpenSshMetadata('lab', { group: 'Lab' });
  const log = { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() };
  const manager = new SshConnectionManager(log as never, {
    knownHosts: new KnownHostsStore(
      path.join(tmp, `known_hosts-${counter++}`),
      path.join(tmp, 'no-global-known-hosts'),
    ),
    loadConfig: () => loadConfigDocument(configFile),
    vault,
    savedSshProfile: (id) => {
      const profile = database.savedHostProfile(id)?.profile;
      return profile?.kind === 'ssh' ? profile : undefined;
    },
    folderAuth: folderAuthResolver(database),
    profileFolderAuth: savedProfileFolderAuthResolver(database),
    hostPasswordSecret: (host) => database.hostPasswordSecretId(host),
  });
  cleanups.push(() => {
    manager.closeAll();
    vault.dispose();
    database.close();
  });
  return { manager, vault, database };
}

function makeIo(
  answer: (prompt: string) => string = () => PASSWORD,
  signal?: AbortSignal,
): ConnectIo & { prompts: number; asked: AuthPromptInfo[]; statuses: string[] } {
  const io = {
    ...(signal ? { signal } : {}),
    prompts: 0,
    asked: [] as AuthPromptInfo[],
    statuses: [] as string[],
    status: (message: string) => {
      io.statuses.push(message);
    },
    prompt: (info: AuthPromptInfo) => {
      io.prompts += info.prompts.length;
      io.asked.push(info);
      return Promise.resolve({ answers: info.prompts.map((prompt) => answer(prompt.prompt)) });
    },
    hostKey: () => Promise.resolve(true),
  };
  return io as unknown as ConnectIo & { prompts: number; asked: AuthPromptInfo[]; statuses: string[] };
}

const profile: SshProfile = { kind: 'ssh', target: 'lab' };

async function connect(manager: SshConnectionManager, io: ConnectIo, target: SshProfile = profile): Promise<void> {
  const lease = await manager.connect(target, io);
  lease.release();
}

describe('logging in with a named secret', () => {
  it('asks the password manager for the host’s secret without a prompt, and without a vault', async () => {
    const { server, port, attempts } = await startServer();
    cleanups.push(() => server.close());
    const provider = new FakeSecretProvider({ [LOCATOR]: PASSWORD });
    const { manager, vault, database } = await setup(port, provider, { vault: false });
    const secret = vault.createExternalSecret({
      provider: 'fakevault',
      name: 'core-sw1 login',
      locator: LOCATOR,
      options: { account: 'work' },
    });
    database.updateOpenSshMetadata('lab', { passwordSecretId: secret.id });

    const io = makeIo();
    await connect(manager, io);

    expect(io.prompts).toBe(0);
    expect(attempts).toEqual([true]);
    expect(provider.reads).toEqual([{ locator: LOCATOR, options: { account: 'work' }, settings: {} }]);
    expect(io.statuses).toContain(`Asking FakeVault for “core-sw1 login” to log in to tester@127.0.0.1:${port} …`);
    expect(io.statuses).toContain(`Using “core-sw1 login” from FakeVault for tester@127.0.0.1:${port}.`);
    expect(io.statuses.join('\n')).not.toContain(PASSWORD);
  });

  it('puts the host’s secret ahead of its saved password', async () => {
    const { server, port, attempts } = await startServer();
    cleanups.push(() => server.close());
    const { manager, vault, database } = await setup(port, new FakeSecretProvider({ [LOCATOR]: PASSWORD }));
    const hostRef = { user: 'tester', host: '127.0.0.1', port };
    await vault.rememberSshPassword(sshPasswordAccount(hostRef), sshPasswordLabel(hostRef), 'stale-saved');
    const secret = vault.createExternalSecret({ provider: 'fakevault', name: 'core-sw1 login', locator: LOCATOR });
    database.updateOpenSshMetadata('lab', { passwordSecretId: secret.id });

    const io = makeIo();
    await connect(manager, io);

    expect(io.prompts).toBe(0);
    expect(attempts).toEqual([true]);
  });

  it('uses the folder’s secret for hosts inside it', async () => {
    const { server, port, attempts } = await startServer();
    cleanups.push(() => server.close());
    const { manager, vault, database } = await setup(port, new FakeSecretProvider({ [LOCATOR]: PASSWORD }));
    const secret = vault.createExternalSecret({ provider: 'fakevault', name: 'TACACS', locator: LOCATOR });
    database.upsertFolderSettings('Lab', { passwordSecretId: secret.id });

    const io = makeIo();
    await connect(manager, io);

    expect(io.prompts).toBe(0);
    expect(attempts).toEqual([true]);
    expect(io.statuses).toContain('Using “TACACS” from FakeVault for Folder Lab.');
  });

  it('lets the password manager ask in the session’s own prompt', async () => {
    const { server, port, attempts } = await startServer();
    cleanups.push(() => server.close());
    const provider = new FakeSecretProvider({ [LOCATOR]: PASSWORD });
    provider.passphrase = 'open sesame';
    const { manager, vault, database } = await setup(port, provider, { vault: false });
    const secret = vault.createExternalSecret({ provider: 'fakevault', name: 'core-sw1 login', locator: LOCATOR });
    database.updateOpenSshMetadata('lab', { passwordSecretId: secret.id });

    const io = makeIo((prompt) => (prompt === 'Passphrase' ? 'open sesame' : PASSWORD));
    await connect(manager, io);

    expect(io.asked).toEqual([
      { host: 'lab', name: 'Unlock FakeVault', prompts: [{ prompt: 'Passphrase', echo: false }] },
    ]);
    expect(attempts).toEqual([true]);
  });

  it('says why the password manager failed and moves on to the next saved password', async () => {
    const { server, port, attempts } = await startServer();
    cleanups.push(() => server.close());
    const failure = new SecretProviderError('not-installed', 'The FakeVault CLI is not installed.');
    const { manager, vault, database } = await setup(port, new FakeSecretProvider({}, { failure }));
    const secret = vault.createExternalSecret({ provider: 'fakevault', name: 'core-sw1 login', locator: LOCATOR });
    database.updateOpenSshMetadata('lab', { passwordSecretId: secret.id });
    const row = database.upsertFolderSettings('Lab', {});
    await vault.rememberSshPassword(folderPasswordAccount(row.id), folderPasswordLabel(row.path), PASSWORD);

    const io = makeIo();
    await connect(manager, io);

    expect(io.prompts).toBe(0);
    expect(attempts).toEqual([true]);
    expect(io.statuses).toContain(
      'FakeVault could not provide “core-sw1 login”: The FakeVault CLI is not installed.',
    );
  });

  it('falls back to the password prompt when nothing else is saved, or the value is refused', async () => {
    const { server, port, attempts } = await startServer();
    cleanups.push(() => server.close());
    const failure = new SecretProviderError('denied', 'FakeVault did not allow access.');
    const unavailable = await setup(port, new FakeSecretProvider({}, { failure }), { vault: false });
    const secret = unavailable.vault.createExternalSecret({ provider: 'fakevault', name: 'core-sw1 login', locator: LOCATOR });
    unavailable.database.updateOpenSshMetadata('lab', { passwordSecretId: secret.id });
    const first = makeIo();
    await connect(unavailable.manager, first);
    expect(first.prompts).toBe(1);
    expect(attempts).toEqual([true]);

    const stale = await setup(port, new FakeSecretProvider({ [LOCATOR]: 'rotated-away' }));
    const staleSecret = stale.vault.createExternalSecret({ provider: 'fakevault', name: 'core-sw1 login', locator: LOCATOR });
    stale.database.updateOpenSshMetadata('lab', { passwordSecretId: staleSecret.id });
    const second = makeIo();
    await connect(stale.manager, second);
    expect(second.prompts).toBe(1);
    expect(attempts).toEqual([true, false, true]);
    // The prompt names the secret, not a saved password the host never had.
    for (const io of [first, second]) {
      expect(io.asked[0]?.instructions).toBe(
        'The password from “core-sw1 login” was unavailable or was not accepted. Enter the current password.',
      );
    }
  });

  it('asks a missing password manager once, however many secrets it holds', async () => {
    const { server, port, attempts } = await startServer();
    cleanups.push(() => server.close());
    const failure = new SecretProviderError('not-installed', 'The FakeVault CLI is not installed.');
    const provider = new FakeSecretProvider({}, { failure });
    const { manager, vault, database } = await setup(port, provider, { vault: false });
    const hostSecret = vault.createExternalSecret({ provider: 'fakevault', name: 'core-sw1 login', locator: LOCATOR });
    const folderSecret = vault.createExternalSecret({ provider: 'fakevault', name: 'TACACS', locator: 'fake://network/tacacs' });
    database.updateOpenSshMetadata('lab', { passwordSecretId: hostSecret.id });
    database.upsertFolderSettings('Lab', { passwordSecretId: folderSecret.id });

    const io = makeIo();
    await connect(manager, io);

    expect(provider.reads.map((read) => read.locator)).toEqual([LOCATOR]);
    expect(io.statuses.filter((status) => status.includes('could not provide'))).toEqual([
      'FakeVault could not provide “core-sw1 login”: The FakeVault CLI is not installed.',
    ]);
    expect(io.prompts).toBe(1);
    expect(attempts).toEqual([true]);
  });

  it('reads a secret named by both the host and its folder once', async () => {
    const { server, port, attempts } = await startServer();
    cleanups.push(() => server.close());
    const failure = new SecretProviderError('denied', 'FakeVault did not allow access.');
    const provider = new FakeSecretProvider({}, { failure });
    const { manager, vault, database } = await setup(port, provider, { vault: false });
    const secret = vault.createExternalSecret({ provider: 'fakevault', name: 'TACACS', locator: LOCATOR });
    database.updateOpenSshMetadata('lab', { passwordSecretId: secret.id });
    database.upsertFolderSettings('Lab', { passwordSecretId: secret.id });

    const io = makeIo();
    await connect(manager, io);

    expect(provider.reads).toHaveLength(1);
    expect(io.statuses.filter((status) => status.includes('could not provide'))).toHaveLength(1);
    expect(io.prompts).toBe(1);
    expect(attempts).toEqual([true]);
  });

  it('stops waiting on the password manager when the session goes away, and lets the next one ask', async () => {
    const { server, port, attempts } = await startServer();
    cleanups.push(() => server.close());
    const provider = new FakeSecretProvider({ [LOCATOR]: PASSWORD, 'fake://network/core-sw2': PASSWORD });
    let open!: () => void;
    provider.gate = new Promise((resolve) => (open = resolve));
    // A different user, so the second host dials its own transport instead
    // of waiting on the first host's.
    const { manager, vault, database } = await setup(port, provider, {
      vault: false,
      hosts: [{ alias: 'lab', user: 'tester' }, { alias: 'lab2', user: 'operator' }],
    });
    const first = vault.createExternalSecret({ provider: 'fakevault', name: 'core-sw1 login', locator: LOCATOR });
    const second = vault.createExternalSecret({ provider: 'fakevault', name: 'core-sw2 login', locator: 'fake://network/core-sw2' });
    database.updateOpenSshMetadata('lab', { passwordSecretId: first.id });
    database.updateOpenSshMetadata('lab2', { passwordSecretId: second.id });

    // The first session's read waits on the manager (the gate); the second
    // queues behind it, as the registry runs one read per provider at a time.
    const controller = new AbortController();
    const abandoned = makeIo(undefined, controller.signal);
    const abandonedConnect = connect(manager, abandoned);
    abandonedConnect.catch(() => undefined);
    await vi.waitFor(() => expect(provider.reads).toHaveLength(1));
    const next = makeIo();
    const nextConnect = connect(manager, next, { kind: 'ssh', target: 'lab2' });
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(provider.reads).toHaveLength(1);

    controller.abort();
    await expect(abandonedConnect).rejects.toThrow(/cancelled/);
    // The second read starts before the manager ever answers the first.
    await vi.waitFor(() => expect(provider.reads).toHaveLength(2));

    open();
    await nextConnect;
    expect(next.prompts).toBe(0);
    expect(attempts).toEqual([true]);
  });

  it('logs in with a vault secret too, and skips one that was deleted', async () => {
    const { server, port, attempts } = await startServer();
    cleanups.push(() => server.close());
    const provider = new FakeSecretProvider({});
    const { manager, vault, database } = await setup(port, provider);
    const secret = await vault.createSecret({ name: 'Lab login', value: PASSWORD }, MASTER);
    database.updateOpenSshMetadata('lab', { passwordSecretId: secret.id });

    const io = makeIo();
    await connect(manager, io);
    expect(io.prompts).toBe(0);
    expect(io.statuses).toContain(`Using “Lab login” for tester@127.0.0.1:${port}.`);

    manager.closeAll();
    vault.deleteCredential(secret.id);
    const again = makeIo();
    await connect(manager, again);
    expect(again.prompts).toBe(1);
    expect(attempts).toEqual([true, true]);
    expect(provider.reads).toEqual([]);
  });

  it('reads a Muxus-only host’s secret through its profile ID', async () => {
    const { server, port, attempts } = await startServer();
    cleanups.push(() => server.close());
    const { manager, vault, database } = await setup(port, new FakeSecretProvider({ [LOCATOR]: PASSWORD }));
    const saved = database.saveSavedHostProfile({
      name: 'core-sw1',
      profile: { kind: 'ssh', target: `tester@127.0.0.1:${port}`, useConfig: false },
    });
    const secret = vault.createExternalSecret({ provider: 'fakevault', name: 'core-sw1 login', locator: LOCATOR });
    database.updateSavedHostMetadata(saved.id, { passwordSecretId: secret.id });
    expect(database.savedHostProfile(saved.id)?.metadata.passwordSecretId).toBe(secret.id);

    const io = makeIo();
    await connect(manager, io, { kind: 'ssh', target: `tester@127.0.0.1:${port}`, useConfig: false, profileId: saved.id });

    expect(io.prompts).toBe(0);
    expect(attempts).toEqual([true]);
  });
});

describe('reading the login password early', () => {
  it('starts the read as the connection starts and logs in with it, and reads nothing for a shared connection', async () => {
    const { server, port, attempts } = await startServer();
    cleanups.push(() => server.close());
    const provider = new FakeSecretProvider({ [LOCATOR]: PASSWORD });
    const { manager, vault, database } = await setup(port, provider, { vault: false });
    const secret = vault.createExternalSecret({ provider: 'fakevault', name: 'core-sw1 login', locator: LOCATOR });
    database.updateOpenSshMetadata('lab', { passwordSecretId: secret.id });

    const io = makeIo();
    io.earlySecrets = new EarlySecretReads(vault);
    const lease = await (async () => {
      const connecting = manager.connect(profile, io);
      // Under way before the SSH handshake could have reached the password.
      await new Promise((resolve) => setImmediate(resolve));
      expect(provider.reads).toHaveLength(1);
      expect(io.statuses.some((status) => status.startsWith('Asking FakeVault'))).toBe(false);
      return connecting;
    })();

    expect(io.prompts).toBe(0);
    expect(attempts).toEqual([true]);
    expect(provider.reads).toHaveLength(1);
    expect(io.statuses).toContain(`Using “core-sw1 login” from FakeVault for tester@127.0.0.1:${port}.`);

    const second = makeIo();
    second.earlySecrets = new EarlySecretReads(vault);
    await connect(manager, second);
    expect(provider.reads).toHaveLength(1);
    lease.release();
  });

  it('asks in the session’s prompt when the password manager wanted to ask during the early read', async () => {
    const { server, port, attempts } = await startServer();
    cleanups.push(() => server.close());
    const provider = new FakeSecretProvider({ [LOCATOR]: PASSWORD });
    provider.passphrase = 'open sesame';
    const { manager, vault, database } = await setup(port, provider, { vault: false });
    const secret = vault.createExternalSecret({ provider: 'fakevault', name: 'TACACS', locator: LOCATOR });
    database.upsertFolderSettings('Lab', { passwordSecretId: secret.id });

    const io = makeIo((prompt) => (prompt === 'Passphrase' ? 'open sesame' : PASSWORD));
    io.earlySecrets = new EarlySecretReads(vault);
    await connect(manager, io);

    expect(io.asked).toEqual([
      { host: 'lab', name: 'Unlock FakeVault', prompts: [{ prompt: 'Passphrase', echo: false }] },
    ]);
    expect(provider.reads).toHaveLength(2);
    expect(attempts).toEqual([true]);
  });

  it('takes a failed early read as the secret’s failure and moves on to the next password', async () => {
    const { server, port, attempts } = await startServer();
    cleanups.push(() => server.close());
    const failure = new SecretProviderError('denied', 'FakeVault did not allow access.');
    const provider = new FakeSecretProvider({}, { failure });
    const { manager, vault, database } = await setup(port, provider);
    const secret = vault.createExternalSecret({ provider: 'fakevault', name: 'core-sw1 login', locator: LOCATOR });
    database.updateOpenSshMetadata('lab', { passwordSecretId: secret.id });
    const row = database.upsertFolderSettings('Lab', {});
    await vault.rememberSshPassword(folderPasswordAccount(row.id), folderPasswordLabel(row.path), PASSWORD);

    const io = makeIo();
    io.earlySecrets = new EarlySecretReads(vault);
    await connect(manager, io);

    expect(provider.reads).toHaveLength(1);
    expect(io.statuses).toContain('FakeVault could not provide “core-sw1 login”: FakeVault did not allow access.');
    expect(io.prompts).toBe(0);
    expect(attempts).toEqual([true]);
  });

  it('reads nothing early when the first password to try is not in a password manager', async () => {
    const { server, port, attempts } = await startServer();
    cleanups.push(() => server.close());
    const provider = new FakeSecretProvider({ [LOCATOR]: 'not-it' });
    const { manager, vault, database } = await setup(port, provider);
    const hostRef = { user: 'tester', host: '127.0.0.1', port };
    await vault.rememberSshPassword(sshPasswordAccount(hostRef), sshPasswordLabel(hostRef), PASSWORD);
    const secret = vault.createExternalSecret({ provider: 'fakevault', name: 'TACACS', locator: LOCATOR });
    database.upsertFolderSettings('Lab', { passwordSecretId: secret.id });

    const io = makeIo();
    io.earlySecrets = new EarlySecretReads(vault);
    await connect(manager, io);

    expect(provider.reads).toEqual([]);
    expect(attempts).toEqual([true]);
  });
});
