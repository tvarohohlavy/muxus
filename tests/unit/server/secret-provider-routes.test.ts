import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { PasswordVaultStatus, SecretProvidersResponse, VaultSecretSaveResult } from '@muxus/shared';
import type { AppContext } from '../../../server/src/app.js';
import { buildApp } from '../../../server/src/app.js';
import { resolveConfig } from '../../../server/src/config.js';
import { SecretProviderError } from '../../../server/src/secret-providers/provider.js';
import { FakeSecretProvider } from './fake-secret-provider.js';

const TOKEN = 'secret-provider-route-token';
const MASTER = 'master-pass-12';
const LOCATOR = 'fake://network/core-sw1';
const VALUE = 'Cisco-Pass-1';

let app: Awaited<ReturnType<typeof buildApp>>['app'];
let ctx: AppContext;
let provider: FakeSecretProvider;

beforeEach(async () => {
  provider = new FakeSecretProvider({ [LOCATOR]: VALUE });
  ({ app, ctx } = await buildApp(
    resolveConfig({
      token: TOKEN,
      databasePath: ':memory:',
      openBrowser: false,
      prettyLogs: false,
      staticRoot: '/path/that/does/not/exist',
    }),
    { secretProviders: [provider] },
  ));
});

afterEach(async () => {
  await app.close();
});

function request(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { authorization: `Bearer ${TOKEN}` },
    ...(payload === undefined ? {} : { payload: payload as object }),
  });
}

async function addSecret(input: Record<string, unknown> = {}): Promise<VaultSecretSaveResult> {
  const response = await request('POST', '/api/password-vault/external-secrets', {
    provider: 'fakevault',
    name: 'core-sw1 login',
    locator: LOCATOR,
    ...input,
  });
  expect(response.statusCode).toBe(200);
  return response.json();
}

describe('secret provider routes', () => {
  it('lists the providers this build offers, with their status', async () => {
    const response = await request('GET', '/api/secret-providers');
    expect(response.statusCode).toBe(200);
    expect(response.json<SecretProvidersResponse>()).toEqual({
      providers: [
        {
          descriptor: provider.descriptor,
          settings: {},
          status: { available: true, summary: 'FakeVault is ready.', detected: { cliPath: '/usr/bin/fakevault' } },
        },
      ],
    });
  });

  it('saves settings, and refuses ones the provider cannot use', async () => {
    const saved = await request('PUT', '/api/secret-providers/fakevault/settings', {
      settings: { cliPath: '/opt/fakevault' },
    });
    expect(saved.statusCode).toBe(200);
    expect(saved.json()).toMatchObject({ settings: { cliPath: '/opt/fakevault' } });

    const relative = await request('PUT', '/api/secret-providers/fakevault/settings', {
      settings: { cliPath: 'fakevault' },
    });
    expect(relative.statusCode).toBe(400);
    expect(relative.json()).toEqual({
      message: 'Enter the full path to the CLI.',
      code: 'invalid-secret-provider-settings',
    });

    const unknown = await request('PUT', '/api/secret-providers/nothing/settings', { settings: {} });
    expect(unknown.statusCode).toBe(404);
    expect(unknown.json()).toMatchObject({ code: 'secret-provider-missing' });

    const cleared = await request('PUT', '/api/secret-providers/fakevault/settings', {
      settings: { cliPath: '' },
    });
    expect(cleared.json()).toMatchObject({ settings: {} });
    expect(ctx.database.secretProviderSettings('fakevault')).toEqual({});
  });

  it('tests a locator without ever returning the value', async () => {
    const ok = await request('POST', '/api/secret-providers/fakevault/test', { locator: LOCATOR });
    expect(ok.statusCode).toBe(200);
    expect(ok.headers['cache-control']).toBe('no-store');
    expect(ok.json()).toEqual({ ok: true });
    expect(ok.body).not.toContain(VALUE);

    const missing = await request('POST', '/api/secret-providers/fakevault/test', {
      locator: 'fake://network/gone',
    });
    expect(missing.statusCode).toBe(502);
    expect(missing.json()).toEqual({
      message: 'FakeVault has nothing at that path.',
      code: 'secret-provider-unavailable',
    });

    const invalid = await request('POST', '/api/secret-providers/fakevault/test', { locator: 'op://x' });
    expect(invalid.statusCode).toBe(400);
    expect(invalid.json()).toMatchObject({ message: 'An item path starts with fake://.' });
    expect(provider.reads).toHaveLength(2);
  });

  it('saves a secret from a password manager with no vault and no master password', async () => {
    const { secret, status } = await addSecret({ username: 'admin', options: { account: 'work' } });
    expect(secret).toMatchObject({
      name: 'core-sw1 login',
      username: 'admin',
      external: {
        provider: 'fakevault',
        providerLabel: 'FakeVault',
        locator: LOCATOR,
        options: { account: 'work' },
      },
    });
    expect(status).toMatchObject({ configured: false, secrets: [{ id: secret.id }] });
    expect(JSON.stringify(status)).not.toContain(VALUE);

    const renamed = await request('PUT', `/api/password-vault/external-secrets/${secret.id}`, {
      provider: 'fakevault',
      name: 'core-sw1',
      locator: 'fake://network/core-sw1-new',
    });
    expect(renamed.statusCode).toBe(200);
    expect(renamed.json<VaultSecretSaveResult>().secret).toMatchObject({
      id: secret.id,
      name: 'core-sw1',
      external: { locator: 'fake://network/core-sw1-new' },
    });
    expect(renamed.json<VaultSecretSaveResult>().secret.username).toBeUndefined();
    expect(renamed.json<VaultSecretSaveResult>().secret.external?.options).toBeUndefined();

    const gone = await request('PUT', '/api/password-vault/external-secrets/nothing-here', {
      provider: 'fakevault',
      name: 'x',
      locator: LOCATOR,
    });
    expect(gone.statusCode).toBe(404);
  });

  it('refuses a secret the provider could not find, or a name already taken', async () => {
    await addSecret();
    const taken = await request('POST', '/api/password-vault/external-secrets', {
      provider: 'fakevault',
      name: 'CORE-SW1 LOGIN',
      locator: LOCATOR,
    });
    expect(taken.statusCode).toBe(409);
    expect(taken.json()).toMatchObject({ code: 'vault-secret-name-taken' });

    for (const [payload, message] of [
      [{ locator: 'op://x' }, 'An item path starts with fake://.'],
      [{ provider: 'nothing' }, 'This version of Muxus has no secret provider “nothing”.'],
      [{ options: { region: 'eu' } }, 'FakeVault has no option “region”.'],
    ] as const) {
      const refused = await request('POST', '/api/password-vault/external-secrets', {
        provider: 'fakevault',
        name: 'Another',
        locator: LOCATOR,
        ...payload,
      });
      expect(refused.statusCode).toBe(400);
      expect(refused.json()).toEqual({ message, code: 'invalid-vault-secret' });
    }
  });

  it('keeps those secrets when the vault is reset, and deletes them like any other', async () => {
    await request('POST', '/api/password-vault/create', { password: MASTER });
    const vaultSecret = await request('POST', '/api/password-vault/secrets', {
      name: 'Enable',
      value: 'enable-pass',
      masterPassword: MASTER,
    });
    expect(vaultSecret.statusCode).toBe(200);
    const { secret } = await addSecret();
    expect(ctx.vault.secrets().map((entry) => entry.name)).toEqual(['core-sw1 login', 'Enable']);

    const reset = await request('DELETE', '/api/password-vault');
    expect(reset.json<PasswordVaultStatus>().secrets.map((entry) => entry.id)).toEqual([secret.id]);

    const deleted = await request('DELETE', `/api/password-vault/credentials/${secret.id}`);
    expect(deleted.json()).toEqual({ deleted: true });
    expect(ctx.vault.secrets()).toEqual([]);
  });

  it('asks the manager only once there is a session to type into', async () => {
    const { secret } = await addSecret();
    provider.failure = new SecretProviderError('denied', 'FakeVault did not allow access.');
    const noSession = await request('POST', `/api/password-vault/secrets/${secret.id}/send`, {
      terminalIds: ['nope'],
      enter: true,
    });
    expect(noSession.statusCode).toBe(409);
    expect(provider.reads).toEqual([]);
  });
});
