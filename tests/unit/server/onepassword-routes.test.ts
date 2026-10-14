import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { SecretProviderInfo, SecretProvidersResponse, VaultSecretSaveResult } from '@muxus/shared';
import { buildApp } from '../../../server/src/app.js';
import { resolveConfig } from '../../../server/src/config.js';
import { isExecutableFile } from '../../../server/src/secret-providers/cli.js';
import { OnePasswordProvider } from '../../../server/src/secret-providers/onepassword.js';

const TOKEN = 'onepassword-route-token';
const VALUE = 'Cisco-Pass-1';
const REFERENCE = 'op://Network/core-sw1/password';

let built: Awaited<ReturnType<typeof buildApp>>;
let scratch: string;

beforeEach(async () => {
  scratch = mkdtempSync(path.join(os.tmpdir(), 'muxus-onepassword-routes-'));
  // The real provider, but only the test's own op is ever found: the
  // build's default would run whatever op this machine has on PATH.
  const fake = path.join(scratch, 'op');
  built = await buildApp(
    resolveConfig({
      token: TOKEN,
      databasePath: ':memory:',
      openBrowser: false,
      prettyLogs: false,
      staticRoot: '/path/that/does/not/exist',
    }),
    { secretProviders: [new OnePasswordProvider({ isFile: (file) => file === fake && isExecutableFile(file) })] },
  );
});

afterEach(async () => {
  await built.app.close();
  rmSync(scratch, { recursive: true, force: true });
});

async function api<T>(method: 'GET' | 'POST' | 'PUT', url: string, payload?: unknown) {
  const response = await built.app.inject({
    method,
    url,
    headers: { authorization: `Bearer ${TOKEN}` },
    payload: payload as never,
  });
  return { status: response.statusCode, body: response.json() as T, raw: response.body };
}

/** A stand-in for the 1Password CLI that knows one field. */
function fakeOp(): string {
  const op = path.join(scratch, 'op');
  writeFileSync(
    op,
    [
      '#!/bin/sh',
      'if [ "$1" = "--version" ]; then echo 2.30.0; exit 0; fi',
      'for last; do :; done',
      'case "$last" in',
      `  ${REFERENCE}) printf '%s' '${VALUE}' ;;`,
      `  *) echo "[ERROR] 2026/10/09 10:00:00 could not read secret '$last': \\"gone\\" isn't an item in the \\"Network\\" vault" >&2; exit 1 ;;`,
      'esac',
      '',
    ].join('\n'),
  );
  chmodSync(op, 0o755);
  return op;
}

describe('1Password as a secret provider', () => {
  it('is offered with its fields', async () => {
    const list = await api<SecretProvidersResponse>('GET', '/api/secret-providers');
    const onePassword = list.body.providers.find((info) => info.descriptor.id === 'onepassword');
    expect(onePassword?.descriptor).toMatchObject({
      label: '1Password',
      locator: { label: 'Secret reference' },
      options: [{ key: 'account' }],
      settings: [{ key: 'cliPath' }],
    });
  });

  it.skipIf(process.platform === 'win32')('finds the CLI at a configured path and tests a reference', async () => {
    const relative = await api<{ message: string }>('PUT', '/api/secret-providers/onepassword/settings', {
      settings: { cliPath: 'op' },
    });
    expect(relative).toMatchObject({ status: 400, body: { message: 'Enter the full path to the 1Password CLI.' } });

    const op = fakeOp();
    const saved = await api<SecretProviderInfo>('PUT', '/api/secret-providers/onepassword/settings', {
      settings: { cliPath: op },
    });
    expect(saved).toMatchObject({
      status: 200,
      body: {
        settings: { cliPath: op },
        status: { available: true, summary: 'Found the 1Password CLI 2.30.0.', detected: { cliPath: op } },
      },
    });

    const ok = await api('POST', '/api/secret-providers/onepassword/test', { locator: REFERENCE });
    expect(ok).toMatchObject({ status: 200, body: { ok: true } });
    expect(ok.raw).not.toContain(VALUE);

    const gone = await api<{ code: string; message: string }>('POST', '/api/secret-providers/onepassword/test', {
      locator: 'op://Network/gone/password',
    });
    expect(gone).toMatchObject({
      status: 502,
      body: {
        code: 'secret-provider-unavailable',
        message: '1Password has nothing at that secret reference. 1Password said: “"gone" isn\'t an item in the "Network" vault”',
      },
    });
  });

  it('saves a reference and an account, and rejects a malformed one', async () => {
    const created = await api<VaultSecretSaveResult>('POST', '/api/password-vault/external-secrets', {
      provider: 'onepassword',
      name: 'core-sw1 enable',
      locator: ` ${REFERENCE} `,
      options: { account: 'work.1password.com' },
    });
    expect(created.status).toBe(200);
    expect(created.body.secret.external).toEqual({
      provider: 'onepassword',
      providerLabel: '1Password',
      locator: REFERENCE,
      options: { account: 'work.1password.com' },
    });

    const bad = await api<{ code: string; message: string }>('POST', '/api/password-vault/external-secrets', {
      provider: 'onepassword',
      name: 'enable',
      locator: 'Network/core-sw1/enable',
    });
    expect(bad).toMatchObject({
      status: 400,
      body: { code: 'invalid-vault-secret', message: 'A secret reference starts with op://' },
    });
    const flag = await api<{ code: string }>('POST', '/api/password-vault/external-secrets', {
      provider: 'onepassword',
      name: 'enable',
      locator: REFERENCE,
      options: { account: '--debug' },
    });
    expect(flag).toMatchObject({ status: 400, body: { code: 'invalid-vault-secret' } });
  });
});
