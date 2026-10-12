import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { MuxusDatabase } from '../../../server/src/persistence/database.js';
import type { CliRunner } from '../../../server/src/secret-providers/cli.js';
import {
  knownLocations,
  OnePasswordProvider,
} from '../../../server/src/secret-providers/onepassword.js';
import { SecretProviderError } from '../../../server/src/secret-providers/provider.js';
import { SecretProviders } from '../../../server/src/secret-providers/registry.js';

const REFERENCE = 'op://Network/core-sw1/password';
const UNREACHABLE = `[ERROR] 2026/10/09 22:41:53 could not read secret '${REFERENCE}': error initializing client: connecting to desktop app: connecting to desktop app timed out, make sure it is installed, running and CLI integration is enabled`;

function failure(stderr: string, extra: Record<string, unknown> = {}): Error {
  return Object.assign(new Error('Command failed'), { code: 1, stderr, ...extra });
}

function provider(run: CliRunner, files: string[] = ['/usr/bin/op']): OnePasswordProvider {
  return new OnePasswordProvider({
    run,
    platform: 'linux',
    env: { PATH: '/usr/bin' },
    isFile: (file) => files.includes(file),
    retryDelayMs: 0,
  });
}

function read(
  onePassword: OnePasswordProvider,
  locator = REFERENCE,
  options: { account?: string; cliPath?: string; signal?: AbortSignal } = {},
): Promise<string> {
  return onePassword.read(
    { locator, options: options.account ? { account: options.account } : {} },
    {
      settings: options.cliPath ? { cliPath: options.cliPath } : {},
      ...(options.signal ? { signal: options.signal } : {}),
    },
  );
}

async function problemOf(promise: Promise<unknown>): Promise<SecretProviderError> {
  const err = await promise.then(
    () => undefined,
    (error: unknown) => error,
  );
  expect(err).toBeInstanceOf(SecretProviderError);
  return err as SecretProviderError;
}

const databases: MuxusDatabase[] = [];
afterEach(() => {
  for (const database of databases.splice(0)) database.close();
});

/** The registry around a provider, which checks what the user typed before the CLI sees it. */
function registryFor(onePassword: OnePasswordProvider): SecretProviders {
  const database = new MuxusDatabase(':memory:');
  databases.push(database);
  return new SecretProviders(database, [onePassword]);
}

describe('1Password secret references', () => {
  const onePassword = provider(async () => ({ stdout: Buffer.from('x'), stderr: '' }));

  it('accepts vault/item/field, a section and a query', () => {
    expect(onePassword.locatorProblem(REFERENCE)).toBeUndefined();
    expect(onePassword.locatorProblem('op://Network/core sw1/TACACS/password')).toBeUndefined();
    expect(onePassword.locatorProblem('op://Network/core-sw1/one-time password?attribute=otp')).toBeUndefined();
  });

  it('rejects anything else before it becomes an argument', () => {
    expect(onePassword.locatorProblem('--help')).toMatch(/op:\/\//);
    expect(onePassword.locatorProblem('op://Network/core-sw1')).toMatch(/vault, an item and a field/);
    expect(onePassword.locatorProblem('op://Network//password')).toMatch(/vault, an item and a field/);
    expect(onePassword.locatorProblem('op://a/b/c/d/e')).toMatch(/vault, an item and a field/);
    const providers = registryFor(onePassword);
    expect(() => providers.checkSecret('onepassword', 'op://Network/core-sw1/pass\nword')).toThrow(
      /characters Muxus cannot use/,
    );
    expect(() => providers.checkSecret('onepassword', `op://v/i/${'f'.repeat(1100)}`)).toThrow(/too long/);
  });

  it('keeps an account from reading as a flag, and wants a full CLI path', () => {
    expect(onePassword.optionProblem('account', 'my.1password.com')).toBeUndefined();
    expect(onePassword.optionProblem('account', '--session')).toMatch(/dash/);
    expect(onePassword.settingProblem('cliPath', '/opt/op')).toBeUndefined();
    expect(onePassword.settingProblem('cliPath', 'op')).toBe('Enter the full path to the 1Password CLI.');
  });
});

describe('OnePasswordProvider', () => {
  it('runs op read without a newline and returns the value', async () => {
    const calls: Array<{ file: string; args: readonly string[] }> = [];
    const onePassword = provider(async (file, args) => {
      calls.push({ file, args });
      return { stdout: Buffer.from('s3cret!'), stderr: '' };
    });
    await expect(read(onePassword)).resolves.toBe('s3cret!');
    await expect(read(onePassword, REFERENCE, { account: 'work.1password.com' })).resolves.toBe('s3cret!');
    expect(calls).toEqual([
      { file: '/usr/bin/op', args: ['read', '--no-newline', REFERENCE] },
      { file: '/usr/bin/op', args: ['read', '--no-newline', '--account', 'work.1password.com', REFERENCE] },
    ]);
  });

  it('never runs anything for a malformed reference or account', async () => {
    let ran = false;
    const providers = registryFor(
      provider(async () => {
        ran = true;
        return { stdout: Buffer.from('x'), stderr: '' };
      }),
    );
    await problemOf(providers.read('onepassword', { locator: '--version' }));
    await problemOf(providers.read('onepassword', { locator: REFERENCE, options: { account: '--debug' } }));
    expect(ran).toBe(false);
  });

  it('says when the CLI cannot be found', async () => {
    const err = await problemOf(read(provider(async () => ({ stdout: Buffer.from('x'), stderr: '' }), [])));
    expect(err.problem).toBe('not-installed');
    expect(err.message).toBe('The 1Password CLI (op) is not installed, or Muxus cannot find it.');
  });

  it('finds op in the usual install folders when PATH lacks it', () => {
    expect(knownLocations('darwin', {})).toContain('/usr/local/bin/op');
    expect(knownLocations('darwin', {})).toContain('/opt/homebrew/bin/op');
    expect(knownLocations('linux', {})).toContain('/usr/bin/op');
    const windows = knownLocations('win32', {
      LOCALAPPDATA: 'C:\\Users\\a\\AppData\\Local',
      ProgramFiles: 'C:\\Program Files',
    });
    expect(windows).toContain('C:\\Users\\a\\AppData\\Local\\Microsoft\\WinGet\\Links\\op.exe');
    expect(windows).toContain(
      'C:\\Users\\a\\AppData\\Local\\Microsoft\\WinGet\\Packages\\AgileBits.1Password.CLI_Microsoft.Winget.Source_8wekyb3d8bbwe\\op.exe',
    );
    expect(windows).toContain('C:\\Program Files\\1Password CLI\\op.exe');
  });

  it('looks for op.exe on the Windows PATH', async () => {
    const calls: string[] = [];
    const onePassword = new OnePasswordProvider({
      platform: 'win32',
      env: { Path: 'C:\\Tools;"C:\\Program Files\\1Password CLI"' },
      isFile: (file) => file === 'C:\\Program Files\\1Password CLI\\op.exe',
      run: async (file) => {
        calls.push(file);
        return { stdout: Buffer.from('v'), stderr: '' };
      },
    });
    await read(onePassword);
    expect(calls).toEqual(['C:\\Program Files\\1Password CLI\\op.exe']);
  });

  it('uses a configured path and nothing else', async () => {
    const calls: string[] = [];
    const onePassword = provider(async (file) => {
      calls.push(file);
      return { stdout: Buffer.from('v'), stderr: '' };
    });
    const err = await problemOf(read(onePassword, REFERENCE, { cliPath: '/opt/tools/op' }));
    expect(err.problem).toBe('not-installed');
    expect(err.message).toBe('The 1Password CLI was not found at /opt/tools/op.');
    expect(calls).toEqual([]);
  });

  it.each([
    ['[ERROR] 2026/10/09 10:00:00 account is not signed in', 'locked'],
    [UNREACHABLE, 'unreachable'],
    ['[ERROR] 2026/10/09 22:41:45 read: context deadline exceeded', 'timeout'],
    ['[ERROR] 2026/10/09 10:00:00 authorization prompt dismissed, please try again', 'denied'],
    [`[ERROR] 2026/10/09 10:00:00 could not read secret '${REFERENCE}': "core-sw1" isn't an item in the "Network" vault`, 'not-found'],
    ['[ERROR] 2026/10/09 10:00:00 something unexpected', 'failed'],
  ])('explains %s', async (stderr, problem) => {
    const err = await problemOf(
      read(
        provider(async () => {
          throw failure(stderr);
        }),
      ),
    );
    expect(err.problem).toBe(problem);
    expect(err.message).not.toContain('[ERROR]');
    // The user knows which reference failed; the message keeps to the cause.
    expect(err.message).not.toContain('could not read secret');
  });

  it('tries once more when the 1Password app could not be reached', async () => {
    let calls = 0;
    const flaky = provider(async () => {
      calls++;
      if (calls === 1) throw failure(UNREACHABLE);
      return { stdout: Buffer.from('v'), stderr: '' };
    });
    await expect(read(flaky)).resolves.toBe('v');
    expect(calls).toBe(2);

    calls = 0;
    const down = provider(async () => {
      calls++;
      throw failure(UNREACHABLE);
    });
    const err = await problemOf(read(down));
    expect(err.problem).toBe('unreachable');
    expect(err.message).toMatch(/^Muxus could not reach the 1Password app\./);
    expect(err.message).toContain('connecting to desktop app timed out');
    expect(calls).toBe(2);

    // Other failures are not retried.
    calls = 0;
    const denied = provider(async () => {
      calls++;
      throw failure('[ERROR] 2026/10/09 10:00:00 authorization prompt dismissed');
    });
    await problemOf(read(denied));
    expect(calls).toBe(1);
  });

  it('stops retrying when the read is cancelled', async () => {
    const controller = new AbortController();
    let calls = 0;
    const onePassword = new OnePasswordProvider({
      platform: 'linux',
      env: { PATH: '/usr/bin' },
      isFile: (file) => file === '/usr/bin/op',
      retryDelayMs: 60_000,
      run: async () => {
        calls++;
        throw failure(UNREACHABLE);
      },
    });
    const pending = read(onePassword, REFERENCE, { signal: controller.signal });
    await new Promise((resolve) => setTimeout(resolve, 10));
    controller.abort();
    expect((await problemOf(pending)).problem).toBe('cancelled');
    expect(calls).toBe(1);
  });

  it('reports a timeout, a field too long, and an empty field', async () => {
    const timedOut = provider(async () => {
      throw failure('', { killed: true, signal: 'SIGTERM', code: null });
    });
    expect((await problemOf(read(timedOut))).problem).toBe('timeout');

    const tooLong = provider(async () => {
      throw failure('', { code: 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER' });
    });
    expect((await problemOf(read(tooLong))).message).toBe('The 1Password field is too long to type.');

    const providers = registryFor(provider(async () => ({ stdout: Buffer.alloc(0), stderr: '' })));
    expect((await problemOf(providers.read('onepassword', { locator: REFERENCE }))).message).toBe(
      '1Password gave an empty value.',
    );
  });

  it('reports its version and where it found the CLI, or why it is unavailable', async () => {
    let versions = 0;
    const available = provider(async () => {
      versions++;
      return { stdout: Buffer.from('2.32.0\n'), stderr: '' };
    });
    await expect(available.status({ settings: {}, refresh: false })).resolves.toEqual({
      available: true,
      summary: 'Found the 1Password CLI 2.32.0 at /usr/bin/op.',
      detected: { cliPath: '/usr/bin/op' },
    });
    // Cached until refreshed or the configured path changes.
    await available.status({ settings: {}, refresh: false });
    expect(versions).toBe(1);
    await available.status({ settings: {}, refresh: true });
    expect(versions).toBe(2);
    await expect(available.status({ settings: { cliPath: '/opt/op' }, refresh: false })).resolves.toEqual({
      available: false,
      summary: 'The 1Password CLI was not found at /opt/op.',
    });

    const missing = provider(async () => ({ stdout: Buffer.from(''), stderr: '' }), []);
    await expect(missing.status({ settings: {}, refresh: false })).resolves.toEqual({
      available: false,
      summary: 'The 1Password CLI (op) is not installed, or Muxus cannot find it.',
    });
  });
});

describe('OnePasswordProvider with a real executable', () => {
  let directory: string;

  beforeEach(() => {
    directory = mkdtempSync(path.join(os.tmpdir(), 'muxus-op-'));
  });

  afterEach(() => {
    rmSync(directory, { recursive: true, force: true });
  });

  it.skipIf(process.platform === 'win32')('passes the arguments without a shell', async () => {
    const op = path.join(directory, 'op');
    // Echoes its arguments back, the way a shell never would.
    writeFileSync(op, '#!/bin/sh\nfor arg in "$@"; do printf "%s|" "$arg"; done\n');
    chmodSync(op, 0o755);
    const onePassword = new OnePasswordProvider({ env: { PATH: directory } });
    const reference = 'op://Net work/sw $(id)/pass;word';
    await expect(read(onePassword, reference)).resolves.toBe(`read|--no-newline|${reference}|`);
    await expect(onePassword.status({ settings: {}, refresh: true })).resolves.toEqual({
      available: true,
      summary: `Found the 1Password CLI --version| at ${op}.`,
      detected: { cliPath: op },
    });
  });

  it.skipIf(process.platform === 'win32')('turns a non-zero exit into an explanation', async () => {
    const op = path.join(directory, 'op');
    writeFileSync(
      op,
      '#!/bin/sh\necho "[ERROR] 2026/10/09 10:00:00 no accounts configured for use with 1Password CLI" >&2\nexit 1\n',
    );
    chmodSync(op, 0o755);
    const err = await problemOf(read(new OnePasswordProvider({ env: { PATH: directory } })));
    expect(err.problem).toBe('locked');
    expect(err.message).toContain('no accounts configured');
  });
});
