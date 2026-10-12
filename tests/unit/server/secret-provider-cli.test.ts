import { describe, expect, it } from 'vitest';
import {
  absolutePathProblem,
  cliFailureProblem,
  failureStderr,
  findExecutable,
  lastErrorLine,
  runCli,
  valueFromStdout,
} from '../../../server/src/secret-providers/cli.js';

describe('findExecutable', () => {
  const files = (...paths: string[]) => (file: string) => paths.includes(file);

  it('takes the configured path only when it is a file', () => {
    const isFile = files('/opt/tool/op', '/usr/bin/op');
    const env = { PATH: '/usr/bin' };
    expect(findExecutable('op', { configured: ' /opt/tool/op ', env, isFile, platform: 'linux' })).toBe(
      '/opt/tool/op',
    );
    // A wrong configured path is not quietly replaced by another copy.
    expect(findExecutable('op', { configured: '/nowhere/op', env, isFile, platform: 'linux' })).toBeUndefined();
  });

  it('looks on PATH, skipping relative entries, then in the usual places', () => {
    expect(
      findExecutable('op', {
        env: { PATH: 'bin:/usr/local/bin:/usr/bin' },
        isFile: files('bin/op', '/usr/bin/op'),
        platform: 'linux',
      }),
    ).toBe('/usr/bin/op');
    expect(
      findExecutable('op', {
        env: { PATH: '/usr/bin' },
        knownLocations: ['/opt/homebrew/bin/op', '/usr/local/bin/op'],
        isFile: files('/usr/local/bin/op'),
        platform: 'darwin',
      }),
    ).toBe('/usr/local/bin/op');
    expect(findExecutable('op', { env: {}, isFile: files(), platform: 'linux' })).toBeUndefined();
  });

  it('reads a Windows PATH, quotes and all, and adds .exe', () => {
    expect(
      findExecutable('op', {
        env: { Path: 'C:\\Windows;"C:\\Program Files\\1Password CLI"' },
        isFile: files('C:\\Program Files\\1Password CLI\\op.exe'),
        platform: 'win32',
      }),
    ).toBe('C:\\Program Files\\1Password CLI\\op.exe');
  });
});

describe('running a CLI', () => {
  it('collects what the program prints', async () => {
    const { stdout } = await runCli(process.execPath, ['-e', 'process.stdout.write("s3cret\\n")'], {
      timeout: 10_000,
    });
    expect(valueFromStdout(stdout, { trimNewline: true })).toBe('s3cret');
    // The buffer is wiped once the value is out.
    expect(stdout.every((byte) => byte === 0)).toBe(true);
  });

  it('rejects with the program’s stderr, and wipes what it printed', async () => {
    const error = await runCli(
      process.execPath,
      ['-e', 'process.stdout.write("half"); console.error("[ERROR] first\\n\\u001b[31mdenied\\u001b[0m"); process.exit(3)'],
      { timeout: 10_000 },
    ).then(
      () => undefined,
      (err: unknown) => err,
    );
    expect(cliFailureProblem(error)).toBeUndefined();
    expect(lastErrorLine(failureStderr(error))).toBe('[31mdenied [0m');
  });

  it('sorts out failures that need no stderr', async () => {
    const missing = await runCli('/nonexistent/muxus-tool', [], { timeout: 10_000 }).catch(
      (err: unknown) => err,
    );
    expect(cliFailureProblem(missing)).toBe('not-installed');

    const slow = await runCli(process.execPath, ['-e', 'setTimeout(() => {}, 10_000)'], {
      timeout: 200,
    }).catch((err: unknown) => err);
    expect(cliFailureProblem(slow)).toBe('timeout');

    const controller = new AbortController();
    const cancelled = runCli(process.execPath, ['-e', 'setTimeout(() => {}, 10_000)'], {
      timeout: 10_000,
      signal: controller.signal,
    }).catch((err: unknown) => err);
    controller.abort();
    expect(cliFailureProblem(await cancelled)).toBe('cancelled');

    const chatty = await runCli(process.execPath, ['-e', 'process.stdout.write("x".repeat(200_000))'], {
      timeout: 10_000,
    }).catch((err: unknown) => err);
    expect(cliFailureProblem(chatty)).toBe('failed');
  });

  it('keeps a value as printed unless asked to drop the line break', () => {
    expect(valueFromStdout(Buffer.from('a b\n'))).toBe('a b\n');
    expect(valueFromStdout(Buffer.from('a b\r\n'), { trimNewline: true })).toBe('a b');
    expect(valueFromStdout(Buffer.from('a b\n\n'), { trimNewline: true })).toBe('a b\n');
  });

  it('reads the last line a program wrote to stderr', () => {
    expect(lastErrorLine('')).toBe('');
    expect(lastErrorLine('first\n  second  \n\n')).toBe('second');
  });

  it('wants a full path for a CLI location', () => {
    expect(absolutePathProblem('/usr/bin/op', 'the CLI')).toBeUndefined();
    expect(absolutePathProblem('op', 'the CLI')).toBe('Enter the full path to the CLI.');
  });
});
