import { execFile } from 'node:child_process';
import { statSync } from 'node:fs';
import path from 'node:path';
import type { SecretProviderProblem } from './provider.js';

/**
 * Helpers for providers that run a password manager's command-line tool.
 * No shell is involved: arguments go to the program as they are.
 */

/** Output a password manager's CLI may print; a secret is far smaller. */
const OUTPUT_MAX_BYTES = 64 * 1024;
const DETAIL_MAX_LENGTH = 240;

export interface CliRunResult {
  stdout: Buffer;
  stderr: string;
}

export type CliRunner = (
  file: string,
  args: readonly string[],
  options: { timeout: number; signal?: AbortSignal },
) => Promise<CliRunResult>;

/**
 * Run a program and collect its output. Rejects with the child's error,
 * carrying its `stderr`, for `cliFailureProblem` and `lastErrorLine`.
 * Standard output is wiped on failure: it may hold part of a secret.
 */
export const runCli: CliRunner = (file, args, options) =>
  new Promise((resolve, reject) => {
    execFile(
      file,
      [...args],
      {
        encoding: 'buffer',
        timeout: options.timeout,
        maxBuffer: OUTPUT_MAX_BYTES,
        windowsHide: true,
        signal: options.signal,
      },
      (error, stdout, stderr) => {
        const stderrText = stderr.toString('utf8');
        if (error) {
          stdout.fill(0);
          reject(Object.assign(error, { stderr: stderrText }));
        } else {
          resolve({ stdout, stderr: stderrText });
        }
      },
    );
  });

/**
 * What a failed run shows without reading the program's own words: it is
 * missing, it was cancelled, it ran out of time, or it printed too much.
 * Undefined when it ran and failed; its `stderr` then says why.
 */
export function cliFailureProblem(
  err: unknown,
): Extract<SecretProviderProblem, 'not-installed' | 'cancelled' | 'timeout' | 'failed'> | undefined {
  const error = err as NodeJS.ErrnoException & { killed?: boolean };
  if (error.code === 'ENOENT' || error.code === 'EACCES') return 'not-installed';
  if (error.name === 'AbortError' || error.code === 'ABORT_ERR') return 'cancelled';
  if (error.killed) return 'timeout';
  if (error.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER') return 'failed';
  return undefined;
}

/** The stderr a failed run carried, if any. */
export function failureStderr(err: unknown): string {
  const stderr = (err as { stderr?: unknown }).stderr;
  return typeof stderr === 'string' ? stderr : '';
}

/** The last line a program wrote to stderr, made printable; empty when there is none. */
export function lastErrorLine(stderr: string): string {
  const line = stderr
    .split(/\r?\n/)
    .map((text) => text.trim())
    .filter(Boolean)
    .at(-1);
  return line ? line.replace(/\p{Cc}+/gu, ' ').trim() : '';
}

/** A detail short enough to quote in a message. */
export function clipDetail(text: string, maxLength = DETAIL_MAX_LENGTH): string {
  return text.length > maxLength ? `${text.slice(0, maxLength - 1)}…` : text;
}

/**
 * The value a program printed, as text, with the buffer wiped afterwards.
 * `trimNewline` drops one line break at the end, which most tools add.
 */
export function valueFromStdout(stdout: Buffer, options: { trimNewline?: boolean } = {}): string {
  try {
    const text = stdout.toString('utf8');
    return options.trimNewline ? text.replace(/\r?\n$/, '') : text;
  } finally {
    stdout.fill(0);
  }
}

/**
 * Where a program is: the configured path when it is a file, else the first
 * match on PATH, else the first of `knownLocations` that exists. PATH is read
 * at each call because the desktop app imports it from the login shell after
 * it starts. `name` is without ".exe"; Windows adds it.
 */
export function findExecutable(
  name: string,
  options: {
    configured?: string;
    knownLocations?: readonly string[];
    platform?: NodeJS.Platform;
    env?: NodeJS.ProcessEnv;
    isFile?: (file: string) => boolean;
  } = {},
): string | undefined {
  const isFile = options.isFile ?? isRegularFile;
  const configured = options.configured?.trim();
  if (configured) return isFile(configured) ? configured : undefined;
  const platform = options.platform ?? process.platform;
  const env = options.env ?? process.env;
  const pathApi = platform === 'win32' ? path.win32 : path.posix;
  const fileName = platform === 'win32' ? `${name}.exe` : name;
  const searchPath = env.PATH ?? env.Path ?? '';
  for (const entry of searchPath.split(platform === 'win32' ? ';' : ':')) {
    const directory = entry.trim().replace(/^"(.*)"$/, '$1');
    if (!directory || !pathApi.isAbsolute(directory)) continue;
    const candidate = pathApi.join(directory, fileName);
    if (isFile(candidate)) return candidate;
  }
  return options.knownLocations?.find((candidate) => isFile(candidate));
}

export function isRegularFile(file: string): boolean {
  try {
    return statSync(file).isFile();
  } catch {
    return false;
  }
}

/** Whether a setting is a full path a CLI could live at. */
export function absolutePathProblem(value: string, what: string): string | undefined {
  return path.isAbsolute(value) ? undefined : `Enter the full path to ${what}.`;
}
