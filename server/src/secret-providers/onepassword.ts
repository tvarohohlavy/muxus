import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import type { SecretProviderDescriptor, SecretProviderStatus } from '@muxus/shared';
import {
  absolutePathProblem,
  cliFailureProblem,
  clipDetail,
  failureSignal,
  failureStderr,
  findExecutable,
  isRegularFile,
  lastErrorLine,
  runCli,
  valueFromStdout,
  type CliRunner,
} from './cli.js';
import {
  SecretProviderError,
  type SecretProvider,
  type SecretReadContext,
  type SecretReadRequest,
} from './provider.js';

/** A read may wait on the 1Password app's approval prompt (Touch ID, Windows Hello, system password). */
const READ_TIMEOUT_MS = 120_000;
const VERSION_TIMEOUT_MS = 10_000;
const STATUS_TTL_MS = 30_000;
/**
 * The CLI gives up after a few seconds when it cannot reach the 1Password
 * app, which happens while the app is still waking up. One more try after a
 * pause usually gets through.
 */
const UNREACHABLE_RETRY_DELAY_MS = 2_000;

export const ONEPASSWORD_DESCRIPTOR: SecretProviderDescriptor = {
  id: 'onepassword',
  label: '1Password',
  description:
    'Secrets added from 1Password stay there: Muxus keeps only their secret reference and reads the value through the 1Password CLI (op) each time. Install the CLI, then turn on “Integrate with 1Password CLI” under Settings → Developer in the 1Password app, which then asks you to approve Muxus.',
  locator: {
    label: 'Secret reference',
    placeholder: 'op://Network/core-sw1/password',
    help: 'In 1Password, open the item and choose Copy Secret Reference from the field’s menu: op://vault/item/field, or op://vault/item/section/field. Add ?attribute=otp for a one-time code.',
  },
  options: [
    {
      key: 'account',
      label: '1Password account',
      placeholder: 'my.1password.com',
      help: 'Only needed when you are signed in to more than one account: its sign-in address or ID.',
    },
  ],
  settings: [
    {
      key: 'cliPath',
      label: 'CLI location',
      placeholder: 'Automatic',
      help: 'Leave empty to look on PATH and in the folders the installers use.',
    },
  ],
};

/**
 * Reads 1Password secret references with the 1Password CLI (`op`). The CLI
 * does the signing in: with "Integrate with 1Password CLI" turned on in the
 * 1Password app, the app asks the user to approve Muxus (Touch ID, Windows
 * Hello or the system password); a service account token in
 * OP_SERVICE_ACCOUNT_TOKEN works too. A reference and an account are checked
 * before they become arguments, and no shell is involved.
 */
export class OnePasswordProvider implements SecretProvider {
  readonly descriptor = ONEPASSWORD_DESCRIPTOR;
  private readonly run: CliRunner;
  private cachedStatus:
    | { at: number; cliPath: string | undefined; status: SecretProviderStatus }
    | undefined;

  constructor(
    private readonly options: {
      run?: CliRunner;
      platform?: NodeJS.Platform;
      env?: NodeJS.ProcessEnv;
      isFile?: (file: string) => boolean;
      readTimeoutMs?: number;
      /** Test seam; production waits UNREACHABLE_RETRY_DELAY_MS. */
      retryDelayMs?: number;
    } = {},
  ) {
    this.run = options.run ?? runCli;
  }

  /**
   * Why a reference cannot be used. A reference names a field, never holds
   * its value: `op://<vault>/<item>/[<section>/]<field>`, optionally with a
   * query such as `?attribute=otp`. Only the shape is checked; 1Password
   * resolves it.
   */
  locatorProblem(reference: string): string | undefined {
    if (!reference.startsWith('op://')) return 'A secret reference starts with op://';
    const pathPart = reference.slice('op://'.length).split('?')[0] ?? '';
    const segments = pathPart.split('/');
    if (segments.length < 3 || segments.length > 4 || segments.some((segment) => !segment.trim())) {
      return 'A secret reference names a vault, an item and a field: op://vault/item/field';
    }
    return undefined;
  }

  optionProblem(key: string, value: string): string | undefined {
    // The account follows --account as its own argument; a leading dash would read as a flag.
    if (key === 'account' && value.startsWith('-')) return 'An account cannot start with a dash.';
    return undefined;
  }

  settingProblem(key: string, value: string): string | undefined {
    return key === 'cliPath' ? absolutePathProblem(value, 'the 1Password CLI') : undefined;
  }

  /** Whether the CLI can be found and answers `op --version`; cached briefly unless refreshed. */
  async status({
    settings,
    refresh,
  }: {
    settings: Readonly<Record<string, string>>;
    refresh: boolean;
  }): Promise<SecretProviderStatus> {
    const configured = settings.cliPath;
    const cached = this.cachedStatus;
    if (
      !refresh &&
      cached &&
      cached.cliPath === configured &&
      Date.now() - cached.at < STATUS_TTL_MS
    ) {
      return cached.status;
    }
    let status: SecretProviderStatus;
    const file = this.locate(configured);
    // Where it was found is shown apart from the sentence: the path is long.
    const detected = file ? { detected: { cliPath: file } } : {};
    if (!file) {
      status = { available: false, summary: missing(configured).message };
    } else {
      try {
        const { stdout } = await this.run(file, ['--version'], { timeout: VERSION_TIMEOUT_MS });
        const version = valueFromStdout(stdout).trim().split(/\r?\n/)[0]?.slice(0, 64);
        status = {
          available: true,
          summary: `Found the 1Password CLI${version ? ` ${version}` : ''}.`,
          ...detected,
        };
      } catch (err) {
        status = { available: false, summary: classify(err, file).message, ...detected };
      }
    }
    this.cachedStatus = { at: Date.now(), cliPath: configured, status };
    return status;
  }

  /** Read one field with `op read`, trying once more when the app could not be reached. */
  async read(request: SecretReadRequest, context: SecretReadContext): Promise<string> {
    const configured = context.settings.cliPath;
    const file = this.locate(configured);
    if (!file) throw missing(configured);
    const account = request.options.account;
    const args = ['read', '--no-newline', ...(account ? ['--account', account] : []), request.locator];
    const { signal } = context;
    for (let attempt = 0; ; attempt++) {
      try {
        const { stdout } = await this.run(file, args, {
          timeout: this.options.readTimeoutMs ?? READ_TIMEOUT_MS,
          signal,
        });
        return valueFromStdout(stdout);
      } catch (err) {
        if (signal?.aborted) throw cancelled();
        const problem = classify(err, file);
        if (problem.problem !== 'unreachable' || attempt > 0) throw problem;
      }
      try {
        await sleep(this.options.retryDelayMs ?? UNREACHABLE_RETRY_DELAY_MS, undefined, { signal });
      } catch {
        throw cancelled();
      }
    }
  }

  /** The configured path, else the first `op` on PATH, else the installers' usual places. */
  private locate(configured: string | undefined): string | undefined {
    const platform = this.options.platform ?? process.platform;
    // Read at each lookup: the desktop app imports PATH from the login shell after startup.
    const env = this.options.env ?? process.env;
    return findExecutable('op', {
      configured,
      knownLocations: knownLocations(platform, env),
      platform,
      env,
      ...(this.options.isFile ? { isFile: this.options.isFile } : {}),
    });
  }
}

/**
 * Where the official installers and the common package managers put `op`
 * when PATH does not say. On Windows that is the installer, WinGet (per user
 * and for the machine) and Scoop; Chocolatey's bin is on PATH already, and
 * nothing under ProgramData is tried: any local user may create a path there.
 */
export function knownLocations(platform: NodeJS.Platform, env: NodeJS.ProcessEnv): string[] {
  if (platform === 'win32') {
    const join = (...parts: string[]) => path.win32.join(...parts);
    const localAppData = env.LOCALAPPDATA;
    const programFiles = env.ProgramFiles ?? env.PROGRAMFILES;
    const userProfile = env.USERPROFILE;
    const wingetPackage = 'AgileBits.1Password.CLI_Microsoft.Winget.Source_8wekyb3d8bbwe';
    return [
      localAppData && join(localAppData, 'Microsoft', 'WinGet', 'Links', 'op.exe'),
      localAppData && join(localAppData, 'Microsoft', 'WinGet', 'Packages', wingetPackage, 'op.exe'),
      programFiles && join(programFiles, 'WinGet', 'Links', 'op.exe'),
      programFiles && join(programFiles, 'WinGet', 'Packages', wingetPackage, 'op.exe'),
      programFiles && join(programFiles, '1Password CLI', 'op.exe'),
      userProfile && join(userProfile, 'scoop', 'apps', '1password-cli', 'current', 'op.exe'),
    ].filter((candidate): candidate is string => !!candidate);
  }
  if (platform === 'darwin') {
    return ['/usr/local/bin/op', '/opt/homebrew/bin/op', '/opt/local/bin/op'];
  }
  return ['/usr/bin/op', '/usr/local/bin/op'];
}

function cancelled(): SecretProviderError {
  return new SecretProviderError('cancelled', 'Cancelled.');
}

/**
 * Why there is no CLI to run: nothing was found, or the configured path
 * names a file that may not be run, which is worth saying so the user fixes
 * the file rather than the path.
 */
function missing(configured: string | undefined): SecretProviderError {
  if (!configured) {
    return new SecretProviderError(
      'not-installed',
      'The 1Password CLI (op) is not installed, or Muxus cannot find it.',
    );
  }
  // The search strips the quotes Explorer's "Copy as path" adds; so does this.
  const file = configured.trim().replace(/^"(.*)"$/, '$1');
  if (isRegularFile(file)) return cannotRun(file);
  return new SecretProviderError('not-installed', `The 1Password CLI was not found at ${file}.`);
}

function cannotRun(file: string): SecretProviderError {
  return new SecretProviderError('failed', `Muxus found the 1Password CLI at ${file} but could not run it.`);
}

/** Turn a failed run of the CLI at `file` into a SecretProviderError with a message for the user. */
function classify(err: unknown, file: string): SecretProviderError {
  if (err instanceof SecretProviderError) return err;
  switch (cliFailureProblem(err)) {
    case 'not-installed':
      return missing(undefined);
    case 'not-executable':
      return cannotRun(file);
    case 'cancelled':
      return cancelled();
    case 'timeout':
      return new SecretProviderError(
        'timeout',
        '1Password did not answer in time. Approve Muxus in the 1Password app, then try again.',
      );
    case 'failed':
      return new SecretProviderError('failed', 'The 1Password field is too long to type.');
    case undefined:
      break;
  }
  const signal = failureSignal(err);
  if (signal) {
    return new SecretProviderError(
      'failed',
      `The 1Password CLI at ${file} was stopped by ${signal} before it answered.`,
    );
  }
  const line = errorLine(failureStderr(err));
  const detail = shortDetail(line);
  const said = detail ? ` 1Password said: “${detail}”` : '';
  if (
    /authori[sz]ation (prompt )?(was )?(dismissed|denied|declined|cancel+ed)|user (cancel+ed|denied|declined)|access (was )?denied/i.test(
      line,
    )
  ) {
    return new SecretProviderError('denied', `1Password did not allow access.${said}`);
  }
  if (/connecting to (the )?desktop app|connect to (the )?1password app|is the 1password app (running|unlocked)/i.test(line)) {
    return new SecretProviderError(
      'unreachable',
      `Muxus could not reach the 1Password app. Make sure it is running and unlocked; op whoami in a terminal should show your account.${said}`,
    );
  }
  if (/context deadline exceeded/i.test(line)) {
    return new SecretProviderError(
      'timeout',
      `1Password did not answer in time. Approve Muxus when the 1Password app asks, then try again.${said}`,
    );
  }
  if (
    /not (currently )?signed in|no accounts? (are )?configured|sign ?in (to|with)|session (has )?expired|error initiali[sz]ing client|app integration/i.test(
      line,
    )
  ) {
    return new SecretProviderError(
      'locked',
      `The 1Password CLI is not signed in. Turn on “Integrate with 1Password CLI” in the 1Password app (Settings → Developer), or sign in with op signin.${said}`,
    );
  }
  if (
    /isn't (an item|a vault|a field|a section)|could not find|not found|no item|does not exist|invalid secret reference|more than one item matches/i.test(
      line,
    )
  ) {
    return new SecretProviderError('not-found', `1Password has nothing at that secret reference.${said}`);
  }
  return new SecretProviderError('failed', `1Password could not read the secret.${said}`);
}

/** op's last error line without its "[ERROR] date time" prefix. */
function errorLine(stderr: string): string {
  return lastErrorLine(stderr)
    .replace(/^\[ERROR\]\s*(\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2}\s*)?/i, '')
    .trim();
}

/** The cause, bounded: the user already knows the reference that failed. */
function shortDetail(line: string): string {
  return clipDetail(
    line
      .replace(/^could not read secret '[^']*':\s*/i, '')
      .replace(/^error initiali[sz]ing client:\s*/i, ''),
  );
}
