import { useEffect, useRef, useState } from 'react';
import Alert from '@mui/material/Alert';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import Stack from '@mui/material/Stack';
import TextField from '@mui/material/TextField';
import Typography from '@mui/material/Typography';
import type {
  PasswordVaultSecret,
  SecretProviderInfo,
  VaultSecretSaveResult,
} from '@muxus/shared';
import { createExternalSecret, updateExternalSecret } from '../api/password-vault.js';
import { testExternalSecret } from '../api/secret-providers.js';

const NAME_MAX = 80;
const USERNAME_MAX = 256;

type TestState = { tone: 'success' | 'error' | 'info'; text: string };

/**
 * Add or edit a named secret whose value stays in a password manager. Muxus
 * keeps only where the manager keeps it, so no master password is involved;
 * at each use Muxus asks the manager, which may ask the user to approve. The
 * fields come from the provider's descriptor.
 */
export function ExternalSecretDialog({
  provider,
  secret,
  initialName = '',
  onClose,
  onSaved,
}: {
  provider: SecretProviderInfo;
  /** The secret to edit; absent adds a new one. */
  secret?: PasswordVaultSecret;
  initialName?: string;
  onClose: () => void;
  onSaved: (result: VaultSecretSaveResult) => void;
}) {
  const { descriptor, status } = provider;
  const [name, setName] = useState(secret?.name ?? initialName);
  const [username, setUsername] = useState(secret?.username ?? '');
  const [locator, setLocator] = useState(secret?.external?.locator ?? '');
  const [options, setOptions] = useState<Record<string, string>>(secret?.external?.options ?? {});
  const [error, setError] = useState<string>();
  const [test, setTest] = useState<TestState>();
  /** Set while the secret is being saved. */
  const [busy, setBusy] = useState(false);
  /** Set while the provider is being asked for the value. */
  const [testing, setTesting] = useState(false);
  const firstFieldRef = useRef<HTMLInputElement>(null);
  const testRun = useRef<AbortController>(null);

  useEffect(() => {
    const frame = requestAnimationFrame(() => firstFieldRef.current?.focus());
    return () => cancelAnimationFrame(frame);
  }, []);

  /**
   * Stop waiting for the provider. Its approval prompt may be hidden or
   * ignored for minutes, so the user must always be able to leave; the
   * provider finishes or times out on its own.
   */
  const cancelTest = () => {
    const run = testRun.current;
    if (!run) return;
    testRun.current = null;
    run.abort();
    setTesting(false);
    setTest(undefined);
  };

  useEffect(() => cancelTest, []);

  const close = () => {
    cancelTest();
    onClose();
  };

  /** Only the options with a value; the backend checks them all again. */
  const filledOptions = () =>
    Object.fromEntries(
      Object.entries(options).flatMap(([key, value]) => (value.trim() ? [[key, value.trim()]] : [])),
    );

  const runTest = async () => {
    cancelTest();
    const run = new AbortController();
    testRun.current = run;
    setError(undefined);
    setTesting(true);
    setTest({
      tone: 'info',
      text: `Asking ${descriptor.label}… Approve Muxus in ${descriptor.label} if it asks.`,
    });
    try {
      await testExternalSecret(
        descriptor.id,
        { locator: locator.trim(), options: filledOptions() },
        { signal: run.signal },
      );
      if (testRun.current !== run) return;
      setTest({ tone: 'success', text: `${descriptor.label} provided a value.` });
    } catch (err) {
      // A cancelled or superseded run has nothing to report.
      if (testRun.current !== run) return;
      setTest({ tone: 'error', text: err instanceof Error ? err.message : String(err) });
    } finally {
      if (testRun.current === run) {
        testRun.current = null;
        setTesting(false);
      }
    }
  };

  const save = async () => {
    if (testing) return;
    if (!name.trim()) {
      setError('Give the secret a name.');
      return;
    }
    if (!locator.trim()) {
      setError(`Enter the ${descriptor.locator.label.toLocaleLowerCase()}.`);
      return;
    }
    setBusy(true);
    setError(undefined);
    try {
      const input = {
        provider: descriptor.id,
        name: name.trim(),
        ...(username.trim() ? { username: username.trim() } : {}),
        locator: locator.trim(),
        options: filledOptions(),
      };
      const result = secret
        ? await updateExternalSecret(secret.id, input)
        : await createExternalSecret(input);
      onSaved(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const submitOnEnter = (event: React.KeyboardEvent) => {
    if (event.key === 'Enter') {
      event.preventDefault();
      void save();
    }
  };

  return (
    <Dialog open onClose={busy ? undefined : close} maxWidth="sm" fullWidth>
      <DialogTitle>
        {secret ? `Edit ${descriptor.label} secret` : `Add ${descriptor.label} secret`}
      </DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 0.5 }}>
          <Typography variant="body2" color="textSecondary">
            The value stays in {descriptor.label}. Muxus keeps only where it is and asks{' '}
            {descriptor.label} for it each time it types it.
          </Typography>
          {status.available ? null : (
            <Alert severity="warning" variant="outlined">
              {status.summary} You can still save the secret. Until {descriptor.label} works, Muxus
              asks you to type the value when a login needs it.
            </Alert>
          )}
          {error ? <Alert severity="error">{error}</Alert> : null}
          <TextField
            label="Name"
            value={name}
            inputRef={firstFieldRef}
            onChange={(event) => setName(event.target.value)}
            onKeyDown={submitOnEnter}
            slotProps={{ htmlInput: { maxLength: NAME_MAX } }}
          />
          <TextField
            label="User name (optional)"
            value={username}
            autoComplete="off"
            onChange={(event) => setUsername(event.target.value)}
            onKeyDown={submitOnEnter}
            slotProps={{ htmlInput: { maxLength: USERNAME_MAX, spellCheck: false } }}
          />
          <TextField
            label={descriptor.locator.label}
            placeholder={descriptor.locator.placeholder}
            value={locator}
            autoComplete="off"
            onChange={(event) => {
              setLocator(event.target.value);
              // A test of the old value would answer for the new one.
              cancelTest();
            }}
            onKeyDown={submitOnEnter}
            helperText={descriptor.locator.help}
            slotProps={{ htmlInput: { spellCheck: false } }}
          />
          {descriptor.options.map((field) => (
            <TextField
              key={field.key}
              label={`${field.label} (optional)`}
              placeholder={field.placeholder}
              value={options[field.key] ?? ''}
              autoComplete="off"
              onChange={(event) => {
                setOptions((current) => ({ ...current, [field.key]: event.target.value }));
                cancelTest();
              }}
              onKeyDown={submitOnEnter}
              helperText={field.help}
              slotProps={{ htmlInput: { spellCheck: false } }}
            />
          ))}
          {test ? (
            <Alert severity={test.tone} variant="outlined">
              {test.text}
            </Alert>
          ) : null}
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button
          disabled={busy || testing || !locator.trim()}
          onClick={() => void runTest()}
          sx={{ mr: 'auto' }}
        >
          Test
        </Button>
        <Button disabled={busy} onClick={close}>
          Cancel
        </Button>
        <Button variant="contained" disabled={busy || testing} onClick={() => void save()}>
          Save secret
        </Button>
      </DialogActions>
    </Dialog>
  );
}
