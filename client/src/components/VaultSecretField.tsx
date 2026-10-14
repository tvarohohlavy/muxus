import { useState } from 'react';
import Box from '@mui/material/Box';
import Link from '@mui/material/Link';
import ListItemIcon from '@mui/material/ListItemIcon';
import MenuItem from '@mui/material/MenuItem';
import TextField from '@mui/material/TextField';
import type { SxProps, Theme } from '@mui/material/styles';
import AddIcon from '@mui/icons-material/Add';
import { useQueryClient } from '@tanstack/react-query';
import type { PasswordVaultSecret, VaultSecretSaveResult } from '@muxus/shared';
import { usePasswordVaultStatus, useSecretProviders } from '../api/password-vault-queries.js';
import { useUiStore } from '../state/ui.js';
import { vaultSecretMissing } from '../vault-secrets.js';
import { ExternalSecretDialog } from './ExternalSecretDialog.js';
import { VaultSecretDialog } from './VaultSecretDialog.js';

const NEW_SECRET = '\u0000new-secret';
/** Followed by the provider's ID. */
const NEW_EXTERNAL_SECRET = '\u0000new-external-secret:';
const MISSING_SECRET = '\u0000missing-secret';
const NO_SECRET = '\u0000no-secret';

/** Who holds a secret's value, for the picker: its user name and the password manager. */
function secretDetail(secret: PasswordVaultSecret): string {
  return [secret.username, secret.external?.providerLabel].filter(Boolean).join(' · ');
}

/**
 * Pick a named secret, from the password vault or a password manager, or
 * add one on the spot. Only the secret's id is handed out; a reference whose
 * secret was deleted shows as missing until another is picked. Meant for any
 * editor that stores a secret reference: command buttons, login steps, a
 * host's login password. With `noneLabel`, choosing nothing is allowed and
 * hands out ''.
 */
export function VaultSecretField({
  value,
  onChange,
  label = 'Secret',
  helperText,
  noneLabel,
  disabled = false,
  fullWidth = true,
  size,
  sx,
}: {
  value: string | undefined;
  onChange: (secretId: string) => void;
  label?: string;
  helperText?: React.ReactNode;
  /** Offer an empty choice with this label. */
  noneLabel?: string;
  disabled?: boolean;
  fullWidth?: boolean;
  size?: 'small' | 'medium';
  sx?: SxProps<Theme>;
}) {
  const queryClient = useQueryClient();
  const { data: status, isLoading } = usePasswordVaultStatus();
  const { data: providerList } = useSecretProviders();
  const openSettings = useUiStore((state) => state.openSettings);
  /** NEW_SECRET for the vault, else the ID of the provider a secret is being added to. */
  const [adding, setAdding] = useState<string>();
  const secrets = status?.secrets ?? [];
  const providers = providerList?.providers ?? [];
  const missing = !!value && vaultSecretMissing(status, value) === true;
  const configured = status?.configured ?? true;
  // A password manager's secrets need no vault, so the field works without one.
  const usable = configured || providers.length > 0 || secrets.length > 0;
  const addingProvider = providers.find((provider) => provider.descriptor.id === adding);

  const hint = missing ? (
    'This secret was deleted. Pick another one.'
  ) : !configured && secrets.length === 0 ? (
    <>
      {providers.length > 0
        ? `Add a secret from ${providers.map((provider) => provider.descriptor.label).join(' or ')} here, or create the password vault under `
        : 'Secrets live in the password vault. Create it under '}
      <Link
        component="button"
        type="button"
        variant="caption"
        onClick={() => openSettings({ section: 'passwords' })}
        sx={{ verticalAlign: 'baseline' }}
      >
        Settings → Passwords
      </Link>
      .
    </>
  ) : (
    helperText
  );

  const saved = (result: VaultSecretSaveResult) => {
    queryClient.setQueryData(['password-vault'], result.status);
    setAdding(undefined);
    onChange(result.secret.id);
  };

  return (
    <>
      <TextField
        select
        label={label}
        size={size}
        fullWidth={fullWidth}
        disabled={disabled || isLoading || !usable}
        error={missing}
        helperText={hint}
        value={missing ? MISSING_SECRET : value || (noneLabel !== undefined ? NO_SECRET : '')}
        onChange={(event) => {
          const next = event.target.value;
          if (next === NEW_SECRET) setAdding(NEW_SECRET);
          else if (next.startsWith(NEW_EXTERNAL_SECRET)) setAdding(next.slice(NEW_EXTERNAL_SECRET.length));
          else if (next === NO_SECRET) onChange('');
          else if (next !== MISSING_SECRET) onChange(next);
        }}
        slotProps={{
          // The empty value shows a placeholder, so the label always sits on the outline.
          inputLabel: { shrink: true },
          select: {
            displayEmpty: true,
            renderValue: (selected) => {
              if (selected === MISSING_SECRET) return 'Missing secret';
              if (selected === NO_SECRET) return noneLabel;
              const secret = secrets.find((candidate) => candidate.id === selected);
              if (!secret) {
                return (
                  <Box component="span" sx={{ color: 'text.secondary' }}>
                    Choose a secret
                  </Box>
                );
              }
              const detail = secretDetail(secret);
              return detail ? `${secret.name} · ${detail}` : secret.name;
            },
          },
        }}
        sx={sx}
      >
        {missing ? (
          <MenuItem value={MISSING_SECRET} disabled>
            Missing secret
          </MenuItem>
        ) : null}
        {noneLabel !== undefined ? <MenuItem value={NO_SECRET}>{noneLabel}</MenuItem> : null}
        {secrets.map((secret) => {
          const detail = secretDetail(secret);
          return (
            <MenuItem key={secret.id} value={secret.id}>
              <Box component="span" sx={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>
                {secret.name}
              </Box>
              {detail ? (
                <Box component="span" sx={{ ml: 1.5, color: 'text.secondary', fontSize: 13 }}>
                  {detail}
                </Box>
              ) : null}
            </MenuItem>
          );
        })}
        {configured ? (
          <MenuItem value={NEW_SECRET}>
            <ListItemIcon>
              <AddIcon fontSize="small" />
            </ListItemIcon>
            New secret…
          </MenuItem>
        ) : null}
        {providers.map((provider) => (
          <MenuItem
            key={provider.descriptor.id}
            value={`${NEW_EXTERNAL_SECRET}${provider.descriptor.id}`}
          >
            <ListItemIcon>
              <AddIcon fontSize="small" />
            </ListItemIcon>
            New secret from {provider.descriptor.label}…
          </MenuItem>
        ))}
      </TextField>
      {adding === NEW_SECRET ? (
        <VaultSecretDialog onClose={() => setAdding(undefined)} onSaved={saved} />
      ) : null}
      {addingProvider ? (
        <ExternalSecretDialog
          provider={addingProvider}
          onClose={() => setAdding(undefined)}
          onSaved={saved}
        />
      ) : null}
    </>
  );
}
