import { useQuery } from '@tanstack/react-query';
import type { PasswordVaultStatus, SecretProvidersResponse } from '@muxus/shared';
import { fetchPasswordVaultStatus } from './password-vault.js';
import { fetchSecretProviders } from './secret-providers.js';

/** Feature-local so password-vault code stays out of the initial bundle. */
export function usePasswordVaultStatus(enabled = true) {
  return useQuery<PasswordVaultStatus>({
    queryKey: ['password-vault'],
    queryFn: fetchPasswordVaultStatus,
    enabled,
  });
}

/** The password managers Muxus can ask for named secrets, as the backend last found them. */
export function useSecretProviders(enabled = true) {
  return useQuery<SecretProvidersResponse>({
    queryKey: ['secret-providers'],
    queryFn: () => fetchSecretProviders(),
    enabled,
    staleTime: 30_000,
  });
}
