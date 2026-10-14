import type {
  ExternalSecretTestRequest,
  SecretProviderInfo,
  SecretProvidersResponse,
} from '@muxus/shared';
import { apiFetch } from './http.js';

const JSON_HEADERS = { 'content-type': 'application/json' };

/** The password managers Muxus can ask; `refresh` skips the providers' short status caches. */
export function fetchSecretProviders(refresh = false): Promise<SecretProvidersResponse> {
  return apiFetch<SecretProvidersResponse>(`/api/secret-providers${refresh ? '?refresh=1' : ''}`);
}

/** Change a provider's settings; an empty or null value unsets one. */
export function saveSecretProviderSettings(
  id: string,
  settings: Record<string, string | null>,
): Promise<SecretProviderInfo> {
  return apiFetch<SecretProviderInfo>(`/api/secret-providers/${encodeURIComponent(id)}/settings`, {
    method: 'PUT',
    headers: JSON_HEADERS,
    body: JSON.stringify({ settings }),
  });
}

/**
 * Ask the provider for the value and throw it away: resolves when it could
 * provide it. The provider may wait minutes for the user's approval, so the
 * caller can give up early through `signal`.
 */
export function testExternalSecret(
  id: string,
  request: ExternalSecretTestRequest,
  { signal }: { signal?: AbortSignal } = {},
): Promise<{ ok: true }> {
  return apiFetch<{ ok: true }>(`/api/secret-providers/${encodeURIComponent(id)}/test`, {
    method: 'POST',
    headers: JSON_HEADERS,
    body: JSON.stringify(request),
    signal,
  });
}
