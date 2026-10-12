/**
 * Secret providers: password managers Muxus asks for a value at the moment it
 * types it. A named secret from a provider stores only where the manager keeps
 * the value (its locator), never the value itself.
 */

/** Longest locator Muxus stores, in characters. */
export const EXTERNAL_SECRET_LOCATOR_MAX_LENGTH = 1024;
/** Longest per-secret option value, in characters. */
export const EXTERNAL_SECRET_OPTION_MAX_LENGTH = 256;
/** Longest provider setting value, in characters. */
export const SECRET_PROVIDER_SETTING_MAX_LENGTH = 4096;

/** A text field a provider asks for: per secret (options) or once (settings). */
export interface SecretProviderField {
  key: string;
  label: string;
  placeholder?: string;
  help?: string;
}

/** How a provider presents itself; the UI is drawn from this alone. */
export interface SecretProviderDescriptor {
  /** Stable ID stored with each secret, e.g. "onepassword". */
  id: string;
  /** The password manager's name, e.g. "1Password". */
  label: string;
  /** What the Settings group says about the provider and how to set it up. */
  description: string;
  /** The field that says where the manager keeps a value. */
  locator: { label: string; placeholder?: string; help?: string };
  /** Optional extra fields per secret, such as an account. */
  options: SecretProviderField[];
  /** Optional settings for the provider as a whole, such as the path to its CLI. */
  settings: SecretProviderField[];
}

/** Whether a provider can be used right now. */
export interface SecretProviderStatus {
  available: boolean;
  /** One sentence for Settings: what was found, or why the provider cannot be used. */
  summary: string;
  /** Values found automatically, shown in place of empty settings (e.g. the CLI's path). */
  detected?: Record<string, string>;
}

/** One provider as GET /api/secret-providers lists it. */
export interface SecretProviderInfo {
  descriptor: SecretProviderDescriptor;
  /** The saved settings; a missing key is unset. */
  settings: Record<string, string>;
  status: SecretProviderStatus;
}

export interface SecretProvidersResponse {
  providers: SecretProviderInfo[];
}

/** Body of PUT /api/secret-providers/:id/settings; an empty or null value unsets a key. */
export interface SecretProviderSettingsInput {
  settings: Record<string, string | null>;
}

/**
 * Body of POST /api/password-vault/external-secrets and its PUT. Saving one
 * needs neither a vault nor its master password: there is no value to protect.
 */
export interface ExternalSecretInput {
  provider: string;
  name: string;
  username?: string;
  locator: string;
  options?: Record<string, string>;
}

/** Body of POST /api/secret-providers/:id/test: checks a locator, never returns its value. */
export interface ExternalSecretTestRequest {
  locator: string;
  options?: Record<string, string>;
}
