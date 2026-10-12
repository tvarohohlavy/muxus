import { OnePasswordProvider } from './onepassword.js';
import type { SecretProvider } from './provider.js';

export { SecretProviderError, type SecretProvider } from './provider.js';
export { SecretProviders } from './registry.js';

/** The secret providers this build of Muxus offers. */
export function defaultSecretProviders(): SecretProvider[] {
  return [new OnePasswordProvider()];
}
