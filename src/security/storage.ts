import * as SecureStore from 'expo-secure-store';
import { Platform } from 'react-native';
import type { IdentityKeyPair } from '@koove/crypto';

const KEY_ALIAS_IDENTITY = 'koove_device_identity';
const KEY_ALIAS_CONFIG_CACHE = 'koove_config_cache';

const WEB_UNSUPPORTED =
  '[SecureStorage] Web is not a supported secret consumer in v1: browsers have ' +
  'no hardware-backed key storage, so a private identity key cannot be held ' +
  'securely. Consume secrets from the mobile SDK instead.';

/**
 * Hardware-backed storage for the device's X25519 identity.
 *
 * On iOS/Android the identity lives in the Keychain / Keystore via
 * expo-secure-store. The device identity is STABLE — it is generated once and
 * persists. (Rotation/revocation happens at the DEK level via re-wrapping, not
 * by replacing the device key, which would break access to existing secrets in
 * the zero-knowledge model.)
 *
 * SECURITY: the `web` platform is NOT a supported consumer in v1. Browsers
 * cannot store a raw private key securely, so identity reads/writes fail closed
 * on web rather than persisting the key in plaintext localStorage (the previous
 * behaviour). The web dashboard is a writer-only surface and never needs a
 * device identity. clearIdentity() additionally scrubs any key a prior build
 * may have already leaked into localStorage.
 */
export class SecureStorage {
  static async saveIdentity(identity: IdentityKeyPair): Promise<void> {
    if (Platform.OS === 'web') {
      throw new Error(WEB_UNSUPPORTED);
    }
    const serialized = JSON.stringify(identity);
    await SecureStore.setItemAsync(KEY_ALIAS_IDENTITY, serialized);
  }

  static async getIdentity(): Promise<IdentityKeyPair | null> {
    if (Platform.OS === 'web') {
      throw new Error(WEB_UNSUPPORTED);
    }
    const serialized = await SecureStore.getItemAsync(KEY_ALIAS_IDENTITY);
    if (!serialized) return null;
    try {
      return JSON.parse(serialized) as IdentityKeyPair;
    } catch {
      return null;
    }
  }

  static async clearIdentity(): Promise<void> {
    if (Platform.OS === 'web') {
      // Defensive cleanup: scrub any private key a prior build leaked here.
      try {
        localStorage.removeItem(KEY_ALIAS_IDENTITY);
        localStorage.removeItem(KEY_ALIAS_CONFIG_CACHE);
      } catch {
        /* localStorage unavailable — nothing to scrub */
      }
      return;
    }
    await SecureStore.deleteItemAsync(KEY_ALIAS_IDENTITY);
    await SecureStore.deleteItemAsync(KEY_ALIAS_CONFIG_CACHE);
  }

  static async saveConfigCache(config: string): Promise<void> {
    if (Platform.OS === 'web') {
      throw new Error(WEB_UNSUPPORTED);
    }
    await SecureStore.setItemAsync(KEY_ALIAS_CONFIG_CACHE, config);
  }

  static async getConfigCache(): Promise<string | null> {
    // Fail closed on web: no cached config means init() cannot silently treat
    // an unsupported web consumer as "keys ready".
    if (Platform.OS === 'web') return null;
    return await SecureStore.getItemAsync(KEY_ALIAS_CONFIG_CACHE);
  }
}
