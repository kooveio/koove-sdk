import { KeyManager } from './security/key-manager';
import { RASP } from './security/rasp';
import { SecureStorage } from './security/storage';

import type { SecretEnvelope } from '@koove/crypto';

export interface KooveClientConfig {
  apiUrl: string;
  appId: string;
  appToken: string;
  /**
   * Dev-only attestation secret for running the flow on a simulator/emulator
   * (where App Attest / Play Integrity are unavailable). Honored only by a
   * non-production control plane with the dev bypass enabled. NEVER set this in
   * a production build.
   */
  devAttestationSecret?: string;
}

export class KooveClient {
  private config: KooveClientConfig;

  constructor(config: KooveClientConfig) {
    this.config = config;
  }

  /**
   * Initializes the SDK: runs environment-integrity (RASP) checks and ensures a
   * device cryptographic identity exists and is registered with the control
   * plane so secrets can be wrapped for this device.
   */
  async init(): Promise<void> {
    console.log('[KooveClient] Initializing...');

    // 1. Verify Environment Integrity (RASP)
    await RASP.ensureEnvironment();

    // 2. Ensure a device identity exists, falling back to a cached one offline.
    try {
      // Ensure a device identity exists and is registered with the control plane.
      await KeyManager.ensureIdentity(this.config.apiUrl, this.config.appId, this.config.appToken, {
        devAttestationSecret: this.config.devAttestationSecret,
      });
    } catch (e) {
      console.warn('[KooveClient] Network init failed. Trying offline cache...');
      const cached = await SecureStorage.getConfigCache();
      if (cached) {
        console.log('[KooveClient] Loaded identity from offline cache 📦');
      } else {
        console.error('[KooveClient] No offline cache content available.');
        throw e; // Fail if no network and no cached identity
      }
    }

    console.log('[KooveClient] Ready and Secure 🛡️');
  }

  /**
   * Decrypts a secret envelope using the device's local private identity key.
   * Gated by biometric / device-passcode authentication.
   */
  async decryptSecret(envelope: SecretEnvelope): Promise<string> {
    return await KeyManager.decrypt(envelope);
  }
}

/**
 * @deprecated Legacy names from the VPN era — use KooveClient / KooveClientConfig.
 * Kept as aliases so existing test apps keep compiling; removed in 1.0.
 */
export const VPNClient = KooveClient;
export type VPNClientConfig = KooveClientConfig;

export { KeyManager, RASP };
export {
  generateIdentityKeyPair,
  encryptSecret,
  decryptSecret,
  addRecipient,
} from '@koove/crypto';
export type { IdentityKeyPair, SecretEnvelope, SealedKey } from '@koove/crypto';
