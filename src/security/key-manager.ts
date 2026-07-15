import axios from 'axios';
import { SecureStorage } from './storage';
import { RASP } from './rasp';
import { Biometrics } from './biometrics';
import { Attestation } from './attestation';
import {
  generateIdentityKeyPair,
  decryptSecret,
  computeAttestationBinding,
  bytesToBase64,
  type IdentityKeyPair,
  type SecretEnvelope,
} from '@koove/crypto';

/** Fail fast on unreachable hosts instead of hanging the whole init. */
const REQUEST_TIMEOUT_MS = 15_000;

export interface RegistrationOptions {
  /**
   * Dev-only secret sent alongside the `dev` attestation marker when running on
   * a simulator/emulator. Honored ONLY by a non-production server with the dev
   * bypass enabled. NEVER set this in a production build.
   */
  devAttestationSecret?: string;
}

/**
 * Manages the device's cryptographic identity (X25519) and local decryption of
 * secret envelopes.
 *
 * The identity is generated once and stored in hardware-backed secure storage.
 * Its public key is registered with the control plane ONLY after a genuine
 * attestation (App Attest / Play Integrity), so the server can wrap secrets for
 * a verified device. The private key never leaves the device.
 */
export class KeyManager {
  /**
   * Ensure a device identity exists. Generates one on first run and registers it
   * with the control plane via the attested-registration flow. Returns the
   * identity.
   */
  static async ensureIdentity(
    apiUrl: string,
    appId: string,
    appToken: string,
    opts: RegistrationOptions = {},
  ): Promise<IdentityKeyPair> {
    // RASP check before any sensitive key operation.
    await RASP.ensureEnvironment();

    const existing = await SecureStorage.getIdentity();
    if (existing) {
      // A locally stored identity does NOT imply the server knows it: a
      // registration that failed mid-flight must not leave the SDK claiming
      // "ready" forever (found live on the first physical-device run).
      // Discovery is the source of truth; re-attesting the same key is a safe
      // upsert server-side.
      if (await this.isRegistered(apiUrl, appId, appToken, existing.publicKey)) {
        console.log('[KeyManager] Device identity present and registered.');
        return existing;
      }
      console.log('[KeyManager] Identity present but NOT registered — attesting now...');
      await this.registerDevice(apiUrl, appId, appToken, existing, opts);
      console.log('[KeyManager] Device identity registered.');
      return existing;
    }

    console.log('[KeyManager] No identity found. Generating X25519 device identity...');
    const identity = generateIdentityKeyPair();
    // Register FIRST, persist after: a failed registration must leave no
    // half-initialized state behind.
    await this.registerDevice(apiUrl, appId, appToken, identity, opts);
    await SecureStorage.saveIdentity(identity);
    console.log('[KeyManager] Device identity registered.');
    return identity;
  }

  /** Whether the server already lists this pubkey as a device (any status). */
  private static async isRegistered(
    apiUrl: string,
    appId: string,
    appToken: string,
    publicKey: string,
  ): Promise<boolean> {
    try {
      const { data } = await axios.get(`${apiUrl}/apps/${appId}/devices`, {
        headers: { Authorization: `Bearer ${appToken}` },
        timeout: REQUEST_TIMEOUT_MS,
      });
      const devices: Array<{ publicKey?: string }> = data?.devices ?? [];
      return devices.some((d) => d.publicKey === publicKey);
    } catch {
      // Can't reach discovery: assume not registered so we attempt the real
      // registration (which will surface the actual error).
      return false;
    }
  }

  /**
   * Decrypt a secret envelope for this device. Gated by biometric auth.
   */
  static async decrypt(envelope: SecretEnvelope): Promise<string> {
    const authenticated = await Biometrics.authenticate();
    if (!authenticated) throw new Error('Biometric Authentication Failed');

    const identity = await SecureStorage.getIdentity();
    if (!identity) throw new Error('No device identity available for decryption');

    try {
      return decryptSecret(identity, envelope);
    } catch (error) {
      console.error('[KeyManager] Decryption failed:', error);
      throw new Error('Decryption failed');
    }
  }

  /**
   * Register this device with the control plane via attestation:
   *   1. fetch a server-issued challenge,
   *   2. bind the challenge to this device's public key,
   *   3. produce an attestation proof (real native, or the explicit dev marker),
   *   4. submit it to the attested-registration endpoint.
   *
   * The server records the public key as an eligible recipient only if the proof
   * verifies. This replaces the old `rotate-key` call, which registered any key
   * with just the (extractable) appToken.
   */
  private static async registerDevice(
    apiUrl: string,
    appId: string,
    appToken: string,
    identity: IdentityKeyPair,
    opts: RegistrationOptions,
  ): Promise<void> {
    try {
      // 1. Server-issued, single-use challenge.
      const { data: challenge } = await axios.post(
        `${apiUrl}/apps/${appId}/attestation/challenge`,
        {},
        { headers: { Authorization: `Bearer ${appToken}` }, timeout: REQUEST_TIMEOUT_MS },
      );

      // 2. The single shared binding: commit the challenge to this public key.
      const binding = computeAttestationBinding(challenge.nonce, identity.publicKey);
      const clientDataHashB64 = bytesToBase64(binding);

      // 3. Attestation proof (native App Attest / Play Integrity, or dev marker).
      const proof = await Attestation.attest(clientDataHashB64);

      // 4. Submit. The dev secret is sent only on the dev path.
      const headers: Record<string, string> = { Authorization: `Bearer ${appToken}` };
      if (proof.kind === 'dev' && opts.devAttestationSecret) {
        headers['x-koove-dev-secret'] = opts.devAttestationSecret;
      }

      await axios.post(
        `${apiUrl}/apps/${appId}/devices`,
        {
          challengeId: challenge.challengeId,
          x25519PublicKey: identity.publicKey,
          platform: proof.platform,
          kind: proof.kind,
          payload: proof.payload,
        },
        { headers, timeout: REQUEST_TIMEOUT_MS },
      );
    } catch (error) {
      console.error('[KeyManager] Device registration failed:', error);
      // Surface the server's rejection reason (or the transport error) —
      // "registration failed" alone is undebuggable in the field.
      const detail = axios.isAxiosError(error)
        ? error.response
          ? `HTTP ${error.response.status}: ${typeof error.response.data === 'string' ? error.response.data : JSON.stringify(error.response.data)}`
          : error.message
        : error instanceof Error
          ? error.message
          : String(error);
      throw new Error(`Device registration failed — ${detail}`);
    }
  }
}
