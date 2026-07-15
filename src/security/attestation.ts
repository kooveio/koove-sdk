import { Platform } from 'react-native';

/**
 * On-device attestation bridge.
 *
 * The actual platform calls (iOS App Attest via DCAppAttestService, Android Play
 * Integrity) run in the native Expo module, which lands in a later step. This
 * module is the thin JS surface the key manager talks to.
 *
 * IMPORTANT: the native side receives the precomputed `clientDataHashB64`
 * (= computeAttestationBinding(nonce, publicKey)) and passes it through
 * verbatim — it NEVER recomputes the binding, or the single-implementation
 * guarantee in @koove/crypto is lost.
 */
export type AttestationKind = 'ios' | 'android' | 'dev';

export interface AttestationProof {
  kind: AttestationKind;
  platform: 'ios' | 'android';
  /** attestationObject (iOS) / integrityToken (Android) / dev marker. */
  payload: unknown;
}

interface NativeAttestationModule {
  isSupported(): Promise<boolean>;
  attest(clientDataHashB64: string): Promise<{
    keyId?: string;
    attestationObject?: string;
    integrityToken?: string;
  }>;
}

function getNativeModule(): NativeAttestationModule | null {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { NativeModules } = require('react-native');
    const mod = NativeModules?.ExpoVpnSdkAttestation ?? null;
    return mod && typeof mod.isSupported === 'function' ? mod : null;
  } catch {
    return null;
  }
}

export const Attestation = {
  async isSupported(): Promise<boolean> {
    const native = getNativeModule();
    return native ? native.isSupported() : false;
  },

  /**
   * Produce an attestation proof committing to `clientDataHashB64`.
   *
   * On a device without attestation support (simulator/emulator), there is NO
   * silent fallback: we return the explicit `dev` marker, which only a
   * non-production server with the dev bypass + matching secret will accept.
   */
  async attest(clientDataHashB64: string): Promise<AttestationProof> {
    const platform: 'ios' | 'android' = Platform.OS === 'android' ? 'android' : 'ios';
    const native = getNativeModule();

    if (native && (await native.isSupported())) {
      const out = await native.attest(clientDataHashB64);
      return platform === 'ios'
        ? { kind: 'ios', platform, payload: { keyId: out.keyId, attestationObject: out.attestationObject } }
        : { kind: 'android', platform, payload: { integrityToken: out.integrityToken } };
    }

    return { kind: 'dev', platform, payload: { devAttestation: true } };
  },
};
