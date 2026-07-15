import * as LocalAuthentication from 'expo-local-authentication';

/**
 * Biometric / device-passcode gate over sensitive key operations.
 *
 * SECURITY: there is NO bypass. Decrypting a secret envelope always requires a
 * real user-presence check — biometrics when enrolled, or the device passcode
 * as fallback (`disableDeviceFallback: false`). On a device with neither an
 * enrolled biometric NOR a passcode, authentication fails and the caller MUST
 * fail closed. This is intentional: the zero-knowledge model only releases
 * plaintext to a verified, present user.
 *
 * (Previously a `disableBiometrics` flag turned the gate into an unconditional
 * `return true` — a total auth bypass. It has been removed.)
 */
export class Biometrics {
    /**
     * Whether a biometric sensor is present and enrolled. Informational only:
     * a `false` here does NOT mean authentication is unavailable, because
     * authenticate() can still fall back to the device passcode.
     */
    static async isAvailable(): Promise<boolean> {
        const hasHardware = await LocalAuthentication.hasHardwareAsync();
        const isEnrolled = await LocalAuthentication.isEnrolledAsync();
        return hasHardware && isEnrolled;
    }

    /**
     * Prompts for biometric authentication, falling back to the device
     * passcode. Returns true only on a successful, real user-presence check.
     * Returns false on failure, cancellation, or when the device exposes no
     * authentication method at all — callers MUST treat false as "deny".
     */
    static async authenticate(reason: string = 'Authenticate to access your secret'): Promise<boolean> {
        try {
            const result = await LocalAuthentication.authenticateAsync({
                promptMessage: reason,
                fallbackLabel: 'Use Passcode',
                cancelLabel: 'Cancel',
                disableDeviceFallback: false,
            });
            return result.success;
        } catch (error) {
            console.error('[Biometrics] Auth failed or cancelled', error);
            return false;
        }
    }
}
