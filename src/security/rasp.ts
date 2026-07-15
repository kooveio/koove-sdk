import * as Device from 'expo-device';

/**
 * Local environment checks (deterrence layer).
 *
 * Scope is deliberately narrow: jailbreak/root detection as a local hard-throw.
 * There is NO debugger "detection" — a JS timing check is theater, not control
 * (task5 §7) — and no self-reporting to the server: a compromised client can
 * lie, so the anomaly engine feeds exclusively on server-verified attestation
 * signals.
 */
export class RASP {
    /**
     * Checks if the environment is safe to run.
     * Throws an error if a security violation is detected.
     */
    static async ensureEnvironment(): Promise<void> {
        // Root / Jailbreak Detection (native, via expo-device)
        const isRooted = await Device.isRootedExperimentalAsync();
        if (isRooted) {
            console.error('[RASP] SECURITY VIOLATION: Device appears to be Rooted/Jailbroken.');
            throw new Error('SEC_ERR_001: Environment compromised.');
        }
    }
}
