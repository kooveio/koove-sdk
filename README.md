# @koove/sdk

React Native / Expo SDK for the **consumer side** of [Koove](https://koove.io),
a zero-knowledge secret manager. The SDK gives a device a stable cryptographic
identity, registers it with the control plane **through hardware attestation**
(App Attest / Play Integrity), and locally decrypts secret **envelopes** that
were wrapped for that device — gated behind biometric / device-passcode
authentication. Private keys never leave the device; the server never sees
plaintext.

> **Status:** iOS App Attest is **verified end-to-end on a physical device**
> (iPhone 13 mini, 2026-07-14: real attestation, server-side chain
> verification against Apple's pinned root, biometric-gated decryption — no
> dev bypass). Android Play Integrity is verified on physical hardware too
> (Pixel 6a, 2026-07-17: real MEETS_DEVICE_INTEGRITY verdict, biometric-gated
> decryption, no dev bypass). We don't claim things we haven't verified —
> see *Security model* for exactly what is and isn't guaranteed.

## Features

- Generates and stores a **stable X25519 device identity** in hardware-backed
  secure storage (iOS Keychain / Android Keystore via `expo-secure-store`).
- **Attested registration:** the device public key becomes an eligible secret
  recipient only after a genuine App Attest / Play Integrity proof that
  cryptographically commits to that key (challenge + binding hash). On
  simulators/emulators there is **no silent fallback** — only an explicit dev
  marker that exclusively a non-production control plane can accept.
- **Decrypts secret envelopes locally** (X25519 + AES-256-GCM + HKDF, via
  [`@koove/crypto`](https://www.npmjs.com/package/@koove/crypto)); the server
  stores and serves only opaque ciphertext.
- **Biometric / device-passcode gate** over every decryption (fails closed when
  no authentication method is available).
- **Certificate pinning** out of the box: the config plugin pins the root-CA
  SPKI keys for `koove.io` at the OS level (ATS `NSPinnedDomains` on iOS,
  Network Security Config on Android). Overridable / disableable via plugin
  props for self-hosted control planes.
- Runtime environment-integrity checks (jailbreak / root detection).
- iOS and Android. **Web is not a supported consumer** (browsers have no
  hardware-backed key storage).

## Prerequisites

- Expo SDK 47+, using an **Expo Development Build** (not Expo Go — the SDK
  requires native modules).
- iOS 14+ (App Attest requirement).
- A reachable Koove control plane (`apiUrl`).

## Installation

```bash
npm install @koove/sdk
```

Add the config plugin to `app.json` / `app.config.js`:

```json
{
  "expo": {
    "plugins": ["@koove/sdk"]
  }
}
```

Plugin options:

```json
{
  "expo": {
    "plugins": [["@koove/sdk", {
      "appAttestEnvironment": "production",
      "disablePinning": false,
      "pinnedDomain": "koove.io",
      "androidPinExpiration": "2028-07-01"
    }]]
  }
}
```

Then create a development build:

```bash
expo prebuild        # or: eas build --profile development --platform all
```

## Usage

### Initialize the client and decrypt a secret

```ts
import { KooveClient } from '@koove/sdk';
import type { SecretEnvelope } from '@koove/sdk';

const client = new KooveClient({
  apiUrl: 'https://koove.io/api',
  appId: 'your-app-id',
  appToken: 'your-app-token',
});

// Runs environment checks, ensures the device identity exists and registers
// it via attested registration (challenge -> attest -> verify).
await client.init();

// `envelope` is fetched from the control plane (GET /api/credentials).
// Decryption prompts for biometrics / device passcode and runs locally.
const plaintext = await client.decryptSecret(envelope as SecretEnvelope);
```

`VPNClient` remains as a deprecated alias of `KooveClient` and will be removed
in 1.0.

### Lower-level building blocks

```ts
import {
  KeyManager,
  RASP,
  generateIdentityKeyPair,
  encryptSecret,
  decryptSecret,
  addRecipient,
} from '@koove/sdk';
import type { IdentityKeyPair, SecretEnvelope, SealedKey } from '@koove/sdk';

// Ensure (and register) the device identity directly.
const identity = await KeyManager.ensureIdentity(apiUrl, appId, appToken);

// Decrypt an envelope with biometric gating.
const value = await KeyManager.decrypt(envelope);

// Verify the runtime environment (throws on a compromised device).
await RASP.ensureEnvironment();
```

The `generateIdentityKeyPair` / `encryptSecret` / `decryptSecret` /
`addRecipient` primitives are re-exported from `@koove/crypto`, the open,
auditable envelope-encryption package.

## Security model

- **Zero-knowledge at the edge:** secrets are wrapped for a device's public
  key; the control plane stores and serves only opaque envelopes and never
  holds the plaintext or the device private key.
- **Attestation gates eligibility, not wrapping:** the server marks a device
  public key as an eligible recipient only after verifying the attestation
  proof server-side; the *writer* (CLI / controller identity) wraps the DEK for
  that key. The server never wraps in the zero-knowledge tier.
- **Stable device identity:** the keypair is generated once and persists.
  Rotation / revocation happens at the DEK level via re-wrapping, not by
  replacing the device key.
- **Authentication is mandatory:** `decryptSecret` always requires a real
  user-presence check and fails closed if none is available. There is no bypass.
- **Honest limits:** attestation proves *origin at registration + liveness*; it
  does not make the X25519 key non-extractable on a fully compromised device.
  Client-side checks (jailbreak detection, pinning) raise the attacker's cost —
  the real controls (attestation verification, anomaly detection, revocation,
  canary tokens) live on the server, where a compromised client can't switch
  them off. Revoking a device stops *future* deliveries; plaintext a device
  already decrypted cannot be un-delivered by anyone.

## Limitations

- Requires a Development Build; not compatible with Expo Go.
- Web is not a supported secret consumer in v1.
- Live attestation runs: iOS pending a physical-device validation session;
  Android pending Play Console setup. The dev-bypass path (simulator +
  non-production server) is fully functional for development.

## License

MIT
