import Foundation
import DeviceCheck

/**
 * App Attest bridge (DCAppAttestService).
 *
 * This module NEVER computes the attestation binding: it receives the
 * precomputed clientDataHash (= computeAttestationBinding(nonce, x25519Pub),
 * base64) from JS and passes the decoded bytes verbatim to the OS API. If the
 * native side ever recomputes the hash, the single-implementation guarantee in
 * @koove/crypto is lost.
 */
@objc(ExpoVpnSdkAttestation)
class ExpoVpnSdkAttestation: NSObject {

  @objc static func requiresMainQueueSetup() -> Bool {
    return false
  }

  @objc func isSupported(_ resolve: @escaping RCTPromiseResolveBlock,
                         rejecter reject: @escaping RCTPromiseRejectBlock) {
    if #available(iOS 14.0, *) {
      resolve(DCAppAttestService.shared.isSupported)
    } else {
      resolve(false)
    }
  }

  /**
   * Generate a fresh App Attest key and attest it, committing to the given
   * clientDataHash. Resolves { keyId, attestationObject } (both base64; keyId
   * is base64 as returned by the OS).
   */
  @objc func attest(_ clientDataHashB64: String,
                    resolver resolve: @escaping RCTPromiseResolveBlock,
                    rejecter reject: @escaping RCTPromiseRejectBlock) {
    guard #available(iOS 14.0, *) else {
      reject("E_UNSUPPORTED", "App Attest requires iOS 14+", nil)
      return
    }
    let service = DCAppAttestService.shared
    guard service.isSupported else {
      // Simulator / unsupported hardware. JS falls back to the explicit dev
      // marker — never a silent success here.
      reject("E_UNSUPPORTED", "App Attest is not supported on this device", nil)
      return
    }
    guard let clientDataHash = Data(base64Encoded: clientDataHashB64) else {
      reject("E_BAD_ARGUMENT", "clientDataHash is not valid base64", nil)
      return
    }

    service.generateKey { keyId, error in
      if let error = error {
        reject("E_GENERATE_KEY", "App Attest generateKey failed: \(error.localizedDescription)", error)
        return
      }
      guard let keyId = keyId else {
        reject("E_GENERATE_KEY", "App Attest generateKey returned no keyId", nil)
        return
      }
      service.attestKey(keyId, clientDataHash: clientDataHash) { attestation, error in
        if let error = error {
          reject("E_ATTEST", "App Attest attestKey failed: \(error.localizedDescription)", error)
          return
        }
        guard let attestation = attestation else {
          reject("E_ATTEST", "App Attest attestKey returned no attestation", nil)
          return
        }
        resolve([
          "keyId": keyId,
          "attestationObject": attestation.base64EncodedString(),
        ])
      }
    }
  }

  /**
   * Generate an assertion with a previously attested key (per-request anomaly
   * signal, tasks #6/#7). Resolves { assertion } (base64).
   */
  @objc func generateAssertion(_ keyId: String,
                               clientDataHashB64: String,
                               resolver resolve: @escaping RCTPromiseResolveBlock,
                               rejecter reject: @escaping RCTPromiseRejectBlock) {
    guard #available(iOS 14.0, *) else {
      reject("E_UNSUPPORTED", "App Attest requires iOS 14+", nil)
      return
    }
    guard let clientDataHash = Data(base64Encoded: clientDataHashB64) else {
      reject("E_BAD_ARGUMENT", "clientDataHash is not valid base64", nil)
      return
    }
    DCAppAttestService.shared.generateAssertion(keyId, clientDataHash: clientDataHash) { assertion, error in
      if let error = error {
        reject("E_ASSERT", "App Attest generateAssertion failed: \(error.localizedDescription)", error)
        return
      }
      guard let assertion = assertion else {
        reject("E_ASSERT", "App Attest generateAssertion returned no assertion", nil)
        return
      }
      resolve(["assertion": assertion.base64EncodedString()])
    }
  }
}
