// android/src/main/java/com/expovpnsdk/ExpoVpnSdkAttestationModule.java
package com.expovpnsdk;

import android.util.Base64;

import androidx.annotation.NonNull;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.WritableMap;

import com.google.android.play.core.integrity.IntegrityManager;
import com.google.android.play.core.integrity.IntegrityManagerFactory;
import com.google.android.play.core.integrity.IntegrityTokenRequest;

/**
 * Play Integrity bridge.
 *
 * This module NEVER computes the attestation binding: it receives the
 * precomputed clientDataHash (= computeAttestationBinding(nonce, x25519Pub),
 * standard base64) from JS and passes the SAME bytes through as the Play
 * Integrity nonce. The only transformation is transcoding standard base64 to
 * the URL-safe unpadded encoding the Integrity API requires — an encoding
 * change, not a recomputation.
 */
public class ExpoVpnSdkAttestationModule extends ReactContextBaseJavaModule {
    private static final String NAME = "ExpoVpnSdkAttestation";

    public ExpoVpnSdkAttestationModule(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @Override
    @NonNull
    public String getName() {
        return NAME;
    }

    @ReactMethod
    public void isSupported(Promise promise) {
        // Play Integrity needs Google Play (services + store). An emulator
        // without Play falls through to the explicit dev marker in JS.
        try {
            getReactApplicationContext()
                .getPackageManager()
                .getPackageInfo("com.android.vending", 0);
            promise.resolve(true);
        } catch (Exception e) {
            promise.resolve(false);
        }
    }

    /**
     * Optional GCP project number from manifest meta-data. Required by Play
     * Integrity for apps NOT installed from Play (dev builds by cable); apps
     * from Play work without it. Stored with a "cpn-" prefix because aapt
     * would overflow a bare 12-digit android:value into an int.
     */
    private Long getCloudProjectNumber() {
        try {
            android.content.pm.ApplicationInfo ai = getReactApplicationContext()
                .getPackageManager()
                .getApplicationInfo(
                    getReactApplicationContext().getPackageName(),
                    android.content.pm.PackageManager.GET_META_DATA);
            if (ai.metaData == null) return null;
            Object v = ai.metaData.get("com.koove.sdk.cloudProjectNumber");
            if (v == null) return null;
            String s = String.valueOf(v).trim();
            if (s.startsWith("cpn-")) s = s.substring(4);
            return Long.parseLong(s);
        } catch (Exception e) {
            return null;
        }
    }

    @ReactMethod
    public void attest(String clientDataHashB64, Promise promise) {
        byte[] binding;
        try {
            binding = Base64.decode(clientDataHashB64, Base64.DEFAULT);
        } catch (IllegalArgumentException e) {
            promise.reject("E_BAD_ARGUMENT", "clientDataHash is not valid base64", e);
            return;
        }
        // Same bytes, Integrity-API encoding (URL-safe, no wrap, no padding).
        String nonce = Base64.encodeToString(
            binding, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);

        try {
            IntegrityManager manager =
                IntegrityManagerFactory.create(getReactApplicationContext());
            IntegrityTokenRequest.Builder reqBuilder =
                IntegrityTokenRequest.builder().setNonce(nonce);
            Long cloudProjectNumber = getCloudProjectNumber();
            if (cloudProjectNumber != null) {
                reqBuilder.setCloudProjectNumber(cloudProjectNumber);
            }
            manager
                .requestIntegrityToken(reqBuilder.build())
                .addOnSuccessListener(response -> {
                    WritableMap out = Arguments.createMap();
                    out.putString("integrityToken", response.token());
                    promise.resolve(out);
                })
                .addOnFailureListener(e ->
                    promise.reject("E_ATTEST",
                        "Play Integrity token request failed: " + e.getMessage(), e));
        } catch (Exception e) {
            promise.reject("E_ATTEST",
                "Play Integrity is unavailable: " + e.getMessage(), e);
        }
    }
}
