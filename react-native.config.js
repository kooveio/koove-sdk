// Classic React Native native module (old-bridge). @koove/sdk ships a Swift
// module (RCT_EXTERN_MODULE, iOS podspec) and an Android ReactPackage. This
// makes RN autolinking register BOTH — the empty expo-module.config.json used
// to make Expo claim the package and register nothing on Android, so the
// attestation native module was never wired (found live on a Pixel 6a).
module.exports = {
  dependency: {
    platforms: {
      ios: {},
      android: {
        sourceDir: './android',
        packageImportPath: 'import com.expovpnsdk.ExpoVpnSdkPackage;',
        packageInstance: 'new ExpoVpnSdkPackage()',
      },
    },
  },
};
