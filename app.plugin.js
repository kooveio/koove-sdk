const {
  withEntitlementsPlist,
  withInfoPlist,
  withAndroidManifest,
  withXcodeProject,
  withDangerousMod,
  createRunOncePlugin
} = require('@expo/config-plugins');
const fs = require('fs');
const path = require('path');

const IOS_SOURCES = ['ExpoVpnSdk.m', 'ExpoVpnSdkAttestation.swift'];

/**
 * Certificate pinning (task5/STRATEGY P1: evitar intercepción del secreto en
 * tránsito). Pinneamos claves de ROOT CA (SPKI SHA-256), no de leaf: los leaf
 * de Vercel rotan cada ~90 días; las roots duran décadas. Doble CA para no
 * romper si Vercel cambia de emisor: Google Trust Services (emisor actual de
 * koove.io) + ISRG/Let's Encrypt (respaldo). Pins computados de los PEM
 * oficiales (pki.goog / letsencrypt.org), 2026-07-14.
 */
const DEFAULT_PINNED_DOMAIN = 'koove.io';
const DEFAULT_PINS = [
  'hxqRlPTu1bMS/0DITB1SSu0vd4u/8l8TjPgfaAp63Gc=', // GTS Root R1
  'Vfd95BwDeSQo+NUYxVEEIlvkOlWY2SalKK1lPhzOx78=', // GTS Root R2
  'QXnt2YHvdHR3tJYmQIr0Paosp6t/nggsEGD4QJZ3Q0g=', // GTS Root R3
  'mEflZT5enoR1FuXLgYYGqnVEoZvmf9c2bVBpiOjYQ0c=', // GTS Root R4
  'C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=', // ISRG Root X1
  'diGVwiVYbubAI3RW4hB9xU8e/CH2GnkuvVFZE8zmgzI=', // ISRG Root X2
];
// Fail-open de seguridad en Android: pasada esta fecha el pinning se
// desactiva solo (recomendación de la plataforma para no brickear apps sin
// actualizar). Renovar la fecha en cada release del SDK.
const DEFAULT_ANDROID_PIN_EXPIRATION = '2028-07-01';

// Genera el bridging header en el proyecto de la app
const withSwiftBridgingHeaderFile = (config) => {
  return withDangerousMod(config, [
    'ios',
    async (config) => {
      const iosPath = path.join(config.modRequest.projectRoot, 'ios');
      const bridgingHeaderContent = `#ifndef ExpoVpnSdk_Bridging_Header_h
#define ExpoVpnSdk_Bridging_Header_h

#import <React/RCTBridgeModule.h>

#endif /* ExpoVpnSdk_Bridging_Header_h */
`;
      fs.writeFileSync(
        path.join(iosPath, 'ExpoVpnSdk-Bridging-Header.h'),
        bridgingHeaderContent
      );
      return config;
    },
  ]);
};

// Copia los fuentes nativos del paquete (ios/ es la única fuente de verdad —
// nada de contenido duplicado como strings, que ya causó drift una vez).
const withNativeModuleFiles = (config) => {
  return withDangerousMod(config, [
    'ios',
    async (config) => {
      const iosPath = path.join(config.modRequest.projectRoot, 'ios');
      const moduleDir = path.join(iosPath, 'ExpoVpnSdk');
      fs.mkdirSync(moduleDir, { recursive: true });
      for (const file of IOS_SOURCES) {
        fs.copyFileSync(
          path.join(__dirname, 'ios', file),
          path.join(moduleDir, file)
        );
      }
      return config;
    },
  ]);
};

// Configuración del proyecto Xcode (Swift + bridging header + fuentes)
const withXcodeProjectMod = (config) => {
  return withXcodeProject(config, async (config) => {
    const xcodeProject = config.modResults;

    xcodeProject.addBuildProperty('SWIFT_VERSION', '5.0');
    xcodeProject.addBuildProperty(
      'SWIFT_OBJC_BRIDGING_HEADER',
      '"$(SRCROOT)/ExpoVpnSdk-Bridging-Header.h"'
    );

    const groupName = 'ExpoVpnSdk';
    const groupKey = xcodeProject.findPBXGroupKey({ name: groupName }) ||
      xcodeProject.pbxCreateGroup(groupName, groupName);

    if (groupKey) {
      const target = xcodeProject.getFirstTarget().uuid;
      for (const file of IOS_SOURCES) {
        xcodeProject.addSourceFile(`ExpoVpnSdk/${file}`, { target }, groupKey);
      }
    }

    return config;
  });
};

/**
 * Entitlement de App Attest. Apple acepta 'development' o 'production';
 * los builds de App Store operan SIEMPRE como production. Configurable vía
 * props del plugin: ["vpn-sdk", { "appAttestEnvironment": "development" }].
 */
const withAppAttestEntitlement = (config, props) => {
  return withEntitlementsPlist(config, (config) => {
    config.modResults['com.apple.developer.devicecheck.appattest-environment'] =
      (props && props.appAttestEnvironment) || 'production';
    return config;
  });
};

/**
 * iOS: pinning declarativo vía App Transport Security (NSPinnedDomains,
 * iOS 14+ — mismo mínimo que App Attest). Lo honra NSURLSession, que es el
 * stack que usa React Native/axios. Sin dependencias de terceros en la ruta
 * sensible.
 */
const withIosCertificatePinning = (config, pinning) => {
  return withInfoPlist(config, (config) => {
    const infoPlist = config.modResults;
    infoPlist.NSAppTransportSecurity = infoPlist.NSAppTransportSecurity || {};
    const pinnedDomains = infoPlist.NSAppTransportSecurity.NSPinnedDomains || {};
    pinnedDomains[pinning.domain] = {
      NSIncludesSubdomains: true,
      NSPinnedCAIdentities: pinning.pins.map((pin) => ({
        'SPKI-SHA256-BASE64': pin,
      })),
    };
    infoPlist.NSAppTransportSecurity.NSPinnedDomains = pinnedDomains;
    return config;
  });
};

/**
 * Android: Network Security Config con <pin-set> (lo honra OkHttp, el stack
 * de red de React Native). Escribe res/xml/koove_network_security_config.xml
 * y lo referencia desde el manifest — salvo que la app ya tenga uno propio,
 * en cuyo caso avisamos y NO lo pisamos (mergearlo a mano).
 */
const withAndroidCertificatePinning = (config, pinning) => {
  config = withDangerousMod(config, [
    'android',
    async (config) => {
      const resXmlDir = path.join(
        config.modRequest.platformProjectRoot,
        'app', 'src', 'main', 'res', 'xml'
      );
      fs.mkdirSync(resXmlDir, { recursive: true });
      const pinsXml = pinning.pins
        .map((pin) => `      <pin digest="SHA-256">${pin}</pin>`)
        .join('\n');
      const xml = `<?xml version="1.0" encoding="utf-8"?>
<!-- Generado por vpn-sdk (Koove). Pinning de roots GTS + ISRG para ${pinning.domain}.
     expiration = fail-open de seguridad: pasada la fecha el pinning se
     desactiva en vez de brickear una app sin actualizar. -->
<network-security-config>
  <domain-config>
    <domain includeSubdomains="true">${pinning.domain}</domain>
    <pin-set expiration="${pinning.androidExpiration}">
${pinsXml}
    </pin-set>
  </domain-config>
</network-security-config>
`;
      fs.writeFileSync(
        path.join(resXmlDir, 'koove_network_security_config.xml'),
        xml
      );
      return config;
    },
  ]);

  config = withAndroidManifest(config, (config) => {
    const application = config.modResults.manifest.application?.[0];
    if (!application) return config;
    const existing = application.$['android:networkSecurityConfig'];
    if (existing && existing !== '@xml/koove_network_security_config') {
      console.warn(
        `[vpn-sdk] La app ya define android:networkSecurityConfig=${existing}; ` +
        'NO se sobreescribe. Añade el <pin-set> de ' +
        'koove_network_security_config.xml a tu config manualmente.'
      );
      return config;
    }
    application.$['android:networkSecurityConfig'] = '@xml/koove_network_security_config';
    return config;
  });

  return config;
};

// Plugin principal — superficie attestation-only (el VPN nativo se purgó;
// STRATEGY: la superficie VPN/ZTNA está diferida).
const withKooveSdk = (config, props) => {
  config = withSwiftBridgingHeaderFile(config);
  config = withNativeModuleFiles(config);
  config = withXcodeProjectMod(config);
  config = withAppAttestEntitlement(config, props);

  // Pinning on por defecto; desactivable para desarrollo contra localhost
  // (["vpn-sdk", { "disablePinning": true }]).
  if (!props || !props.disablePinning) {
    const pinning = {
      domain: (props && props.pinnedDomain) || DEFAULT_PINNED_DOMAIN,
      pins: (props && props.pins) || DEFAULT_PINS,
      androidExpiration:
        (props && props.androidPinExpiration) || DEFAULT_ANDROID_PIN_EXPIRATION,
    };
    config = withIosCertificatePinning(config, pinning);
    config = withAndroidCertificatePinning(config, pinning);
  }

  return config;
};

module.exports = createRunOncePlugin(
  withKooveSdk,
  'vpn-sdk',
  '0.2.0'
);
