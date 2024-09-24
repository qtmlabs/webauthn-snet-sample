import { Injectable } from '@angular/core';
import { CBOR } from 'cbor-redux';
import { compactVerify, decodeProtectedHeader, importX509 } from 'jose';
import * as asn1X509 from '@peculiar/asn1-x509';
import * as x509 from '@peculiar/x509';

function byteArrayToBase64(array: Uint8Array) {
  return btoa(
    Array.from(array)
      .map((c) => String.fromCharCode(c))
      .join('')
  );
}

function byteArrayToBase64Url(array: Uint8Array) {
  return byteArrayToBase64(array)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

const GOOGLE_TRUST_SERVICE_ROOTS = [
  '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',
].map((encoded) => new x509.X509Certificate(encoded));

const GOOGLE_PLAY_SERVICES_KNOWN_CERTIFICATES = [
  '7C:E8:3C:1B:71:F3:D5:72:FE:D0:4C:8D:40:C5:CB:10:FF:75:E6:D8:7D:9D:F6:FB:D5:3F:04:68:C2:90:50:53',
  'D2:2C:C5:00:29:9F:B2:28:73:A0:1A:01:0D:E1:C8:2F:BE:4D:06:11:19:B9:48:14:DD:30:1D:AB:50:CB:76:78',
  'F0:FD:6C:5B:41:0F:25:CB:25:C3:B5:33:46:C8:97:2F:AE:30:F8:EE:74:11:DF:91:04:80:AD:6B:2D:60:DB:83',
  '19:75:B2:F1:71:77:BC:89:A5:DF:F3:1F:9E:64:A6:CA:E2:81:A5:3D:C1:D1:D5:9B:1D:14:7F:E1:C8:2A:FA:00',
].map((fingerprint) =>
  byteArrayToBase64(
    Uint8Array.from(fingerprint.split(':').map((c) => parseInt(c, 16)))
  )
);

@Injectable({
  providedIn: 'root',
})
export class AttestationService {
  constructor() {}

  async performAttestation(): Promise<string> {
    const challenge = new Uint8Array(32);
    crypto.getRandomValues(challenge);
    const encodedChallenge = byteArrayToBase64Url(challenge);

    const response = (await navigator.credentials.create({
      publicKey: {
        attestation: 'direct',
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          residentKey: 'discouraged',
        },
        challenge,
        pubKeyCredParams: [
          {
            type: 'public-key',
            alg: -7,
          },
        ],
        rp: {
          name: 'WebAuthn SafetyNet example',
        },
        user: {
          name: '',
          id: new Uint8Array(),
          displayName: 'WebAuthn SafetyNet example',
        },
      },
    })) as PublicKeyCredential | null;

    if (!response) {
      return 'Rejected: unable to attest';
    }

    const attestation = response.response as AuthenticatorAttestationResponse;
    const { fmt, attStmt, authData } = CBOR.decode(
      attestation.attestationObject
    );

    const clientDataHash = new Uint8Array(
      await crypto.subtle.digest('SHA-256', attestation.clientDataJSON)
    );
    const expectedNonce = byteArrayToBase64(
      new Uint8Array(
        await crypto.subtle.digest(
          'SHA-256',
          new Uint8Array([...authData, ...clientDataHash])
        )
      )
    );

    if (fmt !== 'android-safetynet') {
      return 'Rejected: not Android SafetyNet';
    }

    const safetyNetResponse = new TextDecoder().decode(attStmt.response);
    const header = decodeProtectedHeader(safetyNetResponse);

    if (header.x5c == null || header.alg == null) {
      return 'Rejected: invalid JWS';
    }

    const certChain = header.x5c.map(
      (encodedCert) => new x509.X509Certificate(encodedCert)
    );

    for (let i = 0; i < certChain.length; i++) {
      const cert = certChain[i];
      const issuerCert = certChain[i + 1];

      let isTrusted = false;
      for (const trustedCert of GOOGLE_TRUST_SERVICE_ROOTS) {
        if (await cert.verify({ publicKey: trustedCert.publicKey })) {
          isTrusted = true;
          break;
        }
      }
      if (isTrusted) {
        break;
      }

      if (!issuerCert) {
        return 'Rejected: chain not trusted';
      }

      const issuerConstraints =
        issuerCert.getExtension<x509.BasicConstraintsExtension>(
          asn1X509.id_ce_basicConstraints
        );
      if (!issuerConstraints?.ca) {
        return 'Rejected: non-CA certificate found in chain';
      }

      if (!(await cert.verify({ publicKey: issuerCert.publicKey }))) {
        return 'Rejected: chain validation failure';
      }
    }

    const signerIsAndroid = !!certChain[0]
      .getExtension<x509.SubjectAlternativeNameExtension>(
        asn1X509.id_ce_subjectAltName
      )
      ?.names?.items?.some(
        (name) => name.type === 'dns' && name.value === 'attest.android.com'
      );
    if (!signerIsAndroid) {
      return 'Rejected: not allowed signer';
    }

    const publicKey = await importX509(
      `-----BEGIN CERTIFICATE-----${header.x5c[0]}-----END CERTIFICATE-----`,
      header.alg
    );

    const verifiedData = JSON.parse(
      new TextDecoder().decode(
        (await compactVerify(safetyNetResponse, publicKey)).payload
      )
    );

    if (!verifiedData.ctsProfileMatch) {
      return 'Rejected: CTS profile mismatch';
    }

    if (!verifiedData.evaluationType.split(',').includes('HARDWARE_BACKED')) {
      return 'Rejected: no hardware backing';
    }

    if (
      verifiedData.apkPackageName != 'com.google.android.gms' ||
      !verifiedData.apkCertificateDigestSha256.some((fingerprint: string) =>
        GOOGLE_PLAY_SERVICES_KNOWN_CERTIFICATES.includes(fingerprint)
      )
    ) {
      return 'Rejected: wrong package';
    }

    if (verifiedData.nonce != expectedNonce) {
      return `Rejected: signed data hash mismatch: ${verifiedData.nonce} != ${expectedNonce}}`;
    }

    const clientData = JSON.parse(
      new TextDecoder().decode(attestation.clientDataJSON)
    );

    if (clientData.challenge != encodedChallenge) {
      return `Rejected: challenge mismatch: ${clientData.challenge} != ${encodedChallenge}`;
    }

    return `OK, challenge=${encodedChallenge}, response=${JSON.stringify(
      verifiedData
    )}`;
  }
}
