// Copyright (c) 2019 Faye Amacker. All rights reserved.
// Use of this source code is governed by Apache License 2.0 found in the LICENSE file.

package androidkeystore

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"reflect"

	"github.com/fxamacker/cbor"
	"github.com/fxamacker/webauthn"
)

/*
 * Android Keystore Root Certificate extracted by herrjemand.
 * The last certificate in x5c must match this certificate.
 * Date: 2019
 * Availability: https://gist.github.com/herrjemand/c5a84de5c04ef41b3ac7fd12d0cbceae#file-verify-androidkey-webauthn-js
 */
const androidKeyStoreRootCertPem = `
-----BEGIN CERTIFICATE-----
MIICizCCAjKgAwIBAgIJAKIFntEOQ1tXMAoGCCqGSM49BAMCMIGYMQswCQYDVQQG
EwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmll
dzEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTMwMQYD
VQQDDCpBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIFJvb3Qw
HhcNMTYwMTExMDA0MzUwWhcNMzYwMTA2MDA0MzUwWjCBmDELMAkGA1UEBhMCVVMx
EzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFTAT
BgNVBAoMDEdvb2dsZSwgSW5jLjEQMA4GA1UECwwHQW5kcm9pZDEzMDEGA1UEAwwq
QW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBSb290MFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamguD/9/SQ59
dx9EIm29sa/6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpKNjMGEwHQYDVR0O
BBYEFMit6XdMRcOjzw0WEOR5QzohWjDPMB8GA1UdIwQYMBaAFMit6XdMRcOjzw0W
EOR5QzohWjDPMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgKEMAoGCCqG
SM49BAMCA0cAMEQCIDUho++LNEYenNVg8x1YiSBq3KNlQfYNns6KGYxmSGB7AiBN
C/NR2TB8fVvaNTQdqEcbY6WFZTytTySn502vQX3xvw==
-----END CERTIFICATE-----`

var (
	androidKeyStoreRootCert     *x509.Certificate
	oidAndroidKeyCertificateExt = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}
)

type androidKeyAttestationStatement struct {
	webauthn.SignatureAlgorithm
	sig      []byte
	credCert *x509.Certificate
	caCerts  []*x509.Certificate
}

func parseAttestation(data []byte) (webauthn.AttestationStatement, error) {
	type rawAttStmt struct {
		Alg int      `cbor:"alg"`
		Sig []byte   `cbor:"sig"`
		X5C [][]byte `cbor:"x5c"`
	}
	var raw rawAttStmt
	var err error
	if err = cbor.Unmarshal(data, &raw); err != nil {
		return nil, &webauthn.UnmarshalSyntaxError{Type: "Android key attestation", Msg: err.Error()}
	}

	if raw.Alg == 0 {
		return nil, &webauthn.UnmarshalMissingFieldError{Type: "Android key attestation", Field: "alg"}
	}
	if len(raw.Sig) == 0 {
		return nil, &webauthn.UnmarshalMissingFieldError{Type: "Android key attestation", Field: "sig"}
	}
	if len(raw.X5C) == 0 {
		return nil, &webauthn.UnmarshalMissingFieldError{Type: "Android key attestation", Field: "x5c"}
	}

	attStmt := &androidKeyAttestationStatement{
		sig: raw.Sig,
	}

	if attStmt.SignatureAlgorithm, err = webauthn.CoseAlgToSignatureAlgorithm(raw.Alg); err != nil {
		return nil, err
	}

	for i := 0; i < len(raw.X5C); i++ {
		c, err := x509.ParseCertificate(raw.X5C[i])
		if err != nil {
			return nil, &webauthn.UnmarshalSyntaxError{Type: "Android key attestation", Field: fmt.Sprintf("x5c[%d]", i), Msg: err.Error()}
		}
		if i == 0 {
			attStmt.credCert = c
		} else {
			attStmt.caCerts = append(attStmt.caCerts, c)
		}
	}

	return attStmt, nil
}

// Verify implements the webauthn.AttestationStatement interface.  It follows
// android-key attestation statement verification procedure defined in
// http://w3c.github.io/webauthn/#sctn-android-key-attestation
func (attStmt *androidKeyAttestationStatement) Verify(clientDataHash []byte, authnData *webauthn.AuthenticatorData) (attType webauthn.AttestationType, trustPath interface{}, err error) {
	// Verify that root certificate is set to Android KeyStore Root certificate to detect fake attestations.
	if len(attStmt.caCerts) == 0 {
		err = &webauthn.VerificationError{Type: "Android key attestation", Field: "certificate", Msg: "certificate chain is empty"}
		return
	}
	if !attStmt.caCerts[len(attStmt.caCerts)-1].Equal(androidKeyStoreRootCert) {
		err = &webauthn.VerificationError{Type: "Android key attestation", Field: "certificate", Msg: "Android Keystore root certificate doesn't match received attestation certificate"}
		return
	}

	// Verify leaf certificate by building certificate chain.
	if trustPath, err = verifyAttestationCert(attStmt.credCert, attStmt.caCerts); err != nil {
		err = &webauthn.VerificationError{Type: "Android key attestation", Field: "certificate", Msg: err.Error()}
		return
	}

	// Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash
	// using the public key in the first certificate in x5c with algorithm specified in alg.
	rawAuthnData := authnData.Raw
	signed := make([]byte, len(rawAuthnData)+len(clientDataHash))
	copy(signed, rawAuthnData)
	copy(signed[len(rawAuthnData):], clientDataHash)

	if err = attStmt.credCert.CheckSignature(attStmt.Algorithm, signed, attStmt.sig); err != nil {
		err = &webauthn.VerificationError{Type: "Android key attestation", Field: "signature", Msg: err.Error()}
		return
	}

	// Verify that the public key in the first certificate in x5c matches the credentialPublicKey in the
	// attestedCredentialData in authenticatorData.
	if !reflect.DeepEqual(attStmt.credCert.PublicKey, authnData.Credential.PublicKey) {
		err = &webauthn.VerificationError{Type: "Android key attestation", Field: "certificate public key", Msg: "certificate public key does not match credential public key"}
		return
	}

	attestationChallenge, softwareEnforced, teeEnforced, err := parseAndroidKeyCertExtension(attStmt.credCert)
	if err != nil {
		err = &webauthn.VerificationError{Type: "Android key attestation", Field: "certificate extension " + oidAndroidKeyCertificateExt.String(), Msg: err.Error()}
		return
	}

	// Verify that the attestationChallenge field in the attestation certificate extension data is
	// identical to clientDataHash.
	if !bytes.Equal(attestationChallenge, clientDataHash[:]) {
		err = &webauthn.VerificationError{Type: "Android key attestation", Field: "certificate extension attestationChallenge", Msg: "attestationChallenge does not match clientDataHash"}
		return
	}

	// Verify the following using the appropriate authorization list from the attestatoin certificate extension data:
	// - The AuthorizationList.allApplications field is not present on either authorization list
	//   (softwareEnforced nor teeEnfored), since PublicKeyCredential must be scoped to the RP ID.
	if softwareEnforced.allApplications {
		err = &webauthn.VerificationError{Type: "Android key attestation", Field: "certificate extension softwareEnforced", Msg: "softwareEnforced has allApplications set"}
		return
	}
	if teeEnforced.allApplications {
		err = &webauthn.VerificationError{Type: "Android key attestation", Field: "certificate extension teeEnforced", Msg: "teeEnforced has allApplications set"}
		return
	}
	// - For the following, use only the teeEnforced authorization list if the RP wants to accept only keys from a
	//   trusted execution environment, otherwise use the union of teeEnfored and softwareEnfored.
	//   * The value in the AuthorizationList.origin field is equal to KM_ORIGIN_GENERATED.
	kmOriginGenerated := 0
	if softwareEnforced.origin != kmOriginGenerated && teeEnforced.origin != kmOriginGenerated {
		err = &webauthn.VerificationError{Type: "Android key attestation", Field: "certificate extension softwareEnforced and teeEnfored", Msg: "origin is not KM_ORIGIN_GENERATED"}
		return
	}
	//   * The value in the AuthorizationList.purpose field is equal to KM_PURPOSE_SIGN.
	kmPurposeSign := 2
	if (len(softwareEnforced.purpose) != 1 || softwareEnforced.purpose[0] != kmPurposeSign) &&
		(len(teeEnforced.purpose) != 1 || teeEnforced.purpose[0] != kmPurposeSign) {
		err = &webauthn.VerificationError{Type: "Android key attestation", Field: "certificate extension softwareEnforced and teeEnfored", Msg: "purpose is not KM_PURPOSE_SIGN"}
		return
	}

	// If successful, return implementation-specific values representing attestation type Basic and
	// attestation trust path x5c.
	return webauthn.AttestationTypeBasic, trustPath, nil
}

type authorizationList struct {
	allApplications bool
	purpose         []int
	origin          int
}

func parseAuthorizationList(data []byte) (*authorizationList, error) {
	authList := &authorizationList{}

	// purpose [1] EXPLICIT SET OF INTEGER OPTIONAL
	if _, err := asn1.UnmarshalWithParams(data, &authList.purpose, "explicit,set,optional,tag:1"); err != nil {
		return nil, errors.New("failed to unmarshal AuthorizationList purpose: " + err.Error())
	}

	// origin [702] EXPLICIT INTEGER OPTIONAL
	if _, err := asn1.UnmarshalWithParams(data, &authList.origin, "explicit,optional,tag:702"); err != nil {
		return nil, errors.New("failed to unmarshal AuthorizationList origin: " + err.Error())
	}

	// allApplications [600] EXPLICIT NULL OPTIONAL
	if _, err := asn1.UnmarshalWithParams(data, &authList.allApplications, "explicit,optional,tag:600"); err != nil {
		return nil, errors.New("failed to unmarshal AuthorizationList allApplications: " + err.Error())
	}

	return authList, nil
}

func parseAndroidKeyCertExtension(cert *x509.Certificate) (attestationChallenge []byte, softwareEnforced *authorizationList, teeEnforced *authorizationList, err error) {
	var extValue []byte
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidAndroidKeyCertificateExt) {
			extValue = ext.Value
			break
		}
	}
	if len(extValue) == 0 {
		return nil, nil, nil, errors.New("missing certificate extension")
	}

	var seq asn1.RawValue
	var rest []byte
	rest, err = asn1.Unmarshal(extValue, &seq)
	if err != nil {
		return nil, nil, nil, errors.New("failed to unmarshal certificate extension: " + err.Error())
	} else if len(rest) != 0 {
		return nil, nil, nil, errors.New("trailing data after certificate extension")
	}
	if !seq.IsCompound || seq.Tag != asn1.TagSequence || seq.Class != asn1.ClassUniversal {
		return nil, nil, nil, errors.New("bad data")
	}

	rest = seq.Bytes
	for i := 0; len(rest) > 0; i++ {
		var v asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			return nil, nil, nil, errors.New("failed to unmarshal certificate extension element: " + err.Error())
		}
		if i == 4 {
			attestationChallenge = v.Bytes
		} else if i == 6 {
			if softwareEnforced, err = parseAuthorizationList(v.Bytes); err != nil {
				return nil, nil, nil, err
			}
		} else if i == 7 {
			if teeEnforced, err = parseAuthorizationList(v.Bytes); err != nil {
				return nil, nil, nil, err
			}
		}
	}
	return attestationChallenge, softwareEnforced, teeEnforced, nil
}

func verifyAttestationCert(attestnCert *x509.Certificate, caCerts []*x509.Certificate) (trustPath []*x509.Certificate, err error) {
	var verifyOptions x509.VerifyOptions

	if len(caCerts) > 0 {
		lastCert := caCerts[len(caCerts)-1]
		if bytes.Equal(lastCert.RawIssuer, lastCert.RawSubject) && lastCert.IsCA {
			caCerts = caCerts[:len(caCerts)-1]

			verifyOptions.Roots = x509.NewCertPool()
			verifyOptions.Roots.AddCert(lastCert)
		}
		if len(caCerts) > 0 {
			verifyOptions.Intermediates = x509.NewCertPool()
			for _, c := range caCerts {
				verifyOptions.Intermediates.AddCert(c)
			}
		}
	}

	var chains [][]*x509.Certificate
	if chains, err = attestnCert.Verify(verifyOptions); err != nil {
		return nil, err
	}
	return chains[0], nil
}

func init() {
	block, _ := pem.Decode([]byte(androidKeyStoreRootCertPem))
	if block == nil {
		panic("failed to PEM decode Android KeyStore root certificate")
	}

	var err error
	if androidKeyStoreRootCert, err = x509.ParseCertificate(block.Bytes); err != nil {
		panic("failed to parse Android KeyStore root certificate: " + err.Error())
	}

	webauthn.RegisterAttestationFormat("android-key", parseAttestation)
}
