// Copyright (c) 2019 Faye Amacker. All rights reserved.
// Use of this source code is governed by Apache License 2.0 found in the LICENSE file.

package androidsafetynet

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/fxamacker/cbor"
	"github.com/fxamacker/webauthn"
)

// Google GlobalSign Root CA R2, converted from https://pki/goog/gsr2/GSR2.crt.
const googleGlobalSignRootCAR2CertPem = `
-----BEGIN CERTIFICATE-----
MIIDujCCAqKgAwIBAgILBAAAAAABD4Ym5g0wDQYJKoZIhvcNAQEFBQAwTDEgMB4G
A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjIxEzARBgNVBAoTCkdsb2JhbFNp
Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDYxMjE1MDgwMDAwWhcNMjExMjE1
MDgwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMjETMBEG
A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAKbPJA6+Lm8omUVCxKs+IVSbC9N/hHD6ErPL
v4dfxn+G07IwXNb9rfF73OX4YJYJkhD10FPe+3t+c4isUoh7SqbKSaZeqKeMWhG8
eoLrvozps6yWJQeXSpkqBy+0Hne/ig+1AnwblrjFuTosvNYSuetZfeLQBoZfXklq
tTleiDTsvHgMCJiEbKjNS7SgfQx5TfC4LcshytVsW33hoCmEofnTlEnLJGKRILzd
C9XZzPnqJworc5HGnRusyMvo4KD0L5CLTfuwNhv2GXqF4G3yYROIXJ/gkwpRl4pa
zq+r1feqCapgvdzZX99yqWATXgAByUr6P6TqBwMhAo6CygPCm48CAwEAAaOBnDCB
mTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUm+IH
V2ccHsBqBt5ZtJot39wZhi4wNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5n
bG9iYWxzaWduLm5ldC9yb290LXIyLmNybDAfBgNVHSMEGDAWgBSb4gdXZxwewGoG
3lm0mi3f3BmGLjANBgkqhkiG9w0BAQUFAAOCAQEAmYFThxxol4aR7OBKuEQLq4Gs
J0/WwbgcQ3izDJr86iw8bmEbTUsp9Z8FHSbBuOmDAGJFtqkIk7mpM0sYmsL4h4hO
291xNBrBVNpGP+DTKqttVCL1OmLNIG+6KYnX3ZHu01yiPqFbQfXf5WRDLenVOavS
ot+3i9DAgBkcRcAtjOj4LaR0VknFBbVPFd5uRHg5h6h+u/N5GJG79G+dwfCMNYxd
AfvDbbnvRG15RjF+Cv6pgsH/76tuIMRQyV+dTZsXjAzlAcmgQWpzU/qlULRuJQ/7
TBj0/VLZjmmx6BEP3ojY+x1J96relc8geMJgEtslQIxq/H5COEBkEveegeGTLg==
-----END CERTIFICATE-----`

var (
	googleGlobalSignRootCAR2Cert *x509.Certificate
	jwtSigAlg                    = map[string]x509.SignatureAlgorithm{
		"RS256": x509.SHA256WithRSA,
		"RS384": x509.SHA384WithRSA,
		"RS512": x509.SHA512WithRSA,
		"PS256": x509.SHA256WithRSAPSS,
		"PS384": x509.SHA384WithRSAPSS,
		"PS512": x509.SHA512WithRSAPSS,
		"ES256": x509.ECDSAWithSHA256,
		"ES384": x509.ECDSAWithSHA384,
		"ES512": x509.ECDSAWithSHA512,
	}
)

type header struct {
	alg         string
	attestnCert *x509.Certificate
	caCerts     []*x509.Certificate
}

type payload struct {
	Nonce                      string   `json:"nonce"`
	TimestampMS                uint64   `json:"timestampMs"`
	APKPackageName             string   `json:"apkPackageName"`
	APKCertificateDigestSHA256 []string `json:"apkCertificateDigestSha256"`
	APKDigestSHA256            string   `json:"apkDigestSha256"`
	CTSProfileMatch            bool     `json:"ctsProfileMatch"`
	BasicIntegrity             bool     `json:"basicIntegrity"`
}

type androidSafetyNetAttestationStatement struct {
	ver          string // Version number of Google Play Services responsible for providing the SafetyNet API.
	rawHeader    []byte
	rawPayload   []byte
	rawSignature []byte
	*header
	*payload
	sig []byte
}

func parseAttestation(data []byte) (webauthn.AttestationStatement, error) {
	type rawAttStmt struct {
		Ver      string `cbor:"ver"`
		Response []byte `cbor:"response"` // UTF-8 encoded result of the getJwsResult() call of the SafetyNet API.  This value is a JWS object in Compact Serialization.
	}

	var raw rawAttStmt
	var err error
	if err = cbor.Unmarshal(data, &raw); err != nil {
		return nil, &webauthn.UnmarshalSyntaxError{Type: "Android safetynet attestation", Msg: err.Error()}
	}

	parsedJWS := bytes.Split(raw.Response, []byte("."))
	if len(parsedJWS) != 3 {
		return nil, &webauthn.UnmarshalBadDataError{Type: "Android safetynet attestation", Msg: fmt.Sprintf("JWS Compact Serialization format expects 3 parts, got %d parts", len(parsedJWS))}
	}

	attStmt := &androidSafetyNetAttestationStatement{
		ver:          raw.Ver,
		rawHeader:    parsedJWS[0],
		rawPayload:   parsedJWS[1],
		rawSignature: parsedJWS[2],
	}

	n := base64.RawURLEncoding.DecodedLen(len(attStmt.rawHeader))
	headerBytes := make([]byte, n)
	if n, err = base64.RawURLEncoding.Decode(headerBytes, attStmt.rawHeader); err != nil {
		return nil, &webauthn.UnmarshalBadDataError{Type: "Android safetynet attestation", Msg: "failed to base64 decode header: " + err.Error()}
	}
	headerBytes = headerBytes[:n]

	if attStmt.header, err = parseHeader(headerBytes); err != nil {
		return nil, err
	}

	n = base64.RawURLEncoding.DecodedLen(len(attStmt.rawPayload))
	payloadBytes := make([]byte, n)
	if n, err = base64.RawURLEncoding.Decode(payloadBytes, attStmt.rawPayload); err != nil {
		return nil, &webauthn.UnmarshalBadDataError{Type: "Android safetynet attestation", Msg: "failed to base64 decode payload: " + err.Error()}
	}
	payloadBytes = payloadBytes[:n]

	attStmt.payload = &payload{}
	if err = json.Unmarshal(payloadBytes, attStmt.payload); err != nil {
		return nil, &webauthn.UnmarshalSyntaxError{Type: "Android safetynet attestation", Field: "payload", Msg: err.Error()}
	}

	n = base64.RawURLEncoding.DecodedLen(len(attStmt.rawSignature))
	signatureBytes := make([]byte, n)
	if n, err = base64.RawURLEncoding.Decode(signatureBytes, attStmt.rawSignature); err != nil {
		return nil, &webauthn.UnmarshalBadDataError{Type: "Android safetynet attestation", Msg: "failed to base64 decode signature: " + err.Error()}
	}
	attStmt.sig = signatureBytes[:n]

	return attStmt, nil
}

func parseHeader(data []byte) (h *header, err error) {
	type rawHeader struct {
		Alg string   `json:"alg"`
		X5C [][]byte `json:"x5c"`
	}

	var raw rawHeader
	if err = json.Unmarshal(data, &raw); err != nil {
		return nil, &webauthn.UnmarshalSyntaxError{Type: "Android safetynet attestation", Field: "header", Msg: err.Error()}
	}

	if len(raw.X5C) == 0 {
		return nil, &webauthn.UnmarshalMissingFieldError{Type: "Android safetynet attestation", Field: "header.x5c"}
	}

	h = &header{
		alg: raw.Alg,
	}

	for i := 0; i < len(raw.X5C); i++ {
		c, err := x509.ParseCertificate(raw.X5C[i])
		if err != nil {
			return nil, &webauthn.UnmarshalSyntaxError{Type: "Android safetynet attestation", Field: fmt.Sprintf("x5c[%d]", i), Msg: err.Error()}
		}
		if i == 0 {
			h.attestnCert = c
		} else {
			h.caCerts = append(h.caCerts, c)
		}
	}

	return
}

// Verify implements the webauthn.AttestationStatement interface.  It follows
// android-key attestation statement verification procedure defined in
// http://w3c.github.io/webauthn/#sctn-android-safetynet-attestation
func (attStmt *androidSafetyNetAttestationStatement) Verify(clientDataHash []byte, authnData *webauthn.AuthenticatorData) (attType webauthn.AttestationType, trustPath interface{}, err error) {
	// todo: Verify that response is a valid SafetyNet response of version ver.

	// Verify that the nonce in the response is identical to the Base64 encoding of the SHA-256
	// hash of the concatenation of authenticatorData and clientDataHash.
	rawAuthnData := authnData.Raw
	nonceBase := make([]byte, len(rawAuthnData)+len(clientDataHash))
	copy(nonceBase, rawAuthnData)
	copy(nonceBase[len(rawAuthnData):], clientDataHash)
	nonceBuffer := sha256.Sum256(nonceBase)
	expectedNonce := base64.StdEncoding.EncodeToString(nonceBuffer[:])
	if expectedNonce != attStmt.Nonce {
		err = &webauthn.VerificationError{Type: "Android safetynet attestation", Field: "nonce", Msg: "attestation nonce does not match computed nonce"}
		return
	}

	// Verify that attestationCert is issued to the hostname "attest.android.com".
	hostname := "attest.android.com"
	if err = attStmt.attestnCert.VerifyHostname(hostname); err != nil {
		err = &webauthn.VerificationError{Type: "Android safetynet attestation", Field: "certificate hostname", Msg: "attestation certificate is not issued to the hostname \"" + hostname + "\""}
		return
	}

	// Verify that the ctsProfileMatch attribute in the payload of response is true.
	if !attStmt.CTSProfileMatch {
		err = &webauthn.VerificationError{Type: "Android safetynet attestation", Field: "payload.ctsProfileMatch ", Msg: "ctsProfileMatch is false"}
		return
	}

	// Verify attestation certificate by building certificate chain.
	if trustPath, err = verifyAttestationCert(attStmt.attestnCert, attStmt.caCerts); err != nil {
		err = &webauthn.VerificationError{Type: "Android safetynet attestation", Field: "certificate", Msg: err.Error()}
		return
	}

	// Verify JWT signature
	sigAlg, ok := jwtSigAlg[attStmt.alg]
	if !ok {
		err = &webauthn.UnsupportedFeatureError{Feature: "android safetynet attestation alg" + attStmt.alg}
		return
	}

	// Concatenate Base64URL encoded header and payload with full stop, to create signatureBase.
	var signatureBase bytes.Buffer
	signatureBase.Write(attStmt.rawHeader)
	signatureBase.Write([]byte("."))
	signatureBase.Write(attStmt.rawPayload)

	// Verify signature over signatureBase using the public key extracted from leaf certificate.
	if err = attStmt.attestnCert.CheckSignature(sigAlg, signatureBase.Bytes(), attStmt.sig); err != nil {
		err = &webauthn.VerificationError{Type: "Android safetynet attestation", Field: "signature", Msg: err.Error()}
		return
	}

	// If successful, return implementation-specific values representing attestation type Basic and
	// attestation trust path attestationCert.
	return webauthn.AttestationTypeBasic, trustPath, nil
}

func verifyAttestationCert(attestnCert *x509.Certificate, caCerts []*x509.Certificate) (trustPath []*x509.Certificate, err error) {
	var verifyOptions x509.VerifyOptions

	verifyOptions.Roots = x509.NewCertPool()
	verifyOptions.Roots.AddCert(googleGlobalSignRootCAR2Cert)

	if len(caCerts) > 0 {
		verifyOptions.Intermediates = x509.NewCertPool()
		for _, c := range caCerts {
			verifyOptions.Intermediates.AddCert(c)
		}
	}

	var chains [][]*x509.Certificate
	chains, err = attestnCert.Verify(verifyOptions)
	if err != nil {
		return nil, err
	}
	return chains[0], nil
}

func init() {
	block, _ := pem.Decode([]byte(googleGlobalSignRootCAR2CertPem))
	if block == nil {
		panic("failed to PEM decode Google GlobalSign Root CA R2")
	}

	var err error
	if googleGlobalSignRootCAR2Cert, err = x509.ParseCertificate(block.Bytes); err != nil {
		panic("failed to parse Google GlobalSign Root CA R2: " + err.Error())
	}

	webauthn.RegisterAttestationFormat("android-safetynet", parseAttestation)
}
