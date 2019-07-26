// Copyright (c) 2019 Faye Amacker. All rights reserved.
// Use of this source code is governed by Apache License 2.0 found in the LICENSE file.

package fidou2f

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"

	"github.com/fxamacker/cbor"
	"github.com/fxamacker/webauthn"
)

type fidou2fAttestationStatement struct {
	sig         []byte
	attestnCert *x509.Certificate
}

func parseAttestation(data []byte) (webauthn.AttestationStatement, error) {
	type rawAttStmt struct {
		Sig []byte   `cbor:"sig"`
		X5C [][]byte `cbor:"x5c"` // A single element array containing the attestation certificate in X.509 format.
	}
	var raw rawAttStmt
	var err error
	if err = cbor.Unmarshal(data, &raw); err != nil {
		return nil, &webauthn.UnmarshalSyntaxError{Type: "fido u2f attestation", Msg: err.Error()}
	}

	if len(raw.X5C) != 1 {
		return nil, &webauthn.UnmarshalBadDataError{Type: "fido u2f attestation", Msg: fmt.Sprintf("expected 1 attestation certificate, got %d certificates", len(raw.X5C))}
	}

	attStmt := &fidou2fAttestationStatement{sig: raw.Sig}

	if attStmt.attestnCert, err = x509.ParseCertificate(raw.X5C[0]); err != nil {
		return nil, &webauthn.UnmarshalSyntaxError{Type: "fido u2f attestation", Field: "x5c[0]", Msg: err.Error()}
	}

	return attStmt, nil
}

// Verify implements the webauthn.AttestationStatement interface.  It follows
// fido-u2f attestation statement verification procedure defined in
// http://w3c.github.io/webauthn/#sctn-fido-u2f-attestation
func (attStmt *fidou2fAttestationStatement) Verify(clientDataHash []byte, authnData *webauthn.AuthenticatorData) (attType webauthn.AttestationType, trustPath interface{}, err error) {
	// If certificate public key is not an Elliptic Curve (EC) public key over the P-256 curve,
	// terminate this algorithm and return an appropriate error.
	certificatePublicKey, ok := attStmt.attestnCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		err = &webauthn.VerificationError{Type: "fido u2f attestation", Field: "certificate public key", Msg: "certificate public key is not an Elliptic Curve public key"}
		return
	}
	if certificatePublicKey.Params().BitSize != 256 {
		err = &webauthn.VerificationError{Type: "fido u2f attestation", Field: "certificate public key", Msg: "certificate public key is not an Elliptic Curve public key over the P-256 curve"}
		return
	}

	// Convert credentialPublicKey to Raw ANSI X9.62 public key format.
	credentialPublicKey, ok := authnData.Credential.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		err = &webauthn.VerificationError{Type: "fido u2f attestation", Field: "credential public key", Msg: "credential public key is not an Elliptic Curve public key"}
		return
	}
	if credentialPublicKey.Curve.Params().BitSize != 256 {
		err = &webauthn.VerificationError{Type: "fido u2f attestation", Field: "credential public key", Msg: "credential public key is not an Elliptic Curve public key over the P-256 curve"}
		return
	}
	credentialPublicKeyX962 := elliptic.Marshal(credentialPublicKey.Curve, credentialPublicKey.X, credentialPublicKey.Y)

	// Let verificationData be the concatenation of (0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F)
	var verificationDataBuffer bytes.Buffer
	verificationDataBuffer.WriteByte(0x00)
	verificationDataBuffer.Write(authnData.RPIDHash)
	verificationDataBuffer.Write(clientDataHash)
	verificationDataBuffer.Write(authnData.CredentialID)
	verificationDataBuffer.Write(credentialPublicKeyX962)
	verificationData := verificationDataBuffer.Bytes()

	// Verify the sig using verificationData and certificate public key.
	if err = attStmt.attestnCert.CheckSignature(x509.ECDSAWithSHA256, verificationData, attStmt.sig); err != nil {
		err = &webauthn.VerificationError{Type: "fido u2f attestation", Field: "signature", Msg: err.Error()}
		return
	}

	// Optionally, inspect x5c and consult externally provided knowledge to determine whether
	// attStmt conveys a Basic or AttCA attestation.

	// If successful, return implementation-specific values representing attestation type Basic,
	// AttCA or uncertainty, and attesation trust path x5c.
	return webauthn.AttestationTypeBasic, []*x509.Certificate{attStmt.attestnCert}, nil
}

func init() {
	webauthn.RegisterAttestationFormat("fido-u2f", parseAttestation)
}
