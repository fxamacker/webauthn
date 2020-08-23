/*
Copyright 2019-present Faye Amacker.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
Package webauthn provides server-side registration and authentication for clients
using FIDO2 keys, FIDO U2F keys, tpm, etc. and is decoupled from `net/http` for
easy integration with existing projects.

It's modular so projects only import what is needed. Five attestation packages are
available: fidou2f, androidkeystore, androidsafetynet, packed, and tpm.

It doesn't import unreliable packages. It uses fxamacker/cbor because it doesn't
crash and it's the most well-tested CBOR library available (v1.5 has 375+ tests
and passed 3+ billion execs in coverage-guided fuzzing).

A demo webapp (https://www.github.com/fxamacker/webauthn-demo) shows how to use
this package with a security token like the YubiKey.
*/
package webauthn

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// User represents user data for which the Relying Party requests attestation or assertion.
type User struct {
	ID            []byte
	Name          string
	Icon          string
	DisplayName   string
	CredentialIDs [][]byte
}

// AttestationExpectedData represents data needed to verify attestations.
type AttestationExpectedData struct {
	Origin           string
	RPID             string
	CredentialAlgs   []int
	Challenge        string
	UserVerification UserVerificationRequirement
}

// AssertionExpectedData represents data needed to verify assertions.
type AssertionExpectedData struct {
	Origin            string
	RPID              string
	Challenge         string
	UserVerification  UserVerificationRequirement
	UserID            []byte
	UserCredentialIDs [][]byte
	PrevCounter       uint32
	Credential        *Credential
}

// NewAttestationOptions returns a PublicKeyCredentialCreationOptions from config and user.
func NewAttestationOptions(config *Config, user *User) (*PublicKeyCredentialCreationOptions, error) {
	if len(user.Name) == 0 {
		return nil, errors.New("user name is required")
	}
	if len(user.ID) == 0 {
		return nil, errors.New("user id is required")
	}
	if len(user.DisplayName) == 0 {
		return nil, errors.New("user display name is required")
	}

	challenge := make([]byte, config.ChallengeLength)
	if _, err := rand.Read(challenge); err != nil {
		return nil, errors.New("failed to generate challenge: " + err.Error())
	}

	var excludeCredentials []PublicKeyCredentialDescriptor
	for _, id := range user.CredentialIDs {
		excludeCredentials = append(excludeCredentials, PublicKeyCredentialDescriptor{Type: PublicKeyCredentialTypePublicKey, ID: id})
	}

	var credentialParams []PublicKeyCredentialParameters
	for _, alg := range config.CredentialAlgs {
		credentialParams = append(credentialParams, PublicKeyCredentialParameters{PublicKeyCredentialTypePublicKey, alg})
	}

	options := &PublicKeyCredentialCreationOptions{
		RP: PublicKeyCredentialRpEntity{
			Name: config.RPName,
			Icon: config.RPIcon,
			ID:   config.RPID,
		},
		User: PublicKeyCredentialUserEntity{
			Name:        user.Name,
			Icon:        user.Icon,
			ID:          user.ID,
			DisplayName: user.DisplayName,
		},
		Challenge:          challenge,
		PubKeyCredParams:   credentialParams,
		Timeout:            config.Timeout,
		ExcludeCredentials: excludeCredentials,
		AuthenticatorSelection: AuthenticatorSelectionCriteria{
			AuthenticatorAttachment: config.AuthenticatorAttachment,
			RequireResidentKey:      config.ResidentKey == ResidentKeyRequired,
			ResidentKey:             config.ResidentKey,
			UserVerification:        config.UserVerification,
		},
		Attestation: config.Attestation,
	}

	return options, nil
}

// ParseAttestation parses credential attestation and returns PublicKeyCredentialAttestation.
func ParseAttestation(r io.Reader) (*PublicKeyCredentialAttestation, error) {
	var credentialAttestation PublicKeyCredentialAttestation
	if err := json.NewDecoder(r).Decode(&credentialAttestation); err != nil {
		return nil, err
	}
	return &credentialAttestation, nil
}

// VerifyAttestation verifies attestation and returns attestation type, trust path, or error,
// as defined in http://w3c.github.io/webauthn/#sctn-registering-a-new-credential
func VerifyAttestation(credentialAttestation *PublicKeyCredentialAttestation, expected *AttestationExpectedData) (attType AttestationType, trustPath interface{}, err error) {
	// Verify that the value of C.type is webauthn.create.
	if credentialAttestation.ClientData.Type != "webauthn.create" {
		err = &VerificationError{Type: "attestation", Field: "client data type", Msg: "expected \"webauthn.create\", got \"" + credentialAttestation.ClientData.Type + "\""}
		return
	}

	// Verify that the value of C.challenge equals the base64url encoding of options.challenge.
	if credentialAttestation.ClientData.Challenge != expected.Challenge {
		err = &VerificationError{Type: "attestation", Field: "client data challenge", Msg: "client data challenge does not match expected challenge"}
		return
	}

	// Verify that the value of C.origin matches the Relying Party's origin.
	if credentialAttestation.ClientData.Origin != expected.Origin {
		err = &VerificationError{Type: "attestation", Field: "client data origin", Msg: "expected \"" + expected.Origin + "\", got \"" + credentialAttestation.ClientData.Origin + "\""}
		return
	}

	// Verify that authData's credential id matches the credential's raw id.
	if !bytes.Equal(credentialAttestation.RawID, credentialAttestation.AuthnData.CredentialID) {
		err = &VerificationError{Type: "attestation", Field: "credential ID", Msg: "attestation's raw ID does not match credential ID"}
		return
	}

	// Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
	computedRPIDHash := sha256.Sum256([]byte(expected.RPID))
	if !bytes.Equal(credentialAttestation.AuthnData.RPIDHash, computedRPIDHash[:]) {
		err = &VerificationError{Type: "attestation", Field: "rp ID", Msg: "authenticator data's rp ID hash does not match computed rp ID hash"}
		return
	}

	// Verify that the User Present bit of the flags in authData is set.
	if !credentialAttestation.AuthnData.UserPresent {
		err = &VerificationError{Type: "attestation", Field: "user present", Msg: "user wasn't present"}
		return
	}

	// If user verification is required for this registration, verify that the User Verified bit of the flags in authData is set.
	if expected.UserVerification == UserVerificationRequired && !credentialAttestation.AuthnData.UserVerified {
		err = &VerificationError{Type: "attestation", Field: "user verification", Msg: "user didn't verify"}
		return
	}

	// Verify that the "alg" parameter in the credential public key in authData matches the alg
	// attribute of one of the items in options.pubKeyCredParams.
	foundAlg := false
	for _, alg := range expected.CredentialAlgs {
		if alg == credentialAttestation.AuthnData.Credential.COSEAlgorithm {
			foundAlg = true
			break
		}
	}
	if !foundAlg {
		err = &VerificationError{Type: "attestation", Field: "credential algorithm", Msg: "credential algorithm is not among options.pubKeyCredParams."}
		return
	}

	// todo: Verify that the value of C.tokenBinding.status matches the state of Token Binding for
	// the TLS connection over which the assertion was obtained. If Token Binding was used on that
	// TLS connection, also verify that C.tokenBinding.id matches the base64url encoding of the
	// Token Binding ID for the connection.

	// todo: Verify that the values of the client extension outputs in clientExtensionResults and
	// the authenticator extension outputs in the extensions in authData are as expected.

	return credentialAttestation.VerifyAttestationStatement()
}

// NewAssertionOptions returns a PublicKeyCredentialRequestOptions from config and user.
func NewAssertionOptions(config *Config, user *User) (*PublicKeyCredentialRequestOptions, error) {
	challenge := make([]byte, config.ChallengeLength)
	if _, err := rand.Read(challenge); err != nil {
		return nil, errors.New("failed to generate challenge: " + err.Error())
	}

	var allowCredentials []PublicKeyCredentialDescriptor
	for _, id := range user.CredentialIDs {
		allowCredentials = append(allowCredentials, PublicKeyCredentialDescriptor{Type: PublicKeyCredentialTypePublicKey, ID: id})
	}

	options := &PublicKeyCredentialRequestOptions{
		Challenge:        challenge,
		Timeout:          config.Timeout,
		RPID:             config.RPID,
		AllowCredentials: allowCredentials,
		UserVerification: config.UserVerification,
	}

	return options, nil
}

// ParseAssertion parses credential assertion and returns PublicKeyCredentialAssertion.
func ParseAssertion(r io.Reader) (*PublicKeyCredentialAssertion, error) {
	var credentialAssertion PublicKeyCredentialAssertion
	if err := json.NewDecoder(r).Decode(&credentialAssertion); err != nil {
		return nil, err
	}
	return &credentialAssertion, nil
}

// VerifyAssertion verifies assertion and returns error, as defined in http://w3c.github.io/webauthn/#sctn-verifying-assertion
func VerifyAssertion(credentialAssertion *PublicKeyCredentialAssertion, expected *AssertionExpectedData) error {
	// Verify that credential.id identifies one of the public key credentials listed in options.allowCredentials.
	foundCredentialID := false
	for _, id := range expected.UserCredentialIDs {
		if bytes.Equal(id, credentialAssertion.RawID) {
			foundCredentialID = true
			break
		}
	}
	if len(expected.UserCredentialIDs) > 0 && !foundCredentialID {
		return &VerificationError{Type: "assertion", Field: "credential ID", Msg: "credential ID is not allowed"}
	}

	// Verify that userHandle also is the owner of the public key credential.
	if len(credentialAssertion.UserHandle) > 0 {
		if !bytes.Equal(credentialAssertion.UserHandle, expected.UserID) {
			return &VerificationError{Type: "assertion", Field: "user handle", Msg: fmt.Sprintf("expected %02x, got %02x", expected.UserID, credentialAssertion.UserHandle)}
		}
	}

	// Verify that the value of C.type is the string webauthn.get.
	if credentialAssertion.ClientData.Type != "webauthn.get" {
		return &VerificationError{Type: "assertion", Field: "client data type", Msg: "expected \"webauthn.get\", got \"" + credentialAssertion.ClientData.Type + "\""}
	}

	// Verify that the value of C.challenge equals the base64url encoding of options.challenge.
	if credentialAssertion.ClientData.Challenge != expected.Challenge {
		return &VerificationError{Type: "assertion", Field: "client data challenge", Msg: "client data challenge does not match expected challenge"}
	}

	// Verify that the value of C.origin matches the Relying Party's origin.
	if credentialAssertion.ClientData.Origin != expected.Origin {
		return &VerificationError{Type: "assertion", Field: "client data origin", Msg: "expected \"" + expected.Origin + "\", got \"" + credentialAssertion.ClientData.Origin + "\""}
	}

	// Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
	computedRPIDHash := sha256.Sum256([]byte(expected.RPID))
	if !bytes.Equal(credentialAssertion.AuthnData.RPIDHash, computedRPIDHash[:]) {
		return &VerificationError{Type: "assertion", Field: "rp ID", Msg: "authenticator data's rp ID hash does not match computed rp ID hash"}
	}

	// Verify that the User Present bit of the flags in authData is set.
	if !credentialAssertion.AuthnData.UserPresent {
		return &VerificationError{Type: "assertion", Field: "user present", Msg: "user wasn't present"}
	}

	// If user verification is required for this assertion, verify that the User Verified bit of the flags in authData is set.
	if expected.UserVerification == UserVerificationRequired && !credentialAssertion.AuthnData.UserVerified {
		return &VerificationError{Type: "assertion", Field: "user verification", Msg: "user didn't verify"}
	}

	// Using credentialPublicKey, verify that sig is a valid signature over the binary concatenation of authData and hash.
	if err := credentialAssertion.verifySignature(expected.Credential); err != nil {
		return err
	}

	// Verify that authData.signCount does not roll back.
	if credentialAssertion.AuthnData.Counter != 0 || expected.PrevCounter != 0 {
		if credentialAssertion.AuthnData.Counter <= expected.PrevCounter {
			return &VerificationError{Type: "assertion", Field: "counter", Msg: "cloned authenticator is detected"}
		}
	}

	// todo: Verify that the value of C.tokenBinding.status matches the state of Token Binding for
	// the TLS connection over which the attestation was obtained. If Token Binding was used on
	// that TLS connection, also verify that C.tokenBinding.id matches the base64url encoding of
	// the Token Binding ID for the connection.

	// todo: Verify that the values of the client extension outputs in clientExtensionResults and
	// the authenticator extension outputs in the extensions in authData are as expected.

	return nil
}
