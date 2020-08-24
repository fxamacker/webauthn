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

package webauthn

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"sync"

	"github.com/fxamacker/cbor/v2"
)

// AttestationType identifies an attestation trust model.
type AttestationType int

// Attestation types are defined in http://w3c.github.io/webauthn/#sctn-attestation-types
const (
	AttestationTypeBasic AttestationType = iota + 1
	AttestationTypeSelf
	AttestationTypeCA
	AttestationTypeECDAA
	AttestationTypeNone
)

func (attType AttestationType) String() string {
	switch attType {
	case AttestationTypeBasic:
		return "Basic"
	case AttestationTypeSelf:
		return "Self"
	case AttestationTypeCA:
		return "AttCA"
	case AttestationTypeECDAA:
		return "ECDAA"
	case AttestationTypeNone:
		return "None"
	default:
		return "Undefined"
	}
}

// AttestationStatement is the common interface implemented by all attestation statements.
type AttestationStatement interface {
	// Verify verifies an attestation statement and returns attestation type and trust path, or an error.
	Verify(clientDataHash []byte, authnData *AuthenticatorData) (attType AttestationType, trustPath interface{}, err error)
}

func parseAttestationObject(data []byte) (authnData *AuthenticatorData, attStmt AttestationStatement, err error) {
	type rawAttestationObject struct {
		AuthnData []byte          `cbor:"authData"`
		Fmt       string          `cbor:"fmt"`
		AttStmt   cbor.RawMessage `cbor:"attStmt"`
	}
	var raw rawAttestationObject
	if err = cbor.Unmarshal(data, &raw); err != nil {
		return nil, nil, &UnmarshalSyntaxError{Type: "attestation object", Msg: err.Error()}
	}
	if len(raw.AuthnData) == 0 {
		return nil, nil, &UnmarshalMissingFieldError{Type: "attestation object", Field: "authenticator data"}
	}
	if len(raw.Fmt) == 0 {
		return nil, nil, &UnmarshalMissingFieldError{Type: "attestation object", Field: "attestation statement format"}
	}

	if authnData, _, err = parseAuthenticatorData(raw.AuthnData); err != nil {
		return nil, nil, err
	}
	// Verify that credential id and credential are not empty.
	if len(authnData.CredentialID) == 0 || authnData.Credential == nil {
		return nil, nil, &UnmarshalMissingFieldError{Type: "attestation object", Field: "credential data"}
	}
	if attStmt, err = parseAttestationStatement(raw.Fmt, raw.AttStmt); err != nil {
		return nil, nil, err
	}
	return
}

// PublicKeyCredentialAttestation represents the Web Authentication structure of PublicKeyCredential
// for new credentials, as defined in http://w3c.github.io/webauthn/#iface-pkcredential
type PublicKeyCredentialAttestation struct {
	ID         string
	RawID      []byte
	ClientData *CollectedClientData
	AuthnData  *AuthenticatorData
	AttStmt    AttestationStatement
}

// UnmarshalJSON implements json.Unmarshaler interface.  rawId, clientDataJSON, and attestationObject
// are base64 URL encoded.
func (credentialAttestation *PublicKeyCredentialAttestation) UnmarshalJSON(data []byte) (err error) {
	type rawAuthenticatorAttestationResponse struct {
		ClientDataJSON    string `json:"clientDataJSON"`    // JSON-serialized client data passed to the authenticator by the client.
		AttestationObject string `json:"attestationObject"` // Attestation object, containing authenticator data and attestation statement.
	}
	type rawPublicKeyCredential struct {
		ID       string                              `json:"id,omitempty"`    // base64 url encoded credential ID.
		RawID    string                              `json:"rawId,omitempty"` // Raw credential ID.
		Response rawAuthenticatorAttestationResponse `json:"response"`        // Authenticator's response to client's request to create a public key credential.
		Type     string                              `json:"type"`            // "public-key"
	}
	var raw rawPublicKeyCredential
	if err = json.Unmarshal(data, &raw); err != nil {
		return &UnmarshalSyntaxError{Type: "attestation", Msg: err.Error()}
	}

	// Check for empty data.
	if len(raw.ID) == 0 && len(raw.RawID) == 0 {
		return &UnmarshalMissingFieldError{Type: "attestation", Field: "credential id and raw id"}
	}
	if len(raw.Response.ClientDataJSON) == 0 {
		return &UnmarshalMissingFieldError{Type: "attestation", Field: "client data"}
	}
	if len(raw.Response.AttestationObject) == 0 {
		return &UnmarshalMissingFieldError{Type: "attestation", Field: "attestation object"}
	}
	if len(raw.Type) == 0 {
		return &UnmarshalMissingFieldError{Type: "attestation", Field: "type"}
	}

	if raw.Type != "public-key" {
		return &UnmarshalBadDataError{Type: "attestation", Msg: "expected type as \"public-key\", got \"" + raw.Type + "\""}
	}

	// base64 decode RawID, ClientDataJSON, and AttestationObject.
	var rawID []byte
	if len(raw.RawID) > 0 {
		rawID, err = base64DecodeString(raw.RawID)
		if err != nil {
			return &UnmarshalBadDataError{Type: "attestation", Msg: "failed to base64 decode credential raw id"}
		} else if len(rawID) == 0 {
			return &UnmarshalBadDataError{Type: "attestation", Msg: "base64 decoded credential raw id is empty"}
		}
	}
	rawClientDataJSON, err := base64DecodeString(raw.Response.ClientDataJSON)
	if err != nil {
		return &UnmarshalBadDataError{Type: "attestation", Msg: "failed to base64 decode client data"}
	} else if len(rawClientDataJSON) == 0 {
		return &UnmarshalBadDataError{Type: "attestation", Msg: "base64 decoded client data is empty"}
	}
	rawAttestationObject, err := base64DecodeString(raw.Response.AttestationObject)
	if err != nil {
		return &UnmarshalBadDataError{Type: "attestation", Msg: "failed to base64 decode attestation object"}
	} else if len(rawAttestationObject) == 0 {
		return &UnmarshalBadDataError{Type: "attestation", Msg: "base64 decoded attestation object is empty"}
	}

	credentialAttestation.ID = raw.ID
	credentialAttestation.RawID = rawID
	if len(credentialAttestation.ID) == 0 && len(credentialAttestation.RawID) > 0 {
		credentialAttestation.ID = base64.RawURLEncoding.EncodeToString(credentialAttestation.RawID)
	}
	if len(credentialAttestation.RawID) == 0 && len(credentialAttestation.ID) > 0 {
		if credentialAttestation.RawID, err = base64.RawURLEncoding.DecodeString(credentialAttestation.ID); err != nil {
			return &UnmarshalBadDataError{Type: "attestation", Msg: "failed to base64 decode credential id"}
		} else if len(credentialAttestation.RawID) == 0 {
			return &UnmarshalBadDataError{Type: "attestation", Msg: "base64 decoded credential id is empty"}
		}
	}

	if credentialAttestation.ClientData, err = parseClientData(rawClientDataJSON); err != nil {
		return err
	}

	credentialAttestation.AuthnData, credentialAttestation.AttStmt, err = parseAttestationObject(rawAttestationObject)
	return
}

// VerifyAttestationStatement verifies attestation statement and returns attestation type and trust path, or an error.
func (credentialAttestation *PublicKeyCredentialAttestation) VerifyAttestationStatement() (attType AttestationType, trustPath interface{}, err error) {
	clientDataHash := sha256.Sum256(credentialAttestation.ClientData.Raw)
	return credentialAttestation.AttStmt.Verify(clientDataHash[:], credentialAttestation.AuthnData)
}

var (
	formatsMu     sync.RWMutex
	atomicFormats = make(map[string]func([]byte) (AttestationStatement, error))
)

// RegisterAttestationFormat registers attestation statement format with a function that parses attestation statement of given format.
func RegisterAttestationFormat(name string, parse func([]byte) (AttestationStatement, error)) {
	formatsMu.Lock()
	defer formatsMu.Unlock()

	if parse == nil {
		panic("webauth: register attestation parse function is nil")
	}

	if _, ok := atomicFormats[name]; ok {
		panic("webauth: register called twice for attestation parse function " + name)
	}
	atomicFormats[name] = parse
}

// UnregisterAttestationFormat unregisters given attestation statement format.
func UnregisterAttestationFormat(name string) {
	formatsMu.Lock()
	defer formatsMu.Unlock()
	delete(atomicFormats, name)
}

func parseAttestationStatement(format string, data []byte) (AttestationStatement, error) {
	formatsMu.RLock()
	defer formatsMu.RUnlock()
	parser, ok := atomicFormats[format]
	if !ok {
		return nil, &UnregisteredFeatureError{Feature: "attestation statement format " + format}
	}
	return parser(data)
}
