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
)

// PublicKeyCredentialAssertion represents the Web Authentication structure of PublicKeyCredential
// for assertions, as defined in http://w3c.github.io/webauthn/#iface-pkcredential
type PublicKeyCredentialAssertion struct {
	ID         string               // Base64url encoded credential ID.
	RawID      []byte               // Raw credential ID.
	ClientData *CollectedClientData // Client data passed to the authenticator by the client.
	AuthnData  *AuthenticatorData   // Authenticator data returned by the authenticator.
	Signature  []byte               // Raw signature returned from the authenticator.
	UserHandle []byte               // User handle returned from the authenticator, or null.
}

// UnmarshalJSON implements json.Unmarshaler interface.  rawId, clientDataJSON, authenticatorData,
// signature, and userHandle are base64 URL encoded.
func (credentialAssertion *PublicKeyCredentialAssertion) UnmarshalJSON(data []byte) (err error) {
	type rawAuthenticatorAssertionResponse struct {
		ClientDataJSON    string `json:"clientDataJSON"`    // JSON-serialized client data passed to the authenticator by the client.
		AuthenticatorData string `json:"authenticatorData"` // Authenticator data returned by the authenticator.
		Signature         string `json:"signature"`         // Raw signature returned from authenticator.
		UserHandle        string `json:"userHandle"`        // User handle returned from the authenticator, or null.
	}
	type rawPublicKeyCredential struct {
		ID       string                            `json:"id,omitempty"`    // base64 url encoded credential ID.
		RawID    string                            `json:"rawId,omitempty"` // Raw credential ID.
		Response rawAuthenticatorAssertionResponse `json:"response"`        // Authenticator's response to client's request to generate an authentication assertion.
		Type     string                            `json:"type"`            // "public-key"
	}
	var raw rawPublicKeyCredential
	if err = json.Unmarshal(data, &raw); err != nil {
		return &UnmarshalSyntaxError{Type: "assertion", Msg: err.Error()}
	}

	// Check for empty data.
	if len(raw.ID) == 0 && len(raw.RawID) == 0 {
		return &UnmarshalMissingFieldError{Type: "assertion", Field: "credential id and raw id"}
	}
	if len(raw.Response.ClientDataJSON) == 0 {
		return &UnmarshalMissingFieldError{Type: "assertion", Field: "client data"}
	}
	if len(raw.Response.AuthenticatorData) == 0 {
		return &UnmarshalMissingFieldError{Type: "assertion", Field: "authenticator data"}
	}
	if len(raw.Response.Signature) == 0 {
		return &UnmarshalMissingFieldError{Type: "assertion", Field: "signature"}
	}
	if len(raw.Type) == 0 {
		return &UnmarshalMissingFieldError{Type: "assertion", Field: "type"}
	}

	if raw.Type != "public-key" {
		return &UnmarshalBadDataError{Type: "assertion", Msg: "expected type as \"public-key\", got \"" + raw.Type + "\""}
	}

	// base64 decode RawID, ClientDataJSON, AuthenticatorData, Signature, and UserHandle.
	var rawID []byte
	if len(raw.RawID) > 0 {
		rawID, err = base64DecodeString(raw.RawID)
		if err != nil {
			return &UnmarshalBadDataError{Type: "assertion", Msg: "failed to base64 decode credential raw id"}
		} else if len(rawID) == 0 {
			return &UnmarshalBadDataError{Type: "assertion", Msg: "base64 decoded credential raw id is empty"}
		}
	}
	rawClientDataJSON, err := base64DecodeString(raw.Response.ClientDataJSON)
	if err != nil {
		return &UnmarshalBadDataError{Type: "assertion", Msg: "failed to base64 decode client data"}
	} else if len(rawClientDataJSON) == 0 {
		return &UnmarshalBadDataError{Type: "assertion", Msg: "base64 decoded client data is empty"}
	}
	rawAuthenticatorData, err := base64DecodeString(raw.Response.AuthenticatorData)
	if err != nil {
		return &UnmarshalBadDataError{Type: "assertion", Msg: "failed to base64 decode authenticator data"}
	} else if len(rawAuthenticatorData) == 0 {
		return &UnmarshalBadDataError{Type: "assertion", Msg: "base64 decoded authenticator data is empty"}
	}
	rawSignature, err := base64DecodeString(raw.Response.Signature)
	if err != nil {
		return &UnmarshalBadDataError{Type: "assertion", Msg: "failed to base64 decode signature"}
	} else if len(rawSignature) == 0 {
		return &UnmarshalBadDataError{Type: "assertion", Msg: "base64 decoded signature is empty"}
	}
	var rawUserHandle []byte
	if len(raw.Response.UserHandle) > 0 {
		rawUserHandle, err = base64DecodeString(raw.Response.UserHandle)
		if err != nil {
			return &UnmarshalBadDataError{Type: "assertion", Msg: "failed to base64 decode user handle"}
		} else if len(rawUserHandle) == 0 {
			return &UnmarshalBadDataError{Type: "assertion", Msg: "base64 decoded user handle is empty"}
		}
	}

	credentialAssertion.ID = raw.ID
	credentialAssertion.RawID = rawID
	if len(credentialAssertion.ID) == 0 && len(credentialAssertion.RawID) > 0 {
		credentialAssertion.ID = base64.RawURLEncoding.EncodeToString(credentialAssertion.RawID)
	}
	if len(credentialAssertion.RawID) == 0 && len(credentialAssertion.ID) > 0 {
		if credentialAssertion.RawID, err = base64.RawURLEncoding.DecodeString(credentialAssertion.ID); err != nil {
			return &UnmarshalBadDataError{Type: "assertion", Msg: "failed to base64 decode credential id"}
		} else if len(credentialAssertion.RawID) == 0 {
			return &UnmarshalBadDataError{Type: "assertion", Msg: "base64 decoded credential id is empty"}
		}
	}

	if credentialAssertion.ClientData, err = parseClientData(rawClientDataJSON); err != nil {
		return err
	}

	if credentialAssertion.AuthnData, _, err = parseAuthenticatorData(rawAuthenticatorData); err != nil {
		return err
	}
	// Verify that credential id and public key are empty.
	if len(credentialAssertion.AuthnData.CredentialID) != 0 || credentialAssertion.AuthnData.Credential != nil {
		return &UnmarshalBadDataError{Type: "assertion", Msg: "credential data must be empty"}
	}
	credentialAssertion.Signature = rawSignature
	credentialAssertion.UserHandle = rawUserHandle
	return nil
}

// verifySignature verifies assertion's signature with credential.
func (credentialAssertion *PublicKeyCredentialAssertion) verifySignature(c *Credential) (err error) {
	rawAuthnData := credentialAssertion.AuthnData.Raw
	rawClientData := credentialAssertion.ClientData.Raw

	clientDataHash := sha256.Sum256(rawClientData)

	message := make([]byte, len(rawAuthnData)+len(clientDataHash))
	copy(message, rawAuthnData)
	copy(message[len(rawAuthnData):], clientDataHash[:])

	err = c.Verify(message, credentialAssertion.Signature)
	if err != nil {
		return &VerificationError{Type: "assertion", Field: "signature", Msg: err.Error()}
	}
	return nil
}
