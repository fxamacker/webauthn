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
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
)

// AuthenticatorData represents the Web Authentication structure of the same name,
// as defined in http://w3c.github.io/webauthn/#sctn-authenticator-data
type AuthenticatorData struct {
	Raw          []byte                 // Complete raw authenticator data content.
	RPIDHash     []byte                 // SHA-256 hash of the RP ID the credential is scoped to.
	UserPresent  bool                   // User is present.
	UserVerified bool                   // User is verified.
	Counter      uint32                 // Signature Counter.
	AAGUID       []byte                 // AAGUID of the authenticator (optional).
	CredentialID []byte                 // Identifier of a public key credential source (optional).
	Credential   *Credential            // Algorithm and public key portion of a Relying Party-specific credential key pair (optional).
	Extensions   map[string]interface{} // Extension-defined authenticator data (optional).
}

func parseAuthenticatorData(data []byte) (authnData *AuthenticatorData, rest []byte, err error) {
	if len(data) < 37 {
		return nil, nil, &UnmarshalSyntaxError{Type: "authenticator data", Msg: "unexpected EOF"}
	}

	authnData = &AuthenticatorData{Raw: data}

	authnData.RPIDHash = make([]byte, 32)
	copy(authnData.RPIDHash, data)

	flags := data[32]
	authnData.UserPresent = (flags & 0x01) > 0   // UP: flags bit 0.
	authnData.UserVerified = (flags & 0x04) > 0  // UV: flags bit 2.
	credentialDataIncluded := (flags & 0x40) > 0 // AT: flags bit 6.
	extensionDataIncluded := (flags & 0x80) > 0  // ED: flags bit 7.

	authnData.Counter = binary.BigEndian.Uint32(data[33:37])

	rest = data[37:]

	if credentialDataIncluded {
		if len(rest) < 18 {
			return nil, nil, &UnmarshalSyntaxError{Type: "authenticator data", Msg: "unexpected EOF"}
		}

		authnData.AAGUID = make([]byte, 16)
		copy(authnData.AAGUID, rest)

		idLength := binary.BigEndian.Uint16(rest[16:18])

		if len(rest[18:]) < int(idLength) {
			return nil, nil, &UnmarshalSyntaxError{Type: "authenticator data", Msg: "unexpected EOF"}
		}
		authnData.CredentialID = make([]byte, idLength)
		copy(authnData.CredentialID, rest[18:])

		if authnData.Credential, rest, err = ParseCredential(rest[18+idLength:]); err != nil {
			return nil, nil, err
		}
	}

	if extensionDataIncluded {
		return nil, nil, &UnsupportedFeatureError{Feature: "authenticator data extension"}
	}

	return
}

// TokenBindingStatus represents the Web Authentication enumeration of the same name,
// as defined in http://w3c.github.io/webauthn/#dictionary-client-data
type TokenBindingStatus string

// TokenBindingStatus enumeration.
const (
	TokenBindingPresent   TokenBindingStatus = "present"   // Token binding was used when communicating with the Relying Party.
	TokenBindingSupported TokenBindingStatus = "supported" // Client supports token binding, but it was not negotiated when communicating with the Relying Party.
)

// TokenBinding represents the Web Authentication structure of the same name,
// as defined in http://w3c.github.io/webauthn/#dictionary-client-data
type TokenBinding struct {
	Status TokenBindingStatus `json:"status"`
	ID     string             `json:"id"` // Base64url encoded Token Binding ID that was used when communicating with the Relying Party (required if status is "present").
}

// CollectedClientData represents the Web Authentication structure of the same name,
// as defined in http://w3c.github.io/webauthn/#dictionary-client-data
type CollectedClientData struct {
	Raw          []byte        `json:"-"`            // Complete raw client data content.
	Type         string        `json:"type"`         // "webauthn.create" when creating new credentials, and "webauthn.get" when getting an assertion.
	Challenge    string        `json:"challenge"`    // base64 url encoded chanllenge provided by the Relying Party.
	Origin       string        `json:"origin"`       // Fully qualified origin of the requester.
	TokenBinding *TokenBinding `json:"tokenBinding"` // State of the Token Binding protocol used when communicating with the Relying Party.  Its absence indicates that the client doesn't support token binding.
}

func parseClientData(data []byte) (clientData *CollectedClientData, err error) {
	clientData = &CollectedClientData{Raw: data}
	if err = json.Unmarshal(data, &clientData); err != nil {
		return nil, &UnmarshalSyntaxError{Type: "client data", Msg: err.Error()}
	}
	// Verify required fields (type, challenge, origin) are not empty.
	if len(clientData.Type) == 0 {
		return nil, &UnmarshalMissingFieldError{Type: "client data", Field: "type"}
	}
	if len(clientData.Challenge) == 0 {
		return nil, &UnmarshalMissingFieldError{Type: "client data", Field: "challenge"}
	}
	if len(clientData.Origin) == 0 {
		return nil, &UnmarshalMissingFieldError{Type: "client data", Field: "origin"}
	}
	// Verify TokenBinding required field (status) is not empty.
	if clientData.TokenBinding != nil && len(clientData.TokenBinding.Status) == 0 {
		return nil, &UnmarshalMissingFieldError{Type: "client data", Field: "token binding status"}
	}
	return
}

func base64DecodeString(s string) ([]byte, error) {
	if len(s) > 1 {
		// remove padding
		if s[len(s)-2] == '=' {
			s = s[:len(s)-2]
		} else if s[len(s)-1] == '=' {
			s = s[:len(s)-1]
		}
	}

	// convert base64 URL to base64 Std
	s = strings.Replace(s, "-", "+", -1)
	s = strings.Replace(s, "_", "/", -1)

	return base64.RawStdEncoding.DecodeString(s)
}
