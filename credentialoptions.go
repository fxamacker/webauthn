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
	"errors"
	"strconv"
)

type bufferString []byte

// MarshalJSON implements json.Marshaler interface.  It returns a quoted string of base64 URL encoded BufferString.
func (b bufferString) MarshalJSON() ([]byte, error) {
	s := base64.RawURLEncoding.EncodeToString(b)
	return []byte("\"" + s + "\""), nil
}

// UnmarshalJSON implements json.Unmarshaler interface.  The data is expected to be base64 URL encoded.
func (b *bufferString) UnmarshalJSON(data []byte) (err error) {
	if len(data) < 2 {
		return errors.New("json: illegal data " + string(data))
	}
	if data[0] != '"' {
		return errors.New("json: illegal data at input byte 0")
	}
	if data[len(data)-1] != '"' {
		return errors.New("json: illegal data at input byte " + strconv.Itoa(len(data)-1))
	}
	*b, err = base64.RawURLEncoding.DecodeString(string(data[1 : len(data)-1]))
	return err
}

// PublicKeyCredentialRpEntity represents the Web Authentication structure of the same name,
// as defined in http://w3c.github.io/webauthn/#dictionary-rp-credential-params
type PublicKeyCredentialRpEntity struct {
	Name string `json:"name"`           // Human-palatable identifier, intended only for display.
	Icon string `json:"icon,omitempty"` // Serialized URL which resolves to an image associated with the entity.
	ID   string `json:"id,omitempty"`   // Relying Party unique identifier (effective domain).
}

// PublicKeyCredentialUserEntity represents the Web Authentication structure of the same name,
// as defined in http://w3c.github.io/webauthn/#dictionary-user-credential-params
type PublicKeyCredentialUserEntity struct {
	Name        string       `json:"name"`           // Human-palatable identifier, intended only for display.
	Icon        string       `json:"icon,omitempty"` // Serialized URL which resolves to an image associated with the entity.
	ID          bufferString `json:"id"`             // User handle, SHOULD NOT include personally identifying information (WebAuthn spec recommends 64 random bytes).
	DisplayName string       `json:"displayName"`    // Human-palatable name, intended only for display.
}

// AuthenticatorAttachment represents the Web Authentication enumeration of the same name,
// as defined in http://w3c.github.io/webauthn/#enum-attachment
type AuthenticatorAttachment string

// AuthenticatorAttachment enumeration.
const (
	AuthenticatorPlatform      AuthenticatorAttachment = "platform"
	AuthenticatorCrossPlatform AuthenticatorAttachment = "cross-platform"
)

// UserVerificationRequirement represents the Web Authentication enumeration of the same name,
// as defined in http://w3c.github.io/webauthn/#enum-userVerificationRequirement
type UserVerificationRequirement string

// UserVerificationRequirement enumeration.
const (
	UserVerificationRequired    UserVerificationRequirement = "required"
	UserVerificationPreferred   UserVerificationRequirement = "preferred"
	UserVerificationDiscouraged UserVerificationRequirement = "discouraged"
)

// ResidentKeyRequirement represents the Web Authentication enumeration of the same name,
// as defined in http://w3c.github.io/webauthn/#enum-residentKeyRequirement
type ResidentKeyRequirement string

// ResidentKeyRequirement enumeration.
const (
	ResidentKeyDiscouraged ResidentKeyRequirement = "discouraged"
	ResidentKeyPreferred   ResidentKeyRequirement = "preferred"
	ResidentKeyRequired    ResidentKeyRequirement = "required"
)

// AuthenticatorSelectionCriteria represents the Web Authentication structure of the same name,
// as defined in http://w3c.github.io/webauthn/#dictionary-authenticatorSelection
type AuthenticatorSelectionCriteria struct {
	AuthenticatorAttachment AuthenticatorAttachment     `json:"authenticatorAttachment,omitempty"` // Authenticator attachment modality.
	RequireResidentKey      bool                        `json:"requireResidentKey,omitempty"`      // Resident credential storage modality, defaulting to false.
	ResidentKey             ResidentKeyRequirement      `json:"residentKey,omitempty"`             // Supersedes RequireResidentKey.
	UserVerification        UserVerificationRequirement `json:"userVerification,omitempty"`        // Authentication factor capability, defaulting to "preferred".
}

// PublicKeyCredentialType represents the Web Authentication enumeration of the same name,
// as defined in http://w3c.github.io/webauthn/#enum-credentialType
type PublicKeyCredentialType string

// PublicKeyCredentialType enumeration.
const (
	PublicKeyCredentialTypePublicKey PublicKeyCredentialType = "public-key"
)

// PublicKeyCredentialParameters represents the Web Authentication structure of the same name,
// as defined in http://w3c.github.io/webauthn/#dictionary-credential-params
type PublicKeyCredentialParameters struct {
	Type PublicKeyCredentialType `json:"type"` // Type of credential to be created.
	// Alg identifies a cryptographic algorithm registered in the IANA COSE Algorithm registry.
	// It specifies the cryptographic signature algorithm with which the newly generated
	// credential will be used, and thus also the type of asymmetric key pair to be generate.
	Alg int `json:"alg"`
}

// AuthenticatorTransport represents the Web Authentication enumeration of the same name,
// as defined in http://w3c.github.io/webauthn/#enum-transport
type AuthenticatorTransport string

// AuthenticatorTransport enumeration.
const (
	AuthenticatorUSB      AuthenticatorTransport = "usb"      // Removable USB.
	AuthenticatorNFC      AuthenticatorTransport = "nfc"      // Near Field Communication.
	AuthenticatorBLE      AuthenticatorTransport = "ble"      // Bluetooth Low Energy.
	AuthenticatorInternal AuthenticatorTransport = "internal" // Client device specific transport.
)

// PublicKeyCredentialDescriptor represents the Web Authentication structure of the same name,
// as defined in http://w3c.github.io/webauthn/#dictionary-credential-descriptor
type PublicKeyCredentialDescriptor struct {
	Type       PublicKeyCredentialType  `json:"type"`                 // Type of the public key credential.
	ID         bufferString             `json:"id"`                   // Credential ID of the public key credential.
	Transports []AuthenticatorTransport `json:"transports,omitempty"` // How the client might communicate with the authenticator of the public key credential.
}

// AttestationConveyancePreference represents the Web Authentication enumeration of the same name,
// as defined in http://w3c.github.io/webauthn/#enum-attestation-convey
type AttestationConveyancePreference string

// AttestationConveyancePreference enumeration.
const (
	AttestationNone     AttestationConveyancePreference = "none"     // Relying Party is not interested in authenticator attestation.
	AttestationIndirect AttestationConveyancePreference = "indirect" // Relying Party prefers a verifiable attestation statements, but allows the client to decide how to obtain such attestation statements.
	AttestationDirect   AttestationConveyancePreference = "direct"   // Relying Party wants to receive the attestation statement.
)

// PublicKeyCredentialCreationOptions represents the Web Authentication structure of the same name,
// as defined in http://w3c.github.io/webauthn/#dictionary-makecredentialoptions
// Extensions are not supported.
type PublicKeyCredentialCreationOptions struct {
	RP                     PublicKeyCredentialRpEntity     `json:"rp"`                               // Relying Party data responsible for the request.
	User                   PublicKeyCredentialUserEntity   `json:"user"`                             // User data for which the Relying Party is requesting attestation.
	Challenge              bufferString                    `json:"challenge"`                        // Challenge for generating new credential's attestation object.
	PubKeyCredParams       []PublicKeyCredentialParameters `json:"pubKeyCredParams"`                 // Desired properties of the credential to be created.  The sequence is ordered from most preferred to least preferred.
	Timeout                uint64                          `json:"timeout,omitempty"`                // Time in milliseconds for client to wait for the call to complete.  Client can override this value.
	ExcludeCredentials     []PublicKeyCredentialDescriptor `json:"excludeCredentials,omitempty"`     // Used by Relying Parties to limit the creation of multiple credentials for the same account on a single authenticator.
	AuthenticatorSelection AuthenticatorSelectionCriteria  `json:"authenticatorSelection,omitempty"` // Used by Relying Parties to select appropriate authenticators.
	Attestation            AttestationConveyancePreference `json:"attestation,omitempty"`            // Used by Relying Parties to specify preference for attestation conveyance.
}

// PublicKeyCredentialRequestOptions represents the Web Authentication structure of the same name,
// as defined in http://w3c.github.io/webauthn/#dictionary-assertion-options
// Extensions are not supported.
type PublicKeyCredentialRequestOptions struct {
	Challenge        bufferString                    `json:"challenge"`                  // Challenge that the selected authenticator signs, along with other data, when producing an authentication assertion.
	Timeout          uint64                          `json:"timeout,omitempty"`          // Time in milliseconds for client to wait for the call to complete.  Client can override this value.
	RPID             string                          `json:"rpId,omitempty"`             // Relying Party identifier.
	AllowCredentials []PublicKeyCredentialDescriptor `json:"allowCredentials,omitempty"` // A list of public key credentials acceptable to the caller.  The sequence is ordered from most preferred to least preferred.
	UserVerification UserVerificationRequirement     `json:"userVerification,omitempty"` // Relying Party's requirements for user verification.
}
