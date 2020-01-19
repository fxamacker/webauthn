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

package webauthn_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/fxamacker/webauthn"
)

func TestPublicKeyCredentialCreationOptionsJSONMarshal(t *testing.T) {
	options := webauthn.PublicKeyCredentialCreationOptions{
		RP: webauthn.PublicKeyCredentialRpEntity{
			Name: "ACME Corporation",
			Icon: "https://acme.com/avatar.png",
			ID:   "acme.com",
		},
		User: webauthn.PublicKeyCredentialUserEntity{
			Name:        "Jane Doe",
			Icon:        "https://janedoe.com/avatar.png",
			ID:          []byte{1, 2, 3},
			DisplayName: "jane",
		},
		Challenge: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		PubKeyCredParams: []webauthn.PublicKeyCredentialParameters{
			{Type: "public-key", Alg: -7},
			{Type: "public-key", Alg: -37},
		},
		Timeout: uint64(60000),
		ExcludeCredentials: []webauthn.PublicKeyCredentialDescriptor{
			{Type: "public-key", ID: []byte{4, 5, 6}, Transports: []webauthn.AuthenticatorTransport{"usb"}},
			{Type: "public-key", ID: []byte{7, 8, 9}, Transports: []webauthn.AuthenticatorTransport{"internal"}},
		},
		AuthenticatorSelection: webauthn.AuthenticatorSelectionCriteria{
			AuthenticatorAttachment: webauthn.AuthenticatorPlatform,
			RequireResidentKey:      true,
			UserVerification:        webauthn.UserVerificationRequired,
		},
		Attestation: webauthn.AttestationDirect,
	}
	b, err := json.Marshal(options)
	if err != nil {
		t.Fatalf("failed to marshal PublicKeyCredentialCreationOptions object to JSON, %q", err)
	}
	var options2 webauthn.PublicKeyCredentialCreationOptions
	if err = json.Unmarshal(b, &options2); err != nil {
		t.Fatalf("failed to unmarshal PublicKeyCredentialCreationOptions object from JSON, %q", err)
	}
	if !reflect.DeepEqual(options, options2) {
		t.Errorf("json.Unmarshal(%s) returns %+v, want %+v", string(b), options2, options)
	}
}

func TestPublicKeyCredentialRequestOptionsJSONMarshal(t *testing.T) {
	options := webauthn.PublicKeyCredentialRequestOptions{
		Challenge: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Timeout:   uint64(60000),
		RPID:      "acme.com",
		AllowCredentials: []webauthn.PublicKeyCredentialDescriptor{
			{Type: "public-key", ID: []byte{4, 5, 6}, Transports: []webauthn.AuthenticatorTransport{"usb"}},
			{Type: "public-key", ID: []byte{7, 8, 9}, Transports: []webauthn.AuthenticatorTransport{"internal"}},
		},
		UserVerification: webauthn.UserVerificationRequired,
	}
	b, err := json.Marshal(options)
	if err != nil {
		t.Fatalf("failed to marshal PublicKeyCredentialRequestOptions object to JSON, %q", err)
	}
	var options2 webauthn.PublicKeyCredentialRequestOptions
	if err = json.Unmarshal(b, &options2); err != nil {
		t.Fatalf("failed to unmarshal PublicKeyCredentialRequestOptions object from JSON, %q", err)
	}
	if !reflect.DeepEqual(options, options2) {
		t.Errorf("json.Unmarshal(%s) returns %+v, want %+v", string(b), options2, options)
	}
}
