// Copyright (c) 2019 Faye Amacker. All rights reserved.
// Use of this source code is governed by Apache License 2.0 found in the LICENSE file.

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
			webauthn.PublicKeyCredentialDescriptor{Type: "public-key", ID: []byte{4, 5, 6}, Transports: []webauthn.AuthenticatorTransport{"usb"}},
			webauthn.PublicKeyCredentialDescriptor{Type: "public-key", ID: []byte{7, 8, 9}, Transports: []webauthn.AuthenticatorTransport{"internal"}},
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
