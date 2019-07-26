// Copyright (c) 2019 Faye Amacker. All rights reserved.
// Use of this source code is governed by Apache License 2.0 found in the LICENSE file.

package webauthn

import (
	"encoding/json"
	"reflect"
	"testing"
)

var (
	// Test data from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	noneAttestation1 = `{
		"id":    "AAii3V6sGoaozW7TbNaYlJaJ5br8TrBfRXnofZO6l2suc3a5tt_XFuFkFA_5eabU80S1PW0m4IZ79BS2kQO7Zcuy2vf0ESg18GTLG1mo5YSkIdqL2J44egt-6rcj7NedSEwxa_uuxUYBtHNnSQqDmtoUAfM9LSWLl65BjKVZNGUp9ao33mMSdVfQQ0bHze69JVQvLBf8OTiZUqJsOuKmpqUc",
		"rawId": "AAii3V6sGoaozW7TbNaYlJaJ5br8TrBfRXnofZO6l2suc3a5tt_XFuFkFA_5eabU80S1PW0m4IZ79BS2kQO7Zcuy2vf0ESg18GTLG1mo5YSkIdqL2J44egt-6rcj7NedSEwxa_uuxUYBtHNnSQqDmtoUAfM9LSWLl65BjKVZNGUp9ao33mMSdVfQQ0bHze69JVQvLBf8OTiZUqJsOuKmpqUc",
		"response": {
			"attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBJkmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAKIACKLdXqwahqjNbtNs1piUlonluvxOsF9Feeh9k7qXay5zdrm239cW4WQUD_l5ptTzRLU9bSbghnv0FLaRA7tly7La9_QRKDXwZMsbWajlhKQh2ovYnjh6C37qtyPs151ITDFr-67FRgG0c2dJCoOa2hQB8z0tJYuXrkGMpVk0ZSn1qjfeYxJ1V9BDRsfN7r0lVC8sF_w5OJlSomw64qampRylAQIDJiABIVgguxHN3W6ehp0VWXKaMNie1J82MVJCFZYScau74o17cx8iWCDb1jkTLi7lYZZbgwUwpqAk8QmIiPMTVQUVkhGEyGrKww==",
			"clientDataJSON":    "eyJjaGFsbGVuZ2UiOiIzM0VIYXYtaloxdjlxd0g3ODNhVS1qMEFSeDZyNW8tWUhoLXdkN0M2alBiZDdXaDZ5dGJJWm9zSUlBQ2Vod2Y5LXM2aFhoeVNITy1ISFVqRXdaUzI5dyIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0="
		},
		"type": "public-key"
	}`
)

type parseAndVerifyTest struct {
	name          string
	attestation   []byte
	wantAttType   AttestationType
	wantTrustPath interface{}
}

var parseAndVerifyTests = []parseAndVerifyTest{
	{
		"attestation 1",
		[]byte(noneAttestation1),
		AttestationTypeNone,
		nil,
	},
}

func TestParseAndVerifyNoneAttestation(t *testing.T) {
	for _, tc := range parseAndVerifyTests {
		t.Run(tc.name, func(t *testing.T) {
			var credentialAttestation PublicKeyCredentialAttestation
			if err := json.Unmarshal(tc.attestation, &credentialAttestation); err != nil {
				t.Fatalf("failed to unmarshal attestation %s: %q", string(tc.attestation), err)
			}
			_, ok := credentialAttestation.AttStmt.(*noneAttestationStatement)
			if !ok {
				t.Fatalf("attestation type %T, want *noneAttestationStatement", credentialAttestation.AttStmt)
			}
			attType, trustPath, err := credentialAttestation.VerifyAttestationStatement()
			if err != nil {
				t.Fatalf("VerifyAttestationStatement() returns error %q", err)
			}
			if attType != tc.wantAttType {
				t.Errorf("attestation type %v, want %v", attType, tc.wantAttType)
			}
			if !reflect.DeepEqual(trustPath, tc.wantTrustPath) {
				t.Errorf("trust path %v, want %v", trustPath, tc.wantTrustPath)
			}
		})
	}
}
