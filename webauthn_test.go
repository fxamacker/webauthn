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
	"bytes"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"

	"github.com/fxamacker/webauthn"
)

var (
	// Test data adapted from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	attestation1 = `{
		"id":    "AAii3V6sGoaozW7TbNaYlJaJ5br8TrBfRXnofZO6l2suc3a5tt_XFuFkFA_5eabU80S1PW0m4IZ79BS2kQO7Zcuy2vf0ESg18GTLG1mo5YSkIdqL2J44egt-6rcj7NedSEwxa_uuxUYBtHNnSQqDmtoUAfM9LSWLl65BjKVZNGUp9ao33mMSdVfQQ0bHze69JVQvLBf8OTiZUqJsOuKmpqUc",
		"rawId": "AAii3V6sGoaozW7TbNaYlJaJ5br8TrBfRXnofZO6l2suc3a5tt_XFuFkFA_5eabU80S1PW0m4IZ79BS2kQO7Zcuy2vf0ESg18GTLG1mo5YSkIdqL2J44egt-6rcj7NedSEwxa_uuxUYBtHNnSQqDmtoUAfM9LSWLl65BjKVZNGUp9ao33mMSdVfQQ0bHze69JVQvLBf8OTiZUqJsOuKmpqUc",
		"response": {
			"attestationObject": "o2NmbXRkbW9ja2dhdHRTdG10oGhhdXRoRGF0YVkBJkmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAKIACKLdXqwahqjNbtNs1piUlonluvxOsF9Feeh9k7qXay5zdrm239cW4WQUD_l5ptTzRLU9bSbghnv0FLaRA7tly7La9_QRKDXwZMsbWajlhKQh2ovYnjh6C37qtyPs151ITDFr-67FRgG0c2dJCoOa2hQB8z0tJYuXrkGMpVk0ZSn1qjfeYxJ1V9BDRsfN7r0lVC8sF_w5OJlSomw64qampRylAQIDJiABIVgguxHN3W6ehp0VWXKaMNie1J82MVJCFZYScau74o17cx8iWCDb1jkTLi7lYZZbgwUwpqAk8QmIiPMTVQUVkhGEyGrKww==",
			"clientDataJSON":    "eyJjaGFsbGVuZ2UiOiIzM0VIYXYtaloxdjlxd0g3ODNhVS1qMEFSeDZyNW8tWUhoLXdkN0M2alBiZDdXaDZ5dGJJWm9zSUlBQ2Vod2Y5LXM2aFhoeVNITy1ISFVqRXdaUzI5dyIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0="
		},
		"type": "public-key"
	}`
	// Test data adapted from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	attestationMissingIDAndRawID = `{
		"response": {
			"attestationObject": "o2NmbXRkbW9ja2dhdHRTdG10oGhhdXRoRGF0YVkBJkmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAKIACKLdXqwahqjNbtNs1piUlonluvxOsF9Feeh9k7qXay5zdrm239cW4WQUD_l5ptTzRLU9bSbghnv0FLaRA7tly7La9_QRKDXwZMsbWajlhKQh2ovYnjh6C37qtyPs151ITDFr-67FRgG0c2dJCoOa2hQB8z0tJYuXrkGMpVk0ZSn1qjfeYxJ1V9BDRsfN7r0lVC8sF_w5OJlSomw64qampRylAQIDJiABIVgguxHN3W6ehp0VWXKaMNie1J82MVJCFZYScau74o17cx8iWCDb1jkTLi7lYZZbgwUwpqAk8QmIiPMTVQUVkhGEyGrKww==",
			"clientDataJSON":    "eyJjaGFsbGVuZ2UiOiIzM0VIYXYtaloxdjlxd0g3ODNhVS1qMEFSeDZyNW8tWUhoLXdkN0M2alBiZDdXaDZ5dGJJWm9zSUlBQ2Vod2Y5LXM2aFhoeVNITy1ISFVqRXdaUzI5dyIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0="
		},
		"type": "public-key"
	}`
	// Test data adapted from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	attestationWrongID = `{
		"id": "BAii3V6sGoaozW7TbNaYlJaJ5br8TrBfRXnofZO6l2suc3a5tt_XFuFkFA_5eabU80S1PW0m4IZ79BS2kQO7Zcuy2vf0ESg18GTLG1mo5YSkIdqL2J44egt-6rcj7NedSEwxa_uuxUYBtHNnSQqDmtoUAfM9LSWLl65BjKVZNGUp9ao33mMSdVfQQ0bHze69JVQvLBf8OTiZUqJsOuKmpqUc",
		"response": {
			"attestationObject": "o2NmbXRkbW9ja2dhdHRTdG10oGhhdXRoRGF0YVkBJkmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAKIACKLdXqwahqjNbtNs1piUlonluvxOsF9Feeh9k7qXay5zdrm239cW4WQUD_l5ptTzRLU9bSbghnv0FLaRA7tly7La9_QRKDXwZMsbWajlhKQh2ovYnjh6C37qtyPs151ITDFr-67FRgG0c2dJCoOa2hQB8z0tJYuXrkGMpVk0ZSn1qjfeYxJ1V9BDRsfN7r0lVC8sF_w5OJlSomw64qampRylAQIDJiABIVgguxHN3W6ehp0VWXKaMNie1J82MVJCFZYScau74o17cx8iWCDb1jkTLi7lYZZbgwUwpqAk8QmIiPMTVQUVkhGEyGrKww==",
			"clientDataJSON":    "eyJjaGFsbGVuZ2UiOiIzM0VIYXYtaloxdjlxd0g3ODNhVS1qMEFSeDZyNW8tWUhoLXdkN0M2alBiZDdXaDZ5dGJJWm9zSUlBQ2Vod2Y5LXM2aFhoeVNITy1ISFVqRXdaUzI5dyIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0="
		},
		"type": "public-key"
	}`
	// Test data from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	assertion1 = `{
		"id":    "AAhH7cnPRBkcukjnc2G2GM1H5dkVs9P1q2VErhD57pkzKVjBbixdsufjXhUOfiD27D0VA-fPKUVYNGE2XYcjhihtYODQv-xEarplsa7Ix6hK13FA6uyRxMgHC3PhTbx-rbq_RMUbaJ-HoGVt-c820ifdoagkFR02Van8Vr9q67Bn6zHNDT_DNrQbtpIUqqX_Rg2p5o6F7bVO3uOJG9hUNgUb",
		"rawId": "AAhH7cnPRBkcukjnc2G2GM1H5dkVs9P1q2VErhD57pkzKVjBbixdsufjXhUOfiD27D0VA-fPKUVYNGE2XYcjhihtYODQv-xEarplsa7Ix6hK13FA6uyRxMgHC3PhTbx-rbq_RMUbaJ-HoGVt-c820ifdoagkFR02Van8Vr9q67Bn6zHNDT_DNrQbtpIUqqX_Rg2p5o6F7bVO3uOJG9hUNgUb",
		"response": {
			"clientDataJSON":    "eyJjaGFsbGVuZ2UiOiJlYVR5VU5ueVBERGRLOFNORWdURVV2ejFROGR5bGtqalRpbVlkNVg3UUFvLUY4X1oxbHNKaTNCaWxVcEZaSGtJQ05EV1k4cjlpdm5UZ1c3LVhaQzNxUSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
			"authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAABaw",
			"signature":         "MEYCIQD6dF3B0ZoaLA0r78oyRdoMNR0bN93Zi4cF_75hFAH6pQIhALY0UIsrh03u_f4yKOwzwD6Cj3_GWLJiioTT9580s1a7",
			"userHandle":        ""
		},
		"type": "public-key"
	}`
	assertion1Id = "AAhH7cnPRBkcukjnc2G2GM1H5dkVs9P1q2VErhD57pkzKVjBbixdsufjXhUOfiD27D0VA-fPKUVYNGE2XYcjhihtYODQv-xEarplsa7Ix6hK13FA6uyRxMgHC3PhTbx-rbq_RMUbaJ-HoGVt-c820ifdoagkFR02Van8Vr9q67Bn6zHNDT_DNrQbtpIUqqX_Rg2p5o6F7bVO3uOJG9hUNgUb"
	/*
		assertion1PubPEM = `
		-----BEGIN PUBLIC KEY-----
		MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERez9aO2wBAWO54MuGbEqSdWahSnG
		MAg35BCNkaE3j8Q+O/ZhhKqTeIKm7El70EG6ejt4sg1ZaoQ5ELg8k3ywTg==
		-----END PUBLIC KEY-----`
	*/
	//assertion1SigAlg = x509.ECDSAWithSHA256
	assertion1CredentialCoseKey = []byte{
		165, 1, 2, 3, 38, 32, 1, 33, 88, 32, 69, 236, 253, 104, 237, 176, 4, 5, 142, 231, 131, 46, 25, 177, 42, 73, 213, 154, 133, 41, 198, 48, 8, 55, 228, 16, 141, 145, 161, 55, 143, 196, 34, 88, 32, 62, 59, 246, 97, 132, 170, 147, 120, 130, 166, 236, 73, 123, 208, 65, 186, 122, 59, 120, 178, 13, 89, 106, 132, 57, 16, 184, 60, 147, 124, 176, 78,
	}

	// Test data from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	assertion2 = `{
		"id":    "AwVUFfSwuMV1DRHfYmNry1IUGW03wEw9aTAR7kJM1nw",
		"rawId": "AwVUFfSwuMV1DRHfYmNry1IUGW03wEw9aTAR7kJM1nw",
		"response": {
			"clientDataJSON":    "ew0KCSJ0eXBlIiA6ICJ3ZWJhdXRobi5nZXQiLA0KCSJjaGFsbGVuZ2UiIDogIm03WlUwWi1fSWl3dmlGbkYxSlhlSmpGaFZCaW5jVzY5RTFDdGo4QVEtWWJiMXVjNDFiTUh0SXRnNkpBQ2gxc09qX1pYam9udzJhY2pfSkQyaS1heEVRIiwNCgkib3JpZ2luIiA6ICJodHRwczovL3dlYmF1dGhuLm9yZyIsDQoJInRva2VuQmluZGluZyIgOiANCgl7DQoJCSJzdGF0dXMiIDogInN1cHBvcnRlZCINCgl9DQp9",
			"authenticatorData": "lWkIjx7O4yMpVANdvRDXyuORMFonUbVZu4_Xy7IpvdQFAAAAAQ",
			"signature":         "ElyXBPkS6ps0aod8pSEwdbaeG04SUSoucEHaulPrK3eBk3R4aePjTB-SjiPbya5rxzbuUIYO0UnqkpZrb19ZywWqwQ7qVxZzxSq7BCZmJhcML7j54eK_2nszVwXXVgO7WxpBcy_JQMxjwjXw6wNAxmnJ-H3TJJO82x4-9pDkno-GjUH2ObYk9NtkgylyMcENUaPYqajSLX-q5k14T2g839UC3xzsg71xHXQSeHgzPt6f3TXpNxNNcBYJAMm8-exKsoMkxHPDLkzK1wd5giietdoT25XQ72i8fjSSL8eiS1gllEjwbqLJn5zMQbWlgpSzJy3lK634sdeZtmMpXbRtMA",
			"userHandle":        "YWs"
		},
		"type": "public-key"
	}`
	assertion2Id = "AwVUFfSwuMV1DRHfYmNry1IUGW03wEw9aTAR7kJM1nw"
	/*
			assertion2PubPEM = `
		-----BEGIN PUBLIC KEY-----
		MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2zT9pxqfMK3SNWvasEpd
		5/IcnjKGUJcUOGWjNJ3oszlvOlkpiWjCwYqnVH0Fy4ohm0rGzOOw4kyQh6i/X2qX
		dA0C2UNpuq29wpLBxl5ZiePVpnetJJVFRKiwA9WoDvlU3zX7QpFKzbEeRKSmI9r0
		gvJfCPOYWDhmiYxRZ4/u8hfSQ/Qg7NiV0K7jLv1m/2qtPEHVko7UGmXjWk0KANNe
		Xi2bwhQTU938I5aXtUQzDaURHbxCpmm86sKNgOWT1CVOGMuRqHBdyt5qKeu5N0DB
		aRFRRFVkcx6N0fU8y7DHXYnry0T+2Ln8rDZMZrfjQ/+b48CibGU9GwomshQE32pt
		/QIDAQAB
		-----END PUBLIC KEY-----`
	*/
	//assertion2SigAlg = x509.SHA256WithRSA
	assertion2CredentialCoseKey = []byte{
		164, 1, 3, 3, 57, 1, 0, 32, 89, 1, 0, 219, 52, 253, 167, 26, 159, 48, 173, 210, 53, 107, 218, 176, 74, 93, 231, 242, 28, 158, 50, 134, 80, 151, 20, 56, 101, 163, 52, 157, 232, 179, 57, 111, 58, 89, 41, 137, 104, 194, 193, 138, 167, 84, 125, 5, 203, 138, 33, 155, 74, 198, 204, 227, 176, 226, 76, 144, 135, 168, 191, 95, 106, 151, 116, 13, 2, 217, 67, 105, 186, 173, 189, 194, 146, 193, 198, 94, 89, 137, 227, 213, 166, 119, 173, 36, 149, 69, 68, 168, 176, 3, 213, 168, 14, 249, 84, 223, 53, 251, 66, 145, 74, 205, 177, 30, 68, 164, 166, 35, 218, 244, 130, 242, 95, 8, 243, 152, 88, 56, 102, 137, 140, 81, 103, 143, 238, 242, 23, 210, 67, 244, 32, 236, 216, 149, 208, 174, 227, 46, 253, 102, 255, 106, 173, 60, 65, 213, 146, 142, 212, 26, 101, 227, 90, 77, 10, 0, 211, 94, 94, 45, 155, 194, 20, 19, 83, 221, 252, 35, 150, 151, 181, 68, 51, 13, 165, 17, 29, 188, 66, 166, 105, 188, 234, 194, 141, 128, 229, 147, 212, 37, 78, 24, 203, 145, 168, 112, 93, 202, 222, 106, 41, 235, 185, 55, 64, 193, 105, 17, 81, 68, 85, 100, 115, 30, 141, 209, 245, 60, 203, 176, 199, 93, 137, 235, 203, 68, 254, 216, 185, 252, 172, 54, 76, 102, 183, 227, 67, 255, 155, 227, 192, 162, 108, 101, 61, 27, 10, 38, 178, 20, 4, 223, 106, 109, 253, 33, 68, 0, 1, 0, 1,
	}

	// Test data adapted from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	assertionMissingIDAndRawID = `{
		"response": {
			"clientDataJSON":    "eyJjaGFsbGVuZ2UiOiJlYVR5VU5ueVBERGRLOFNORWdURVV2ejFROGR5bGtqalRpbVlkNVg3UUFvLUY4X1oxbHNKaTNCaWxVcEZaSGtJQ05EV1k4cjlpdm5UZ1c3LVhaQzNxUSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
			"authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAABaw",
			"signature":         "MEYCIQD6dF3B0ZoaLA0r78oyRdoMNR0bN93Zi4cF_75hFAH6pQIhALY0UIsrh03u_f4yKOwzwD6Cj3_GWLJiioTT9580s1a7",
			"userHandle":        ""
		},
		"type": "public-key"
	}`
)

type mockAttestationStatement struct {
}

func parseMockAttestation(data []byte) (webauthn.AttestationStatement, error) {
	return &mockAttestationStatement{}, nil
}

func (attStmt *mockAttestationStatement) Verify(rawClientData []byte, authnData *webauthn.AuthenticatorData) (attType webauthn.AttestationType, trustPath interface{}, err error) {
	return webauthn.AttestationTypeBasic, nil, nil
}

type newAttestationOptionsTest struct {
	name                string
	cfg                 *webauthn.Config
	user                *webauthn.User
	wantCreationOptions *webauthn.PublicKeyCredentialCreationOptions
}

type newAttestationOptionsErrorTest struct {
	name         string
	cfg          *webauthn.Config
	user         *webauthn.User
	wantErrorMsg string
}

type parseAndVerifyAttestationTest struct {
	name                string
	attestation         []byte
	expected            *webauthn.AttestationExpectedData
	wantAttestationType webauthn.AttestationType
	wantTrustPath       interface{}
}

type parseAttestationErrorTest struct {
	name         string
	attestation  []byte
	wantErrorMsg string
}

type verifyAttestationErrorTest struct {
	name         string
	attestation  []byte
	expected     *webauthn.AttestationExpectedData
	wantErrorMsg string
}

type newAssertionOptionsTest struct {
	name               string
	cfg                *webauthn.Config
	user               *webauthn.User
	wantRequestOptions *webauthn.PublicKeyCredentialRequestOptions
}

type parseAndVerifyAssertionTest struct {
	name      string
	assertion []byte
	expected  *webauthn.AssertionExpectedData
}

type parseAssertionErrorTest struct {
	name         string
	assertion    []byte
	wantErrorMsg string
}

type verifyAssertionErrorTest struct {
	name         string
	assertion    []byte
	expected     *webauthn.AssertionExpectedData
	wantErrorMsg string
}

var newAttestationOptionsTests = []newAttestationOptionsTest{
	{
		name: "new attestation options 1",
		cfg:  getTestConfig(),
		user: &webauthn.User{
			ID:            []byte{1, 2, 3},
			Name:          "Jane Doe",
			Icon:          "https://janedoe.com/avatar.png",
			DisplayName:   "Jane",
			CredentialIDs: [][]byte{{1, 2, 3}, {4, 5, 6}},
		},
		wantCreationOptions: &webauthn.PublicKeyCredentialCreationOptions{
			RP:   webauthn.PublicKeyCredentialRpEntity{Name: "ACME Corporation", Icon: "https://acme.com/avatar.png", ID: "acme.com"},
			User: webauthn.PublicKeyCredentialUserEntity{Name: "Jane Doe", ID: []byte{1, 2, 3}, Icon: "https://janedoe.com/avatar.png", DisplayName: "Jane"},
			PubKeyCredParams: []webauthn.PublicKeyCredentialParameters{
				{Type: webauthn.PublicKeyCredentialTypePublicKey, Alg: webauthn.COSEAlgES256},
				{Type: webauthn.PublicKeyCredentialTypePublicKey, Alg: webauthn.COSEAlgPS256},
				{Type: webauthn.PublicKeyCredentialTypePublicKey, Alg: webauthn.COSEAlgRS256},
			},
			Timeout: uint64(30000),
			ExcludeCredentials: []webauthn.PublicKeyCredentialDescriptor{
				{Type: webauthn.PublicKeyCredentialTypePublicKey, ID: []byte{1, 2, 3}},
				{Type: webauthn.PublicKeyCredentialTypePublicKey, ID: []byte{4, 5, 6}},
			},
			AuthenticatorSelection: webauthn.AuthenticatorSelectionCriteria{
				AuthenticatorAttachment: webauthn.AuthenticatorPlatform,
				RequireResidentKey:      false,
				ResidentKey:             webauthn.ResidentKeyPreferred,
				UserVerification:        webauthn.UserVerificationPreferred,
			},
			Attestation: webauthn.AttestationDirect,
		},
	},
}

var newAttestationOptionsErrorTests = []newAttestationOptionsErrorTest{
	{
		name: "empty user name",
		cfg:  getTestConfig(),
		user: &webauthn.User{
			ID:            []byte{1, 2, 3},
			Name:          "",
			DisplayName:   "Jane",
			CredentialIDs: nil,
		},
		wantErrorMsg: "user name is required",
	},
	{
		name: "empty user id",
		cfg:  getTestConfig(),
		user: &webauthn.User{
			ID:            nil,
			Name:          "Jane Doe",
			DisplayName:   "Jane",
			CredentialIDs: nil,
		},
		wantErrorMsg: "user id is required",
	},
	{
		name: "empty user display name",
		cfg:  getTestConfig(),
		user: &webauthn.User{
			ID:            []byte{1, 2, 3},
			Name:          "Jane Doe",
			DisplayName:   "",
			CredentialIDs: nil,
		},
		wantErrorMsg: "user display name is required",
	},
}

var parseAndVerifyAttestationTests = []parseAndVerifyAttestationTest{
	{
		name:        "attestation 1",
		attestation: []byte(attestation1),
		expected: &webauthn.AttestationExpectedData{
			RPID:             "localhost",
			Origin:           "https://localhost:8443",
			CredentialAlgs:   []int{webauthn.COSEAlgES256, webauthn.COSEAlgES384, webauthn.COSEAlgES512},
			Challenge:        "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w",
			UserVerification: webauthn.UserVerificationPreferred,
		},
		wantAttestationType: webauthn.AttestationTypeBasic,
		wantTrustPath:       nil,
	},
}

var parseAttestationErrorTests = []parseAttestationErrorTest{
	{
		name:         "invalid attestation",
		attestation:  []byte(attestationMissingIDAndRawID),
		wantErrorMsg: "attestation: missing credential id and raw id",
	},
}

var verifyAttestationErrorTests = []verifyAttestationErrorTest{
	{
		name:        "attestation wrong id",
		attestation: []byte(attestationWrongID),
		expected: &webauthn.AttestationExpectedData{
			RPID:             "localhost",
			Origin:           "https://localhost:8443",
			UserVerification: webauthn.UserVerificationPreferred,
			Challenge:        "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w",
		},
		wantErrorMsg: "attestation: failed to verify credential ID: attestation's raw ID does not match credential ID",
	},
	{
		name:        "attestation wrong rp id",
		attestation: []byte(attestation1),
		expected: &webauthn.AttestationExpectedData{
			RPID:             "acme.com",
			Origin:           "https://localhost:8443",
			UserVerification: webauthn.UserVerificationPreferred,
			Challenge:        "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w",
		},
		wantErrorMsg: "attestation: failed to verify rp ID: authenticator data's rp ID hash does not match computed rp ID hash",
	},
	{
		name:        "attestation doesn't conform to user verification requirement",
		attestation: []byte(attestation1),
		expected: &webauthn.AttestationExpectedData{
			RPID:             "localhost",
			Origin:           "https://localhost:8443",
			UserVerification: webauthn.UserVerificationRequired,
			Challenge:        "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w",
		},
		wantErrorMsg: "attestation: failed to verify user verification: user didn't verify",
	},
}

var newAssertionOptionsTests = []newAssertionOptionsTest{
	{
		name: "new assertion options without allowCredentials",
		cfg:  getTestConfig(),
		user: &webauthn.User{},
		wantRequestOptions: &webauthn.PublicKeyCredentialRequestOptions{
			Timeout:          uint64(30000),
			RPID:             "acme.com",
			AllowCredentials: nil,
			UserVerification: webauthn.UserVerificationPreferred,
		},
	},
	{
		name: "new assertion options with allowCredentials",
		cfg:  getTestConfig(),
		user: &webauthn.User{
			CredentialIDs: [][]byte{{1, 2, 3}, {4, 5, 6}},
		},
		wantRequestOptions: &webauthn.PublicKeyCredentialRequestOptions{
			Timeout: uint64(30000),
			RPID:    "acme.com",
			AllowCredentials: []webauthn.PublicKeyCredentialDescriptor{
				{Type: webauthn.PublicKeyCredentialTypePublicKey, ID: []byte{1, 2, 3}},
				{Type: webauthn.PublicKeyCredentialTypePublicKey, ID: []byte{4, 5, 6}},
			},
			UserVerification: webauthn.UserVerificationPreferred,
		},
	},
}

var parseAndVerifyAssertionTests = []parseAndVerifyAssertionTest{
	{
		name:      "assertion without user handle",
		assertion: []byte(assertion1),
		expected: &webauthn.AssertionExpectedData{
			RPID:              "localhost",
			UserVerification:  webauthn.UserVerificationPreferred,
			UserCredentialIDs: nil,
			Origin:            "https://localhost:8443",
			Challenge:         "eaTyUNnyPDDdK8SNEgTEUvz1Q8dylkjjTimYd5X7QAo-F8_Z1lsJi3BilUpFZHkICNDWY8r9ivnTgW7-XZC3qQ",
			UserID:            nil,
			PrevCounter:       uint32(362),
			Credential:        parseCredential(assertion1CredentialCoseKey),
		},
	},
	{
		name:      "assertion with user handle",
		assertion: []byte(assertion2),
		expected: &webauthn.AssertionExpectedData{
			RPID:              "webauthn.org",
			UserVerification:  webauthn.UserVerificationPreferred,
			UserCredentialIDs: nil,
			Origin:            "https://webauthn.org",
			Challenge:         "m7ZU0Z-_IiwviFnF1JXeJjFhVBincW69E1Ctj8AQ-Ybb1uc41bMHtItg6JACh1sOj_ZXjonw2acj_JD2i-axEQ",
			UserID:            base64Decode("YWs"),
			PrevCounter:       uint32(0),
			Credential:        parseCredential(assertion2CredentialCoseKey),
		},
	},
	{
		name:      "credential id is allowed",
		assertion: []byte(assertion1),
		expected: &webauthn.AssertionExpectedData{
			RPID:              "localhost",
			Origin:            "https://localhost:8443",
			UserVerification:  webauthn.UserVerificationPreferred,
			Challenge:         "eaTyUNnyPDDdK8SNEgTEUvz1Q8dylkjjTimYd5X7QAo-F8_Z1lsJi3BilUpFZHkICNDWY8r9ivnTgW7-XZC3qQ",
			UserCredentialIDs: [][]byte{base64Decode(assertion1Id)},
			Credential:        parseCredential(assertion1CredentialCoseKey),
		},
	},
	{
		name:      "credential id is allowed",
		assertion: []byte(assertion1),
		expected: &webauthn.AssertionExpectedData{
			RPID:              "localhost",
			Origin:            "https://localhost:8443",
			UserVerification:  webauthn.UserVerificationPreferred,
			Challenge:         "eaTyUNnyPDDdK8SNEgTEUvz1Q8dylkjjTimYd5X7QAo-F8_Z1lsJi3BilUpFZHkICNDWY8r9ivnTgW7-XZC3qQ",
			UserCredentialIDs: [][]byte{base64Decode(assertion1Id), base64Decode(assertion2Id)},
			Credential:        parseCredential(assertion1CredentialCoseKey),
		},
	},
}

var parseAssertionErrorTests = []parseAssertionErrorTest{
	{
		name:         "invalid assertion",
		assertion:    []byte(assertionMissingIDAndRawID),
		wantErrorMsg: "assertion: missing credential id and raw id",
	},
}

var verifyAssertionErrorTests = []verifyAssertionErrorTest{
	{
		name:      "assertion wrong rp id",
		assertion: []byte(assertion1),
		expected: &webauthn.AssertionExpectedData{
			RPID:             "acme.com",
			Origin:           "https://localhost:8443",
			UserVerification: webauthn.UserVerificationPreferred,
			Challenge:        "eaTyUNnyPDDdK8SNEgTEUvz1Q8dylkjjTimYd5X7QAo-F8_Z1lsJi3BilUpFZHkICNDWY8r9ivnTgW7-XZC3qQ",
		},
		wantErrorMsg: "assertion: failed to verify rp ID: authenticator data's rp ID hash does not match computed rp ID hash",
	},
	{
		name:      "assertion doesn't conform to user verification requirement",
		assertion: []byte(assertion1),
		expected: &webauthn.AssertionExpectedData{
			RPID:             "localhost",
			Origin:           "https://localhost:8443",
			UserVerification: webauthn.UserVerificationRequired,
			Challenge:        "eaTyUNnyPDDdK8SNEgTEUvz1Q8dylkjjTimYd5X7QAo-F8_Z1lsJi3BilUpFZHkICNDWY8r9ivnTgW7-XZC3qQ",
		},
		wantErrorMsg: "assertion: failed to verify user verification: user didn't verify",
	},
	{
		name:      "credential id is not allowed",
		assertion: []byte(assertion1),
		expected: &webauthn.AssertionExpectedData{
			RPID:              "localhost",
			Origin:            "https://localhost:8443",
			UserVerification:  webauthn.UserVerificationPreferred,
			Challenge:         "eaTyUNnyPDDdK8SNEgTEUvz1Q8dylkjjTimYd5X7QAo-F8_Z1lsJi3BilUpFZHkICNDWY8r9ivnTgW7-XZC3qQ",
			UserCredentialIDs: [][]byte{base64Decode(assertion2Id)},
		},
		wantErrorMsg: "assertion: failed to verify credential ID: credential ID is not allowed",
	},
}

func base64Decode(s string) []byte {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		panic(err.Error())
	}
	return b
}

func getTestConfig() *webauthn.Config {
	cfg := &webauthn.Config{
		RPID:                    "acme.com",
		RPName:                  "ACME Corporation",
		RPIcon:                  "https://acme.com/avatar.png",
		Timeout:                 uint64(30000),
		ChallengeLength:         64,
		AuthenticatorAttachment: webauthn.AuthenticatorPlatform,
		ResidentKey:             webauthn.ResidentKeyPreferred,
		UserVerification:        webauthn.UserVerificationPreferred,
		Attestation:             webauthn.AttestationDirect,
		CredentialAlgs:          []int{webauthn.COSEAlgES256, webauthn.COSEAlgPS256, webauthn.COSEAlgRS256},
	}
	if err := cfg.Valid(); err != nil {
		panic(err)
	}
	return cfg
}

func parseCredential(data []byte) *webauthn.Credential {
	c, _, err := webauthn.ParseCredential(data)
	if err != nil {
		panic(err)
	}
	return c
}

func TestNewAttestationOptions(t *testing.T) {
	for _, tc := range newAttestationOptionsTests {
		t.Run(tc.name, func(t *testing.T) {
			creationOptions, err := webauthn.NewAttestationOptions(tc.cfg, tc.user)
			if err != nil {
				t.Fatalf("NewAttestationOptions() returns error %q", err.Error())
			}
			// test challenge length
			if len(creationOptions.Challenge) != tc.cfg.ChallengeLength {
				t.Errorf("challenge length %d, want %d", len(creationOptions.Challenge), tc.cfg.ChallengeLength)
			}
			// remove new attestation challenge before using reflect.DeepEqual to compare two objects
			creationOptions.Challenge = nil
			if !reflect.DeepEqual(creationOptions, tc.wantCreationOptions) {
				t.Errorf("attestation options %+v, want %+v (challenge field is nil for testing)", creationOptions, tc.wantCreationOptions)
			}
		})
	}
}

func TestNewAttestationOptionsError(t *testing.T) {
	for _, tc := range newAttestationOptionsErrorTests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := webauthn.NewAttestationOptions(tc.cfg, tc.user); err == nil {
				t.Errorf("NewAttestationOptions(%+v, %+v) returns no error, want error containing substring %q", tc.cfg, tc.user, tc.wantErrorMsg)
			} else if !strings.Contains(err.Error(), tc.wantErrorMsg) {
				t.Errorf("NewAttestationOptions(%+v, %+v) returns error %q, want error containing substring %q", tc.cfg, tc.user, err, tc.wantErrorMsg)
			}
		})
	}
}

func TestParseAndVerifyAttestation(t *testing.T) {
	// register mock attestation statement
	webauthn.RegisterAttestationFormat("mock", parseMockAttestation)
	defer webauthn.UnregisterAttestationFormat("mock")

	for _, tc := range parseAndVerifyAttestationTests {
		t.Run(tc.name, func(t *testing.T) {
			credentialAttestation, err := webauthn.ParseAttestation(bytes.NewReader(tc.attestation))
			if err != nil {
				t.Fatalf("ParseAttestation(%s) returns error %q", string(tc.attestation), err)
			}
			attType, trustPath, err := webauthn.VerifyAttestation(credentialAttestation, tc.expected)
			if err != nil {
				t.Fatalf("VerifyAttestation() returns error %q", err)
			}
			if attType != tc.wantAttestationType {
				t.Errorf("attestation type %v, want %v", attType, tc.wantAttestationType)
			}
			if !reflect.DeepEqual(trustPath, tc.wantTrustPath) {
				t.Errorf("trust path %v, want %v", trustPath, tc.wantTrustPath)
			}
		})
	}
}

func TestParseAttestationError(t *testing.T) {
	// register mock attestation statement
	webauthn.RegisterAttestationFormat("mock", parseMockAttestation)
	defer webauthn.UnregisterAttestationFormat("mock")

	for _, tc := range parseAttestationErrorTests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := webauthn.ParseAttestation(bytes.NewReader(tc.attestation)); err == nil {
				t.Errorf("ParseAttestation(%s) returns no error, want error containing substring %q", string(tc.attestation), tc.wantErrorMsg)
			} else if !strings.Contains(err.Error(), tc.wantErrorMsg) {
				t.Errorf("ParseAttestation(%s) returns error %q, want error containing substring %q", string(tc.attestation), err, tc.wantErrorMsg)
			}
		})
	}
}

func TestVerifyAttestationError(t *testing.T) {
	// register mock attestation statement
	webauthn.RegisterAttestationFormat("mock", parseMockAttestation)
	defer webauthn.UnregisterAttestationFormat("mock")

	for _, tc := range verifyAttestationErrorTests {
		t.Run(tc.name, func(t *testing.T) {
			credentialAttestation, err := webauthn.ParseAttestation(bytes.NewReader(tc.attestation))
			if err != nil {
				t.Fatalf("ParseAttestation(%s) returns error %q", tc.attestation, err)
			}
			if _, _, err := webauthn.VerifyAttestation(credentialAttestation, tc.expected); err == nil {
				t.Errorf("VerifyAttestation() returns no error, want error containing substring %q", tc.wantErrorMsg)
			} else if !strings.Contains(err.Error(), tc.wantErrorMsg) {
				t.Errorf("VerifyAttestation() returns error %q, want error containing substring %q", err, tc.wantErrorMsg)
			}
		})
	}
}

func TestNewAssertionOptions(t *testing.T) {
	for _, tc := range newAssertionOptionsTests {
		t.Run(tc.name, func(t *testing.T) {
			requestOptions, err := webauthn.NewAssertionOptions(tc.cfg, tc.user)
			if err != nil {
				t.Fatalf("NewAssertionOptions(%v, %v) returns error %q", tc.cfg, tc.user, err.Error())
			}
			if len(requestOptions.Challenge) != tc.cfg.ChallengeLength {
				t.Errorf("challenge length %d, want %d", len(requestOptions.Challenge), tc.cfg.ChallengeLength)
			}
			// remove new assertion challenge before using reflect.DeepEqual to compare two objects
			requestOptions.Challenge = nil
			if !reflect.DeepEqual(requestOptions, tc.wantRequestOptions) {
				t.Errorf("asssertion options %+v, want %+v (challenge field is nil for testing)", requestOptions, tc.wantRequestOptions)
			}
		})
	}
}

func TestParseAndVerifyAssertion(t *testing.T) {
	for _, tc := range parseAndVerifyAssertionTests {
		t.Run(tc.name, func(t *testing.T) {
			credentialAssertion, err := webauthn.ParseAssertion(bytes.NewReader(tc.assertion))
			if err != nil {
				t.Fatalf("ParseAssertion(%s) returns error %q", string(tc.assertion), err)
			}
			if err := webauthn.VerifyAssertion(credentialAssertion, tc.expected); err != nil {
				t.Errorf("VerifyAssertion(%+v) returns error %q", tc.expected, err)
			}
		})
	}
}

func TestParseAssertionError(t *testing.T) {
	for _, tc := range parseAssertionErrorTests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := webauthn.ParseAssertion(bytes.NewReader(tc.assertion)); err == nil {
				t.Errorf("ParseAssertion(%s) returns no error, want error containing substring %q", string(tc.assertion), tc.wantErrorMsg)
			} else if !strings.Contains(err.Error(), tc.wantErrorMsg) {
				t.Errorf("ParseAssertion(%s) returns error %q, want error containing substring %q", string(tc.assertion), err, tc.wantErrorMsg)
			}
		})
	}
}

func TestVerifyAssertionError(t *testing.T) {
	for _, tc := range verifyAssertionErrorTests {
		t.Run(tc.name, func(t *testing.T) {
			credentialAssertion, err := webauthn.ParseAssertion(bytes.NewReader(tc.assertion))
			if err != nil {
				t.Fatalf("ParseAssertion(%s) returns error %q", string(tc.assertion), err)
			}
			if err := webauthn.VerifyAssertion(credentialAssertion, tc.expected); err == nil {
				t.Errorf("VerifyAssertion() returns no error, want error containing substring %q", tc.wantErrorMsg)
			} else if !strings.Contains(err.Error(), tc.wantErrorMsg) {
				t.Errorf("VerifyAssertion() returns error %q, want error containing substring %q", err, tc.wantErrorMsg)
			}
		})
	}
}
