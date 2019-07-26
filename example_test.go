// Copyright (c) 2019 Faye Amacker. All rights reserved.
// Use of this source code is governed by Apache License 2.0 found in the LICENSE file.

package webauthn_test

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/fxamacker/webauthn"
)

func ExampleNewAttestationOptions() {
	// cfg is initialized at startup and used throughout the program to create attestation and assertion options.
	cfg := &webauthn.Config{
		RPID:                    "localhost",
		RPName:                  "WebAuthn local host",
		Timeout:                 uint64(30000),
		ChallengeLength:         64,
		AuthenticatorAttachment: webauthn.AuthenticatorPlatform,
		ResidentKey:             webauthn.ResidentKeyPreferred,
		UserVerification:        webauthn.UserVerificationPreferred,
		Attestation:             webauthn.AttestationNone,
		CredentialAlgs:          []int{webauthn.COSEAlgES256, webauthn.COSEAlgES384, webauthn.COSEAlgES512},
	}
	if err := cfg.Valid(); err != nil {
		fmt.Println("error:", err)
		return
	}

	// user contains user data for which the Relying Party is requesting attestation or assertion.
	user := &webauthn.User{
		ID:          []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
		Name:        "Jane Doe",
		DisplayName: "Jane",
	}

	creationOptions, err := webauthn.NewAttestationOptions(cfg, user)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	creationOptionsJSON, err := json.Marshal(creationOptions)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	// Save user and creationOptions in session to verify attestation later.
	// Send creationOptionsJSON to web client, which passes it to navigator.credentials.create().

	fmt.Printf("%s\n", creationOptionsJSON)
}

func Example_parseAndVerifyAttestation() {
	// attestation represents attestation data returned by navigator.credentials.create().
	attestation := `{
	"id"   :"AAii3V6sGoaozW7TbNaYlJaJ5br8TrBfRXnofZO6l2suc3a5tt_XFuFkFA_5eabU80S1PW0m4IZ79BS2kQO7Zcuy2vf0ESg18GTLG1mo5YSkIdqL2J44egt-6rcj7NedSEwxa_uuxUYBtHNnSQqDmtoUAfM9LSWLl65BjKVZNGUp9ao33mMSdVfQQ0bHze69JVQvLBf8OTiZUqJsOuKmpqUc",
	"rawId":"AAii3V6sGoaozW7TbNaYlJaJ5br8TrBfRXnofZO6l2suc3a5tt_XFuFkFA_5eabU80S1PW0m4IZ79BS2kQO7Zcuy2vf0ESg18GTLG1mo5YSkIdqL2J44egt-6rcj7NedSEwxa_uuxUYBtHNnSQqDmtoUAfM9LSWLl65BjKVZNGUp9ao33mMSdVfQQ0bHze69JVQvLBf8OTiZUqJsOuKmpqUc",
	"response":{
		"attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBJkmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAKIACKLdXqwahqjNbtNs1piUlonluvxOsF9Feeh9k7qXay5zdrm239cW4WQUD_l5ptTzRLU9bSbghnv0FLaRA7tly7La9_QRKDXwZMsbWajlhKQh2ovYnjh6C37qtyPs151ITDFr-67FRgG0c2dJCoOa2hQB8z0tJYuXrkGMpVk0ZSn1qjfeYxJ1V9BDRsfN7r0lVC8sF_w5OJlSomw64qampRylAQIDJiABIVgguxHN3W6ehp0VWXKaMNie1J82MVJCFZYScau74o17cx8iWCDb1jkTLi7lYZZbgwUwpqAk8QmIiPMTVQUVkhGEyGrKww==",
		"clientDataJSON":"eyJjaGFsbGVuZ2UiOiIzM0VIYXYtaloxdjlxd0g3ODNhVS1qMEFSeDZyNW8tWUhoLXdkN0M2alBiZDdXaDZ5dGJJWm9zSUlBQ2Vod2Y5LXM2aFhoeVNITy1ISFVqRXdaUzI5dyIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0="
	},
	"type":"public-key"
}`
	r := strings.NewReader(attestation)

	// Parse attestation returned by navigator.credentials.create().
	credentialAttestation, err := webauthn.ParseAttestation(r)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	// Create AttestationExpectedData object from saved user and creationOptions.
	expected := &webauthn.AttestationExpectedData{
		Origin:           "https://localhost:8443",
		RPID:             "localhost",
		CredentialAlgs:   []int{webauthn.COSEAlgES256, webauthn.COSEAlgES384, webauthn.COSEAlgES512},
		Challenge:        "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w",
		UserVerification: webauthn.UserVerificationPreferred,
	}

	attType, trustPath, err := webauthn.VerifyAttestation(credentialAttestation, expected)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	// Verify that attType is acceptable and trustPath can be trusted.
	// Save user info, credential id, algorithm, public key, and counter to persistent store.
	// User is registered.

	pk, _ := credentialAttestation.AuthnData.Credential.MarshalPKIXPublicKeyPEM()
	fmt.Printf("Credential ID: %s\n", credentialAttestation.ID)
	fmt.Printf("Credential algorithm: %s\n", credentialAttestation.AuthnData.Credential.Algorithm)
	fmt.Printf("Credential public key: %s", pk)
	fmt.Printf("Authenticator counter: %d\n", credentialAttestation.AuthnData.Counter)
	fmt.Printf("User present: %t\n", credentialAttestation.AuthnData.UserPresent)
	fmt.Printf("User verified: %t\n", credentialAttestation.AuthnData.UserVerified)
	fmt.Printf("Attestation type: %s\n", attType)
	fmt.Printf("Trust path: %v\n", trustPath)

	// Output:
	// Credential ID: AAii3V6sGoaozW7TbNaYlJaJ5br8TrBfRXnofZO6l2suc3a5tt_XFuFkFA_5eabU80S1PW0m4IZ79BS2kQO7Zcuy2vf0ESg18GTLG1mo5YSkIdqL2J44egt-6rcj7NedSEwxa_uuxUYBtHNnSQqDmtoUAfM9LSWLl65BjKVZNGUp9ao33mMSdVfQQ0bHze69JVQvLBf8OTiZUqJsOuKmpqUc
	// Credential algorithm: ECDSA-SHA256
	// Credential public key: -----BEGIN PUBLIC KEY-----
	//MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuxHN3W6ehp0VWXKaMNie1J82MVJC
	//FZYScau74o17cx/b1jkTLi7lYZZbgwUwpqAk8QmIiPMTVQUVkhGEyGrKww==
	//-----END PUBLIC KEY-----
	// Authenticator counter: 0
	// User present: true
	// User verified: false
	// Attestation type: None
	// Trust path: <nil>
}

func ExampleNewAssertionOptions() {
	// cfg is initialized at startup and used throughout the program to create attestation and assertion options.
	cfg := &webauthn.Config{
		RPID:                    "localhost",
		RPName:                  "WebAuthn local host",
		Timeout:                 uint64(30000),
		ChallengeLength:         64,
		AuthenticatorAttachment: webauthn.AuthenticatorPlatform,
		ResidentKey:             webauthn.ResidentKeyPreferred,
		UserVerification:        webauthn.UserVerificationPreferred,
		Attestation:             webauthn.AttestationNone,
		CredentialAlgs:          []int{webauthn.COSEAlgES256, webauthn.COSEAlgES384, webauthn.COSEAlgES512},
	}
	if err := cfg.Valid(); err != nil {
		fmt.Println("error:", err)
		return
	}

	// user contains user data for which the Relying Party is requesting attestation or assertion.
	user := &webauthn.User{
		ID:          []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
		Name:        "Jane Doe",
		DisplayName: "Jane",
		CredentialIDs: [][]byte{
			{0, 8, 71, 237, 201, 207, 68, 25, 28, 186, 72, 231, 115, 97, 182, 24, 205, 71, 229, 217, 21, 179, 211, 245, 171, 101, 68, 174, 16, 249, 238, 153, 51, 41, 88, 193, 110, 44, 93, 178, 231, 227, 94, 21, 14, 126, 32, 246, 236, 61, 21, 3, 231, 207, 41, 69, 88, 52, 97, 54, 93, 135, 35, 134, 40, 109, 96, 224, 208, 191, 236, 68, 106, 186, 101, 177, 174, 200, 199, 168, 74, 215, 113, 64, 234, 236, 145, 196, 200, 7, 11, 115, 225, 77, 188, 126, 173, 186, 191, 68, 197, 27, 104, 159, 135, 160, 101, 109, 249, 207, 54, 210, 39, 221, 161, 168, 36, 21, 29, 54, 85, 169, 252, 86, 191, 106, 235, 176, 103, 235, 49, 205, 13, 63, 195, 54, 180, 27, 182, 146, 20, 170, 165, 255, 70, 13, 169, 230, 142, 133, 237, 181, 78, 222, 227, 137, 27, 216, 84, 54, 5, 27},
		},
	}

	requestOptions, err := webauthn.NewAssertionOptions(cfg, user)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	requestOptionsJSON, err := json.Marshal(requestOptions)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	// Save user and requestOptions in session to verify assertion later.
	// Send requestOptionsJSON to web client, which passes it to navigator.credentials.get().

	fmt.Printf("%s\n", requestOptionsJSON)
}

func Example_parseAndVerifyAssertion() {
	// assertion represents assertion data returned by navigator.credentials.get().
	assertion := `{
	"id":"AAii3V6sGoaozW7TbNaYlJaJ5br8TrBfRXnofZO6l2suc3a5tt_XFuFkFA_5eabU80S1PW0m4IZ79BS2kQO7Zcuy2vf0ESg18GTLG1mo5YSkIdqL2J44egt-6rcj7NedSEwxa_uuxUYBtHNnSQqDmtoUAfM9LSWLl65BjKVZNGUp9ao33mMSdVfQQ0bHze69JVQvLBf8OTiZUqJsOuKmpqUc",
	"rawId":"AAii3V6sGoaozW7TbNaYlJaJ5br8TrBfRXnofZO6l2suc3a5tt_XFuFkFA_5eabU80S1PW0m4IZ79BS2kQO7Zcuy2vf0ESg18GTLG1mo5YSkIdqL2J44egt-6rcj7NedSEwxa_uuxUYBtHNnSQqDmtoUAfM9LSWLl65BjKVZNGUp9ao33mMSdVfQQ0bHze69JVQvLBf8OTiZUqJsOuKmpqUc",
	"response":{
			"clientDataJSON":    "eyJjaGFsbGVuZ2UiOiJlYVR5VU5ueVBERGRLOFNORWdURVV2ejFROGR5bGtqalRpbVlkNVg3UUFvLUY4X1oxbHNKaTNCaWxVcEZaSGtJQ05EV1k4cjlpdm5UZ1c3LVhaQzNxUSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
			"authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAABaw",
			"signature":         "MEYCIQD6dF3B0ZoaLA0r78oyRdoMNR0bN93Zi4cF_75hFAH6pQIhALY0UIsrh03u_f4yKOwzwD6Cj3_GWLJiioTT9580s1a7",
			"userHandle":        "AQIDBAUGBwgJCg"
	},
	"type":"public-key"
}`
	r := strings.NewReader(assertion)

	// Parse PublicKeyCredentialAssertion returned by navigator.credentials.get().
	credentialAssertion, err := webauthn.ParseAssertion(r)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	// Create credential from user's registered credential.
	credentialCoseKey := []byte{
		165, 1, 2, 3, 38, 32, 1, 33, 88, 32, 69, 236, 253, 104, 237, 176, 4, 5, 142, 231, 131, 46, 25, 177, 42, 73, 213, 154, 133, 41, 198, 48, 8, 55, 228, 16, 141, 145, 161, 55, 143, 196, 34, 88, 32, 62, 59, 246, 97, 132, 170, 147, 120, 130, 166, 236, 73, 123, 208, 65, 186, 122, 59, 120, 178, 13, 89, 106, 132, 57, 16, 184, 60, 147, 124, 176, 78,
	}
	c, _, err := webauthn.ParseCredential(credentialCoseKey)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	// Create AssertionExpectedData object from saved user info, user's registered credential, and requestOptions.
	expected := &webauthn.AssertionExpectedData{
		Origin:           "https://localhost:8443",
		RPID:             "localhost",
		Challenge:        "eaTyUNnyPDDdK8SNEgTEUvz1Q8dylkjjTimYd5X7QAo-F8_Z1lsJi3BilUpFZHkICNDWY8r9ivnTgW7-XZC3qQ",
		UserVerification: webauthn.UserVerificationPreferred,
		UserID:           []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
		UserCredentialIDs: [][]byte{
			{0, 8, 162, 221, 94, 172, 26, 134, 168, 205, 110, 211, 108, 214, 152, 148, 150, 137, 229, 186, 252, 78, 176, 95, 69, 121, 232, 125, 147, 186, 151, 107, 46, 115, 118, 185, 182, 223, 215, 22, 225, 100, 20, 15, 249, 121, 166, 212, 243, 68, 181, 61, 109, 38, 224, 134, 123, 244, 20, 182, 145, 3, 187, 101, 203, 178, 218, 247, 244, 17, 40, 53, 240, 100, 203, 27, 89, 168, 229, 132, 164, 33, 218, 139, 216, 158, 56, 122, 11, 126, 234, 183, 35, 236, 215, 157, 72, 76, 49, 107, 251, 174, 197, 70, 1, 180, 115, 103, 73, 10, 131, 154, 218, 20, 1, 243, 61, 45, 37, 139, 151, 174, 65, 140, 165, 89, 52, 101, 41, 245, 170, 55, 222, 99, 18, 117, 87, 208, 67, 70, 199, 205, 238, 189, 37, 84, 47, 44, 23, 252, 57, 56, 153, 82, 162, 108, 58, 226, 166, 166, 165, 28},
		},
		PrevCounter: uint32(0),
		Credential:  c,
	}

	err = webauthn.VerifyAssertion(credentialAssertion, expected)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	// Update counter in persistent store.
	// User is authenticated.

	fmt.Printf("Credential ID: %s\n", credentialAssertion.ID)
	fmt.Printf("Authenticator counter: %d\n", credentialAssertion.AuthnData.Counter)
	fmt.Printf("User present: %t\n", credentialAssertion.AuthnData.UserPresent)
	fmt.Printf("User verified: %t\n", credentialAssertion.AuthnData.UserVerified)

	// Output:
	// Credential ID: AAii3V6sGoaozW7TbNaYlJaJ5br8TrBfRXnofZO6l2suc3a5tt_XFuFkFA_5eabU80S1PW0m4IZ79BS2kQO7Zcuy2vf0ESg18GTLG1mo5YSkIdqL2J44egt-6rcj7NedSEwxa_uuxUYBtHNnSQqDmtoUAfM9LSWLl65BjKVZNGUp9ao33mMSdVfQQ0bHze69JVQvLBf8OTiZUqJsOuKmpqUc
	// Authenticator counter: 363
	// User present: true
	// User verified: false
}
