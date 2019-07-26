// Copyright (c) 2019 Faye Amacker. All rights reserved.
// Use of this source code is governed by Apache License 2.0 found in the LICENSE file.

package webauthn

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/fxamacker/cbor"
)

var (
	// Test data adapted from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	attestation1 = `{
		"rawId": "AAii3V6sGoaozW7TbNaYlJaJ5br8TrBfRXnofZO6l2suc3a5tt_XFuFkFA_5eabU80S1PW0m4IZ79BS2kQO7Zcuy2vf0ESg18GTLG1mo5YSkIdqL2J44egt-6rcj7NedSEwxa_uuxUYBtHNnSQqDmtoUAfM9LSWLl65BjKVZNGUp9ao33mMSdVfQQ0bHze69JVQvLBf8OTiZUqJsOuKmpqUc",
		"response": {
			"attestationObject": "o2NmbXRkbW9ja2dhdHRTdG10oGhhdXRoRGF0YVkBJkmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAKIACKLdXqwahqjNbtNs1piUlonluvxOsF9Feeh9k7qXay5zdrm239cW4WQUD_l5ptTzRLU9bSbghnv0FLaRA7tly7La9_QRKDXwZMsbWajlhKQh2ovYnjh6C37qtyPs151ITDFr-67FRgG0c2dJCoOa2hQB8z0tJYuXrkGMpVk0ZSn1qjfeYxJ1V9BDRsfN7r0lVC8sF_w5OJlSomw64qampRylAQIDJiABIVgguxHN3W6ehp0VWXKaMNie1J82MVJCFZYScau74o17cx8iWCDb1jkTLi7lYZZbgwUwpqAk8QmIiPMTVQUVkhGEyGrKww==",
			"clientDataJSON":    "eyJjaGFsbGVuZ2UiOiIzM0VIYXYtaloxdjlxd0g3ODNhVS1qMEFSeDZyNW8tWUhoLXdkN0M2alBiZDdXaDZ5dGJJWm9zSUlBQ2Vod2Y5LXM2aFhoeVNITy1ISFVqRXdaUzI5dyIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0="
		},
		"type": "public-key"
	}`
	attestation1Id        = "AAii3V6sGoaozW7TbNaYlJaJ5br8TrBfRXnofZO6l2suc3a5tt_XFuFkFA_5eabU80S1PW0m4IZ79BS2kQO7Zcuy2vf0ESg18GTLG1mo5YSkIdqL2J44egt-6rcj7NedSEwxa_uuxUYBtHNnSQqDmtoUAfM9LSWLl65BjKVZNGUp9ao33mMSdVfQQ0bHze69JVQvLBf8OTiZUqJsOuKmpqUc"
	attestation1Challenge = "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w"
	attestation1RPIDHash  = []byte{
		0x49, 0x96, 0x0D, 0xE5, 0x88, 0x0E, 0x8C, 0x68, 0x74, 0x34, 0x17, 0x0F, 0x64, 0x76, 0x60, 0x5B,
		0x8F, 0xE4, 0xAE, 0xB9, 0xA2, 0x86, 0x32, 0xC7, 0x99, 0x5C, 0xF3, 0xBA, 0x83, 0x1D, 0x97, 0x63}
	attestation1AAGUID        = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	attestation1CredentialKey = &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X: big.NewInt(0).SetBytes([]byte{
			0xBB, 0x11, 0xCD, 0xDD, 0x6E, 0x9E, 0x86, 0x9D, 0x15, 0x59, 0x72, 0x9A, 0x30, 0xD8, 0x9E, 0xD4,
			0x9F, 0x36, 0x31, 0x52, 0x42, 0x15, 0x96, 0x12, 0x71, 0xAB, 0xBB, 0xE2, 0x8D, 0x7B, 0x73, 0x1F}),
		Y: big.NewInt(0).SetBytes([]byte{
			0xDB, 0xD6, 0x39, 0x13, 0x2E, 0x2E, 0xE5, 0x61, 0x96, 0x5B, 0x83, 0x05, 0x30, 0xA6, 0xA0, 0x24,
			0xF1, 0x09, 0x88, 0x88, 0xF3, 0x13, 0x55, 0x05, 0x15, 0x92, 0x11, 0x84, 0xC8, 0x6A, 0xCA, 0xC3}),
	}

	// Test data adapted from herrjemand's verify.packed.webauthn.js (2019) at https://gist.github.com/herrjemand/dbeb2c2b76362052e5268224660b6fbc
	attestation2 = `{
		"id":    "H6X2BnnjgOzu_Oj87vpRnwMJeJYVzwM3wtY1lhAfQ14",
		"rawId": "H6X2BnnjgOzu_Oj87vpRnwMJeJYVzwM3wtY1lhAfQ14",
		"response": {
			"attestationObject": "o2NmbXRkbW9ja2dhdHRTdG10oGhhdXRoRGF0YVkBZ0mWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAADio1ZkkY7dJ6rneNKdT3h4BACAfpfYGeeOA7O786Pzu-lGfAwl4lhXPAzfC1jWWEB9DXqQBAwM5__4gWQEAwCKs8mzz5oHi-TkeiSqvW1g4hDSZTfy3j0BJ39f7IDpuBSfZAU2zk7VqZX6DF4ONAO5njKaYkaj-9gN7ZiC8GecSiMmO1fGNrfF9YpWCaJdpwijqQBKhi00SYxeuBkMXp9LhaYtbQOpejfmW6D8Y5MuGonQXVD9tmGbhDwjvPvWU4WvKsL04GcDB4WeNE1DxCRhljpxzZWJqp3xX5ND_lDmaJCNK6raqkBjMM1dkax9pIyk2Rn8rJAEJ66n_T6CZMnuClI1pFp2c4ZGW6w6C8kxF9qFr0035Z0ebQFTEHIeFBoBB0mdNBuUhaHNfZxsf1CXKns8eXC2bJ8vqkGA0YyFDAQAB",
			"clientDataJSON":    "eyJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjMwMDAiLCJjaGFsbGVuZ2UiOiJBWGtYV1hQUDNnTHg4T0xscGtKM2FSUmhGV250blNFTmdnbmpEcEJxbDFuZ0tvbDd4V3dldlVZdnJwQkRQM0xFdmRyMkVPU3RPRnBHR3huTXZYay1WdyIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ"
		},
		"type": "public-key"
	}`
	attestation2Id        = "H6X2BnnjgOzu_Oj87vpRnwMJeJYVzwM3wtY1lhAfQ14"
	attestation2Challenge = "AXkXWXPP3gLx8OLlpkJ3aRRhFWntnSENggnjDpBql1ngKol7xWwevUYvrpBDP3LEvdr2EOStOFpGGxnMvXk-Vw"
	attestation2RPIDHash  = []byte{
		0x49, 0x96, 0x0d, 0xe5, 0x88, 0x0e, 0x8c, 0x68, 0x74, 0x34, 0x17, 0x0f, 0x64, 0x76, 0x60, 0x5b,
		0x8f, 0xe4, 0xae, 0xb9, 0xa2, 0x86, 0x32, 0xc7, 0x99, 0x5c, 0xf3, 0xba, 0x83, 0x1d, 0x97, 0x63}
	attestation2AAGUID = []byte{
		0xa8, 0xd5, 0x99, 0x24, 0x63, 0xb7, 0x49, 0xea, 0xb9, 0xde, 0x34, 0xa7, 0x53, 0xde, 0x1e, 0x01,
	}
	attestation2CredentialKey = &rsa.PublicKey{
		N: big.NewInt(0).SetBytes([]byte{
			0xc0, 0x22, 0xac, 0xf2, 0x6c, 0xf3, 0xe6, 0x81, 0xe2, 0xf9, 0x39, 0x1e, 0x89, 0x2a, 0xaf, 0x5b,
			0x58, 0x38, 0x84, 0x34, 0x99, 0x4d, 0xfc, 0xb7, 0x8f, 0x40, 0x49, 0xdf, 0xd7, 0xfb, 0x20, 0x3a,
			0x6e, 0x05, 0x27, 0xd9, 0x01, 0x4d, 0xb3, 0x93, 0xb5, 0x6a, 0x65, 0x7e, 0x83, 0x17, 0x83, 0x8d,
			0x00, 0xee, 0x67, 0x8c, 0xa6, 0x98, 0x91, 0xa8, 0xfe, 0xf6, 0x03, 0x7b, 0x66, 0x20, 0xbc, 0x19,
			0xe7, 0x12, 0x88, 0xc9, 0x8e, 0xd5, 0xf1, 0x8d, 0xad, 0xf1, 0x7d, 0x62, 0x95, 0x82, 0x68, 0x97,
			0x69, 0xc2, 0x28, 0xea, 0x40, 0x12, 0xa1, 0x8b, 0x4d, 0x12, 0x63, 0x17, 0xae, 0x06, 0x43, 0x17,
			0xa7, 0xd2, 0xe1, 0x69, 0x8b, 0x5b, 0x40, 0xea, 0x5e, 0x8d, 0xf9, 0x96, 0xe8, 0x3f, 0x18, 0xe4,
			0xcb, 0x86, 0xa2, 0x74, 0x17, 0x54, 0x3f, 0x6d, 0x98, 0x66, 0xe1, 0x0f, 0x08, 0xef, 0x3e, 0xf5,
			0x94, 0xe1, 0x6b, 0xca, 0xb0, 0xbd, 0x38, 0x19, 0xc0, 0xc1, 0xe1, 0x67, 0x8d, 0x13, 0x50, 0xf1,
			0x09, 0x18, 0x65, 0x8e, 0x9c, 0x73, 0x65, 0x62, 0x6a, 0xa7, 0x7c, 0x57, 0xe4, 0xd0, 0xff, 0x94,
			0x39, 0x9a, 0x24, 0x23, 0x4a, 0xea, 0xb6, 0xaa, 0x90, 0x18, 0xcc, 0x33, 0x57, 0x64, 0x6b, 0x1f,
			0x69, 0x23, 0x29, 0x36, 0x46, 0x7f, 0x2b, 0x24, 0x01, 0x09, 0xeb, 0xa9, 0xff, 0x4f, 0xa0, 0x99,
			0x32, 0x7b, 0x82, 0x94, 0x8d, 0x69, 0x16, 0x9d, 0x9c, 0xe1, 0x91, 0x96, 0xeb, 0x0e, 0x82, 0xf2,
			0x4c, 0x45, 0xf6, 0xa1, 0x6b, 0xd3, 0x4d, 0xf9, 0x67, 0x47, 0x9b, 0x40, 0x54, 0xc4, 0x1c, 0x87,
			0x85, 0x06, 0x80, 0x41, 0xd2, 0x67, 0x4d, 0x06, 0xe5, 0x21, 0x68, 0x73, 0x5f, 0x67, 0x1b, 0x1f,
			0xd4, 0x25, 0xca, 0x9e, 0xcf, 0x1e, 0x5c, 0x2d, 0x9b, 0x27, 0xcb, 0xea, 0x90, 0x60, 0x34, 0x63}),
		E: 65537,
	}

	// Test data adapted from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	attestationMissingIDAndRawID = `{
		"response": {
			"attestationObject": "o2NmbXRkbW9ja2dhdHRTdG10oGhhdXRoRGF0YVkBJkmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAKIACKLdXqwahqjNbtNs1piUlonluvxOsF9Feeh9k7qXay5zdrm239cW4WQUD_l5ptTzRLU9bSbghnv0FLaRA7tly7La9_QRKDXwZMsbWajlhKQh2ovYnjh6C37qtyPs151ITDFr-67FRgG0c2dJCoOa2hQB8z0tJYuXrkGMpVk0ZSn1qjfeYxJ1V9BDRsfN7r0lVC8sF_w5OJlSomw64qampRylAQIDJiABIVgguxHN3W6ehp0VWXKaMNie1J82MVJCFZYScau74o17cx8iWCDb1jkTLi7lYZZbgwUwpqAk8QmIiPMTVQUVkhGEyGrKww==",
			"clientDataJSON":    "eyJjaGFsbGVuZ2UiOiIzM0VIYXYtaloxdjlxd0g3ODNhVS1qMEFSeDZyNW8tWUhoLXdkN0M2alBiZDdXaDZ5dGJJWm9zSUlBQ2Vod2Y5LXM2aFhoeVNITy1ISFVqRXdaUzI5dyIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0="
		},
		"type": "public-key"
	}`

	// Test data adapted from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	attestationMissingClientData = `{
		"id":    "AAii3V6sGoaozW7TbNaYlJaJ5br8TrBfRXnofZO6l2suc3a5tt_XFuFkFA_5eabU80S1PW0m4IZ79BS2kQO7Zcuy2vf0ESg18GTLG1mo5YSkIdqL2J44egt-6rcj7NedSEwxa_uuxUYBtHNnSQqDmtoUAfM9LSWLl65BjKVZNGUp9ao33mMSdVfQQ0bHze69JVQvLBf8OTiZUqJsOuKmpqUc",
		"rawId": "AAii3V6sGoaozW7TbNaYlJaJ5br8TrBfRXnofZO6l2suc3a5tt_XFuFkFA_5eabU80S1PW0m4IZ79BS2kQO7Zcuy2vf0ESg18GTLG1mo5YSkIdqL2J44egt-6rcj7NedSEwxa_uuxUYBtHNnSQqDmtoUAfM9LSWLl65BjKVZNGUp9ao33mMSdVfQQ0bHze69JVQvLBf8OTiZUqJsOuKmpqUc",
		"response": {
			"attestationObject": "o2NmbXRkbW9ja2dhdHRTdG10oGhhdXRoRGF0YVkBJkmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAKIACKLdXqwahqjNbtNs1piUlonluvxOsF9Feeh9k7qXay5zdrm239cW4WQUD_l5ptTzRLU9bSbghnv0FLaRA7tly7La9_QRKDXwZMsbWajlhKQh2ovYnjh6C37qtyPs151ITDFr-67FRgG0c2dJCoOa2hQB8z0tJYuXrkGMpVk0ZSn1qjfeYxJ1V9BDRsfN7r0lVC8sF_w5OJlSomw64qampRylAQIDJiABIVgguxHN3W6ehp0VWXKaMNie1J82MVJCFZYScau74o17cx8iWCDb1jkTLi7lYZZbgwUwpqAk8QmIiPMTVQUVkhGEyGrKww=="
		},
		"type": "public-key"
	}`

	// Test data adapted from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	attestationMissingAttestationObject = `{
		"id":    "AAii3V6sGoaozW7TbNaYlJaJ5br8TrBfRXnofZO6l2suc3a5tt_XFuFkFA_5eabU80S1PW0m4IZ79BS2kQO7Zcuy2vf0ESg18GTLG1mo5YSkIdqL2J44egt-6rcj7NedSEwxa_uuxUYBtHNnSQqDmtoUAfM9LSWLl65BjKVZNGUp9ao33mMSdVfQQ0bHze69JVQvLBf8OTiZUqJsOuKmpqUc",
		"rawId": "AAii3V6sGoaozW7TbNaYlJaJ5br8TrBfRXnofZO6l2suc3a5tt_XFuFkFA_5eabU80S1PW0m4IZ79BS2kQO7Zcuy2vf0ESg18GTLG1mo5YSkIdqL2J44egt-6rcj7NedSEwxa_uuxUYBtHNnSQqDmtoUAfM9LSWLl65BjKVZNGUp9ao33mMSdVfQQ0bHze69JVQvLBf8OTiZUqJsOuKmpqUc",
		"response": {
			"clientDataJSON": "eyJjaGFsbGVuZ2UiOiIzM0VIYXYtaloxdjlxd0g3ODNhVS1qMEFSeDZyNW8tWUhoLXdkN0M2alBiZDdXaDZ5dGJJWm9zSUlBQ2Vod2Y5LXM2aFhoeVNITy1ISFVqRXdaUzI5dyIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0="
		},
		"type": "public-key"
	}`

	// Test data adapted from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	attestationMissingType = `{
		"id":    "AAii3V6sGoaozW7TbNaYlJaJ5br8TrBfRXnofZO6l2suc3a5tt_XFuFkFA_5eabU80S1PW0m4IZ79BS2kQO7Zcuy2vf0ESg18GTLG1mo5YSkIdqL2J44egt-6rcj7NedSEwxa_uuxUYBtHNnSQqDmtoUAfM9LSWLl65BjKVZNGUp9ao33mMSdVfQQ0bHze69JVQvLBf8OTiZUqJsOuKmpqUc",
		"rawId": "AAii3V6sGoaozW7TbNaYlJaJ5br8TrBfRXnofZO6l2suc3a5tt_XFuFkFA_5eabU80S1PW0m4IZ79BS2kQO7Zcuy2vf0ESg18GTLG1mo5YSkIdqL2J44egt-6rcj7NedSEwxa_uuxUYBtHNnSQqDmtoUAfM9LSWLl65BjKVZNGUp9ao33mMSdVfQQ0bHze69JVQvLBf8OTiZUqJsOuKmpqUc",
		"response": {
			"attestationObject": "o2NmbXRkbW9ja2dhdHRTdG10oGhhdXRoRGF0YVkBJkmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAKIACKLdXqwahqjNbtNs1piUlonluvxOsF9Feeh9k7qXay5zdrm239cW4WQUD_l5ptTzRLU9bSbghnv0FLaRA7tly7La9_QRKDXwZMsbWajlhKQh2ovYnjh6C37qtyPs151ITDFr-67FRgG0c2dJCoOa2hQB8z0tJYuXrkGMpVk0ZSn1qjfeYxJ1V9BDRsfN7r0lVC8sF_w5OJlSomw64qampRylAQIDJiABIVgguxHN3W6ehp0VWXKaMNie1J82MVJCFZYScau74o17cx8iWCDb1jkTLi7lYZZbgwUwpqAk8QmIiPMTVQUVkhGEyGrKww==",
			"clientDataJSON":    "eyJjaGFsbGVuZ2UiOiIzM0VIYXYtaloxdjlxd0g3ODNhVS1qMEFSeDZyNW8tWUhoLXdkN0M2alBiZDdXaDZ5dGJJWm9zSUlBQ2Vod2Y5LXM2aFhoeVNITy1ISFVqRXdaUzI5dyIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0="
		}
	}`

	// Test data adapted from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	attestationInvalidID = `{
		"id": ":?",
		"response": {
			"attestationObject": "o2NmbXRkbW9ja2dhdHRTdG10oGhhdXRoRGF0YVkBJkmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAKIACKLdXqwahqjNbtNs1piUlonluvxOsF9Feeh9k7qXay5zdrm239cW4WQUD_l5ptTzRLU9bSbghnv0FLaRA7tly7La9_QRKDXwZMsbWajlhKQh2ovYnjh6C37qtyPs151ITDFr-67FRgG0c2dJCoOa2hQB8z0tJYuXrkGMpVk0ZSn1qjfeYxJ1V9BDRsfN7r0lVC8sF_w5OJlSomw64qampRylAQIDJiABIVgguxHN3W6ehp0VWXKaMNie1J82MVJCFZYScau74o17cx8iWCDb1jkTLi7lYZZbgwUwpqAk8QmIiPMTVQUVkhGEyGrKww==",
			"clientDataJSON":    "eyJjaGFsbGVuZ2UiOiIzM0VIYXYtaloxdjlxd0g3ODNhVS1qMEFSeDZyNW8tWUhoLXdkN0M2alBiZDdXaDZ5dGJJWm9zSUlBQ2Vod2Y5LXM2aFhoeVNITy1ISFVqRXdaUzI5dyIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0="
		},
		"type": "public-key"
	}`

	// Test data adapted from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	attestationDecodedIDEmpty = `{
		"id": "\n",
		"response": {
			"attestationObject": "o2NmbXRkbW9ja2dhdHRTdG10oGhhdXRoRGF0YVkBJkmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAKIACKLdXqwahqjNbtNs1piUlonluvxOsF9Feeh9k7qXay5zdrm239cW4WQUD_l5ptTzRLU9bSbghnv0FLaRA7tly7La9_QRKDXwZMsbWajlhKQh2ovYnjh6C37qtyPs151ITDFr-67FRgG0c2dJCoOa2hQB8z0tJYuXrkGMpVk0ZSn1qjfeYxJ1V9BDRsfN7r0lVC8sF_w5OJlSomw64qampRylAQIDJiABIVgguxHN3W6ehp0VWXKaMNie1J82MVJCFZYScau74o17cx8iWCDb1jkTLi7lYZZbgwUwpqAk8QmIiPMTVQUVkhGEyGrKww==",
			"clientDataJSON":    "eyJjaGFsbGVuZ2UiOiIzM0VIYXYtaloxdjlxd0g3ODNhVS1qMEFSeDZyNW8tWUhoLXdkN0M2alBiZDdXaDZ5dGJJWm9zSUlBQ2Vod2Y5LXM2aFhoeVNITy1ISFVqRXdaUzI5dyIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0="
		},
		"type": "public-key"
	}`

	// Test data adapted from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	attestationInvalidRawID = `{
		"rawId": ":?",
		"response": {
			"attestationObject": "o2NmbXRkbW9ja2dhdHRTdG10oGhhdXRoRGF0YVkBJkmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAKIACKLdXqwahqjNbtNs1piUlonluvxOsF9Feeh9k7qXay5zdrm239cW4WQUD_l5ptTzRLU9bSbghnv0FLaRA7tly7La9_QRKDXwZMsbWajlhKQh2ovYnjh6C37qtyPs151ITDFr-67FRgG0c2dJCoOa2hQB8z0tJYuXrkGMpVk0ZSn1qjfeYxJ1V9BDRsfN7r0lVC8sF_w5OJlSomw64qampRylAQIDJiABIVgguxHN3W6ehp0VWXKaMNie1J82MVJCFZYScau74o17cx8iWCDb1jkTLi7lYZZbgwUwpqAk8QmIiPMTVQUVkhGEyGrKww==",
			"clientDataJSON":    "eyJjaGFsbGVuZ2UiOiIzM0VIYXYtaloxdjlxd0g3ODNhVS1qMEFSeDZyNW8tWUhoLXdkN0M2alBiZDdXaDZ5dGJJWm9zSUlBQ2Vod2Y5LXM2aFhoeVNITy1ISFVqRXdaUzI5dyIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0="
		},
		"type": "public-key"
	}`

	// Test data adapted from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	attestationDecodedRawIDEmpty = `{
		"rawId": "=0",
		"response": {
			"attestationObject": "o2NmbXRkbW9ja2dhdHRTdG10oGhhdXRoRGF0YVkBJkmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAKIACKLdXqwahqjNbtNs1piUlonluvxOsF9Feeh9k7qXay5zdrm239cW4WQUD_l5ptTzRLU9bSbghnv0FLaRA7tly7La9_QRKDXwZMsbWajlhKQh2ovYnjh6C37qtyPs151ITDFr-67FRgG0c2dJCoOa2hQB8z0tJYuXrkGMpVk0ZSn1qjfeYxJ1V9BDRsfN7r0lVC8sF_w5OJlSomw64qampRylAQIDJiABIVgguxHN3W6ehp0VWXKaMNie1J82MVJCFZYScau74o17cx8iWCDb1jkTLi7lYZZbgwUwpqAk8QmIiPMTVQUVkhGEyGrKww==",
			"clientDataJSON":    "eyJjaGFsbGVuZ2UiOiIzM0VIYXYtaloxdjlxd0g3ODNhVS1qMEFSeDZyNW8tWUhoLXdkN0M2alBiZDdXaDZ5dGJJWm9zSUlBQ2Vod2Y5LXM2aFhoeVNITy1ISFVqRXdaUzI5dyIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0="
		},
		"type": "public-key"
	}`

	// Test data adapted from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	attestationInvalidClientData = `{
		"id":    "AAii3V6sGoaozW7TbNaYlJaJ5br8TrBfRXnofZO6l2suc3a5tt_XFuFkFA_5eabU80S1PW0m4IZ79BS2kQO7Zcuy2vf0ESg18GTLG1mo5YSkIdqL2J44egt-6rcj7NedSEwxa_uuxUYBtHNnSQqDmtoUAfM9LSWLl65BjKVZNGUp9ao33mMSdVfQQ0bHze69JVQvLBf8OTiZUqJsOuKmpqUc",
		"rawId": "AAii3V6sGoaozW7TbNaYlJaJ5br8TrBfRXnofZO6l2suc3a5tt_XFuFkFA_5eabU80S1PW0m4IZ79BS2kQO7Zcuy2vf0ESg18GTLG1mo5YSkIdqL2J44egt-6rcj7NedSEwxa_uuxUYBtHNnSQqDmtoUAfM9LSWLl65BjKVZNGUp9ao33mMSdVfQQ0bHze69JVQvLBf8OTiZUqJsOuKmpqUc",
		"response": {
			"attestationObject": "o2NmbXRkbW9ja2dhdHRTdG10oGhhdXRoRGF0YVkBJkmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAKIACKLdXqwahqjNbtNs1piUlonluvxOsF9Feeh9k7qXay5zdrm239cW4WQUD_l5ptTzRLU9bSbghnv0FLaRA7tly7La9_QRKDXwZMsbWajlhKQh2ovYnjh6C37qtyPs151ITDFr-67FRgG0c2dJCoOa2hQB8z0tJYuXrkGMpVk0ZSn1qjfeYxJ1V9BDRsfN7r0lVC8sF_w5OJlSomw64qampRylAQIDJiABIVgguxHN3W6ehp0VWXKaMNie1J82MVJCFZYScau74o17cx8iWCDb1jkTLi7lYZZbgwUwpqAk8QmIiPMTVQUVkhGEyGrKww==",
			"clientDataJSON":    ":?"
		},
		"type": "public-key"
	}`

	// Test data adapted from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	attestationInvalidAttestationObject = `{
		"id":    "AAii3V6sGoaozW7TbNaYlJaJ5br8TrBfRXnofZO6l2suc3a5tt_XFuFkFA_5eabU80S1PW0m4IZ79BS2kQO7Zcuy2vf0ESg18GTLG1mo5YSkIdqL2J44egt-6rcj7NedSEwxa_uuxUYBtHNnSQqDmtoUAfM9LSWLl65BjKVZNGUp9ao33mMSdVfQQ0bHze69JVQvLBf8OTiZUqJsOuKmpqUc",
		"rawId": "AAii3V6sGoaozW7TbNaYlJaJ5br8TrBfRXnofZO6l2suc3a5tt_XFuFkFA_5eabU80S1PW0m4IZ79BS2kQO7Zcuy2vf0ESg18GTLG1mo5YSkIdqL2J44egt-6rcj7NedSEwxa_uuxUYBtHNnSQqDmtoUAfM9LSWLl65BjKVZNGUp9ao33mMSdVfQQ0bHze69JVQvLBf8OTiZUqJsOuKmpqUc",
		"response": {
			"attestationObject": ":?",
			"clientDataJSON":    "eyJjaGFsbGVuZ2UiOiIzM0VIYXYtaloxdjlxd0g3ODNhVS1qMEFSeDZyNW8tWUhoLXdkN0M2alBiZDdXaDZ5dGJJWm9zSUlBQ2Vod2Y5LXM2aFhoeVNITy1ISFVqRXdaUzI5dyIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0="
		},
		"type": "public-key"
	}`

	// Test data adapted from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	attestationBadClientDataJSON = `{
		"id": "AAii3V6sGoaozW7TbNaYlJaJ5br8TrBfRXnofZO6l2suc3a5tt_XFuFkFA_5eabU80S1PW0m4IZ79BS2kQO7Zcuy2vf0ESg18GTLG1mo5YSkIdqL2J44egt-6rcj7NedSEwxa_uuxUYBtHNnSQqDmtoUAfM9LSWLl65BjKVZNGUp9ao33mMSdVfQQ0bHze69JVQvLBf8OTiZUqJsOuKmpqUc",
		"response": {
			"attestationObject": "o2NmbXRkbW9ja2dhdHRTdG10oGhhdXRoRGF0YVkBJkmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAKIACKLdXqwahqjNbtNs1piUlonluvxOsF9Feeh9k7qXay5zdrm239cW4WQUD_l5ptTzRLU9bSbghnv0FLaRA7tly7La9_QRKDXwZMsbWajlhKQh2ovYnjh6C37qtyPs151ITDFr-67FRgG0c2dJCoOa2hQB8z0tJYuXrkGMpVk0ZSn1qjfeYxJ1V9BDRsfN7r0lVC8sF_w5OJlSomw64qampRylAQIDJiABIVgguxHN3W6ehp0VWXKaMNie1J82MVJCFZYScau74o17cx8iWCDb1jkTLi7lYZZbgwUwpqAk8QmIiPMTVQUVkhGEyGrKww==",
			"clientDataJSON":    "aGVsbG8="
		},
		"type": "public-key"
	}`

	// Test data adapted from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	attestationBadAttestationObjectCbor = `{
		"id": "AAii3V6sGoaozW7TbNaYlJaJ5br8TrBfRXnofZO6l2suc3a5tt_XFuFkFA_5eabU80S1PW0m4IZ79BS2kQO7Zcuy2vf0ESg18GTLG1mo5YSkIdqL2J44egt-6rcj7NedSEwxa_uuxUYBtHNnSQqDmtoUAfM9LSWLl65BjKVZNGUp9ao33mMSdVfQQ0bHze69JVQvLBf8OTiZUqJsOuKmpqUc",
		"response": {
			"attestationObject": "aGVsbG8=",
			"clientDataJSON":    "eyJjaGFsbGVuZ2UiOiIzM0VIYXYtaloxdjlxd0g3ODNhVS1qMEFSeDZyNW8tWUhoLXdkN0M2alBiZDdXaDZ5dGJJWm9zSUlBQ2Vod2Y5LXM2aFhoeVNITy1ISFVqRXdaUzI5dyIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0="
		},
		"type": "public-key"
	}`

	// Test data adapted from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	attestationBadType = `{
		"id":    "AAii3V6sGoaozW7TbNaYlJaJ5br8TrBfRXnofZO6l2suc3a5tt_XFuFkFA_5eabU80S1PW0m4IZ79BS2kQO7Zcuy2vf0ESg18GTLG1mo5YSkIdqL2J44egt-6rcj7NedSEwxa_uuxUYBtHNnSQqDmtoUAfM9LSWLl65BjKVZNGUp9ao33mMSdVfQQ0bHze69JVQvLBf8OTiZUqJsOuKmpqUc",
		"rawId": "AAii3V6sGoaozW7TbNaYlJaJ5br8TrBfRXnofZO6l2suc3a5tt_XFuFkFA_5eabU80S1PW0m4IZ79BS2kQO7Zcuy2vf0ESg18GTLG1mo5YSkIdqL2J44egt-6rcj7NedSEwxa_uuxUYBtHNnSQqDmtoUAfM9LSWLl65BjKVZNGUp9ao33mMSdVfQQ0bHze69JVQvLBf8OTiZUqJsOuKmpqUc",
		"response": {
			"attestationObject": "o2NmbXRkbW9ja2dhdHRTdG10oGhhdXRoRGF0YVkBJkmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAKIACKLdXqwahqjNbtNs1piUlonluvxOsF9Feeh9k7qXay5zdrm239cW4WQUD_l5ptTzRLU9bSbghnv0FLaRA7tly7La9_QRKDXwZMsbWajlhKQh2ovYnjh6C37qtyPs151ITDFr-67FRgG0c2dJCoOa2hQB8z0tJYuXrkGMpVk0ZSn1qjfeYxJ1V9BDRsfN7r0lVC8sF_w5OJlSomw64qampRylAQIDJiABIVgguxHN3W6ehp0VWXKaMNie1J82MVJCFZYScau74o17cx8iWCDb1jkTLi7lYZZbgwUwpqAk8QmIiPMTVQUVkhGEyGrKww==",
			"clientDataJSON":    "eyJjaGFsbGVuZ2UiOiIzM0VIYXYtaloxdjlxd0g3ODNhVS1qMEFSeDZyNW8tWUhoLXdkN0M2alBiZDdXaDZ5dGJJWm9zSUlBQ2Vod2Y5LXM2aFhoeVNITy1ISFVqRXdaUzI5dyIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0="
		},
		"type": "key"
	}`
)

type mockAttestationStatement struct {
}

func parseMockAttestation(data []byte) (AttestationStatement, error) {
	return &mockAttestationStatement{}, nil
}

func (attStmt *mockAttestationStatement) Verify(rawClientData []byte, authnData *AuthenticatorData) (attType AttestationType, trustPath interface{}, err error) {
	return AttestationTypeBasic, nil, nil
}

type parseAttestationTest struct {
	name                    string
	attestation             []byte
	wantCredentialID        string
	wantCredentialRawID     []byte
	wantClientDataOrigin    string
	wantClientDataType      string
	wantClientDataChallenge string
	wantTokenBindingStatus  string
	wantTokenBindingID      string
	wantRPIDHash            []byte
	wantUserPresent         bool
	wantUserVerified        bool
	wantCounter             uint32
	wantExtension           map[string]interface{}
	wantAAGUID              []byte
	wantCredentialSigAlg    x509.SignatureAlgorithm
	wantCredentialKey       crypto.PublicKey
}

type verifyAttestationTest struct {
	name                         string
	attestation                  []byte
	wantAttestationStatementType reflect.Type
	wantAttestationType          AttestationType
	wantTrustPath                interface{}
}

type parseAttestationErrorTest struct {
	name         string
	attestation  []byte
	wantErrorMsg string
}

var parseAttestationTests = []parseAttestationTest{
	{
		name:                    "attestation ECDSAWithSHA256 with mock format",
		attestation:             []byte(attestation1),
		wantCredentialID:        attestation1Id,
		wantCredentialRawID:     base64Decode(attestation1Id),
		wantClientDataOrigin:    "https://localhost:8443",
		wantClientDataType:      "webauthn.create",
		wantClientDataChallenge: attestation1Challenge,
		wantTokenBindingStatus:  "",
		wantTokenBindingID:      "",
		wantRPIDHash:            attestation1RPIDHash,
		wantUserPresent:         true,
		wantUserVerified:        false,
		wantCounter:             uint32(0),
		wantExtension:           nil,
		wantAAGUID:              attestation1AAGUID,
		wantCredentialSigAlg:    x509.ECDSAWithSHA256,
		wantCredentialKey:       attestation1CredentialKey,
	},
	{
		name:                    "attestation SHA1WithRSA with mock format",
		attestation:             []byte(attestation2),
		wantCredentialID:        attestation2Id,
		wantCredentialRawID:     base64Decode(attestation2Id),
		wantClientDataOrigin:    "http://localhost:3000",
		wantClientDataType:      "webauthn.create",
		wantClientDataChallenge: attestation2Challenge,
		wantTokenBindingStatus:  "",
		wantTokenBindingID:      "",
		wantRPIDHash:            attestation2RPIDHash,
		wantUserPresent:         true,
		wantUserVerified:        false,
		wantCounter:             uint32(56),
		wantExtension:           nil,
		wantAAGUID:              attestation2AAGUID,
		wantCredentialSigAlg:    x509.SHA1WithRSA,
		wantCredentialKey:       attestation2CredentialKey,
	},
}

var verifyAttestationTests = []verifyAttestationTest{
	{"attestation ECDSAWithSHA256 with mock format", []byte(attestation1), reflect.TypeOf(&mockAttestationStatement{}), AttestationTypeBasic, nil},
}

var parseAttestationErrorTests = []parseAttestationErrorTest{
	{"missing ID and raw ID", []byte(attestationMissingIDAndRawID), "attestation: missing credential id and raw id"},
	{"missing client data", []byte(attestationMissingClientData), "attestation: missing client data"},
	{"missing attestation object", []byte(attestationMissingAttestationObject), "attestation: missing attestation object"},
	{"missing type", []byte(attestationMissingType), "attestation: missing type"},
	{"id is not base64 encoded", []byte(attestationInvalidID), "attestation: failed to base64 decode credential id"},
	{"base64 decoded id is empty", []byte(attestationDecodedIDEmpty), "attestation: base64 decoded credential id is empty"},
	{"raw id is not base64 encoded", []byte(attestationInvalidRawID), "attestation: failed to base64 decode credential raw id"},
	{"base64 decoded raw id is empty", []byte(attestationDecodedRawIDEmpty), "attestation: base64 decoded credential raw id is empty"},
	{"client data is not base64 encoded", []byte(attestationInvalidClientData), "attestation: failed to base64 decode client data"},
	{"attestation object is not base64 encoded", []byte(attestationInvalidAttestationObject), "attestation: failed to base64 decode attestation object"},
	{"client data is not well-formed JSON", []byte(attestationBadClientDataJSON), "client_data: failed to unmarshal: invalid character"},
	{"attestation object is not well-formed CBOR", []byte(attestationBadAttestationObjectCbor), "attestation_object: failed to unmarshal: unexpected EOF"},
	{"type is wrong", []byte(attestationBadType), "attestation: expected type as \"public-key\", got \"key\""},
}

func base64Decode(s string) []byte {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		panic(err.Error())
	}
	return b
}

func TestParseAttestation(t *testing.T) {
	// register mock attestation statement
	RegisterAttestationFormat("mock", parseMockAttestation)
	defer UnregisterAttestationFormat("mock")

	for _, tc := range parseAttestationTests {
		t.Run(tc.name, func(t *testing.T) {
			var credentialAttestation PublicKeyCredentialAttestation
			if err := json.Unmarshal(tc.attestation, &credentialAttestation); err != nil {
				t.Fatalf("failed to unmarshal attestation %s: %q", string(tc.attestation), err)
			}

			// verify credential id and raw id
			if credentialAttestation.ID != tc.wantCredentialID {
				t.Errorf("credential id %s, want %s", credentialAttestation.ID, tc.wantCredentialID)
			}
			if !bytes.Equal(credentialAttestation.RawID, tc.wantCredentialRawID) {
				t.Errorf("credential raw id %v, want %v", credentialAttestation.RawID, tc.wantCredentialRawID)
			}

			// verify client data
			if credentialAttestation.ClientData.Origin != tc.wantClientDataOrigin {
				t.Errorf("client data origin %s, want %s", credentialAttestation.ClientData.Origin, tc.wantClientDataOrigin)
			}
			if credentialAttestation.ClientData.Type != tc.wantClientDataType {
				t.Errorf("client data type %s, want %s", credentialAttestation.ClientData.Type, tc.wantClientDataType)
			}
			if credentialAttestation.ClientData.Challenge != tc.wantClientDataChallenge {
				t.Errorf("client data challenge %s, want %s", credentialAttestation.ClientData.Challenge, tc.wantClientDataChallenge)
			}
			if credentialAttestation.ClientData.TokenBinding == nil {
				if len(tc.wantTokenBindingStatus) != 0 {
					t.Errorf("client data has no token binding, want token binding status %s", tc.wantTokenBindingStatus)
				}
				if len(tc.wantTokenBindingID) != 0 {
					t.Errorf("client data has no token binding, want token binding id %s", tc.wantTokenBindingID)
				}
			} else {
				if string(credentialAttestation.ClientData.TokenBinding.Status) != tc.wantTokenBindingStatus {
					t.Errorf("client data token binding status %s, want %s", credentialAttestation.ClientData.TokenBinding.Status, tc.wantTokenBindingStatus)
				}
				if credentialAttestation.ClientData.TokenBinding.ID != tc.wantTokenBindingID {
					t.Errorf("client data token binding id %s, want %s", credentialAttestation.ClientData.TokenBinding.ID, tc.wantTokenBindingID)
				}
			}

			// verify authenticator data
			if !bytes.Equal(credentialAttestation.AuthnData.RPIDHash, tc.wantRPIDHash) {
				t.Errorf("rp id hash %0x, want %0x", credentialAttestation.AuthnData.RPIDHash, tc.wantRPIDHash)
			}
			if credentialAttestation.AuthnData.UserPresent != tc.wantUserPresent {
				t.Errorf("user present %t, want %t", credentialAttestation.AuthnData.UserPresent, tc.wantUserPresent)
			}
			if credentialAttestation.AuthnData.UserVerified != tc.wantUserVerified {
				t.Errorf("user verified %t, want %t", credentialAttestation.AuthnData.UserVerified, tc.wantUserVerified)
			}
			if credentialAttestation.AuthnData.Counter != tc.wantCounter {
				t.Errorf("counter %d, want %d", credentialAttestation.AuthnData.Counter, tc.wantCounter)
			}
			if !reflect.DeepEqual(credentialAttestation.AuthnData.Extensions, tc.wantExtension) {
				t.Errorf("extensions %v, want %v", credentialAttestation.AuthnData.Extensions, tc.wantExtension)
			}

			// verify attested credential data
			if !bytes.Equal(credentialAttestation.AuthnData.AAGUID, tc.wantAAGUID) {
				t.Errorf("AAGUID %0x, want %0x", credentialAttestation.AuthnData.AAGUID, tc.wantAAGUID)
			}
			if !bytes.Equal(credentialAttestation.AuthnData.CredentialID, credentialAttestation.RawID) {
				t.Errorf("authenticator credential id %0x, want %0x", credentialAttestation.AuthnData.CredentialID, credentialAttestation.RawID)
			}
			if credentialAttestation.AuthnData.Credential.Algorithm != tc.wantCredentialSigAlg {
				t.Errorf("credential algorithm %s, want %s", credentialAttestation.AuthnData.Credential.Algorithm, tc.wantCredentialSigAlg)
			}
			if !reflect.DeepEqual(credentialAttestation.AuthnData.Credential.PublicKey, tc.wantCredentialKey) {
				t.Errorf("credential public key %+v, want %+v", credentialAttestation.AuthnData.Credential.PublicKey, tc.wantCredentialKey)
			}
		})
	}
}

func TestVerifyAttestation(t *testing.T) {
	// register mock attestation statement
	RegisterAttestationFormat("mock", parseMockAttestation)
	defer UnregisterAttestationFormat("mock")

	for _, tc := range verifyAttestationTests {
		t.Run(tc.name, func(t *testing.T) {
			var credentialAttestation PublicKeyCredentialAttestation
			if err := json.Unmarshal(tc.attestation, &credentialAttestation); err != nil {
				t.Fatalf("failed to unmarshal attestation %s: %q", string(tc.attestation), err)
			}
			if reflect.TypeOf(credentialAttestation.AttStmt) != tc.wantAttestationStatementType {
				t.Errorf("attestation statement type %T, want %T", credentialAttestation.AttStmt, tc.wantAttestationStatementType)
			}
			attType, trustPath, err := credentialAttestation.VerifyAttestationStatement()
			if err != nil {
				t.Fatalf("VerifyAttestationStatement() returns error %q", err)
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
	for _, tc := range parseAttestationErrorTests {
		t.Run(tc.name, func(t *testing.T) {
			var credentialAttestation PublicKeyCredentialAttestation
			if err := json.Unmarshal(tc.attestation, &credentialAttestation); err == nil {
				t.Errorf("unmarshal PublicKeyCredentialAttestation %s returns no error,  want error containing substring %q", string(tc.attestation), tc.wantErrorMsg)
			} else if !strings.Contains(err.Error(), tc.wantErrorMsg) {
				t.Errorf("unmarshal PublicKeyCredentialAttestation %s returns error %q,  want error containing substring %q", string(tc.attestation), err, tc.wantErrorMsg)
			}
		})
	}
}

func TestParseAuthenticatorDataError(t *testing.T) {
	rpIDHash := sha256.Sum256([]byte("localhost"))
	counter := []byte{0, 0, 0, 12}
	aaguid := [16]byte{}
	credentialIDLength := []byte{0, 8}
	credentialID := [8]byte{}

	// truncated data (missing counter)
	var invalidDataBuf1 bytes.Buffer
	invalidDataBuf1.Write(rpIDHash[:])
	invalidDataBuf1.WriteByte(0x44) // flag: up = 0, uv = 1, attestation included, no extensions

	// truncated credential data (missing credential id length, credential id, and cose key)
	var invalidDataBuf2 bytes.Buffer
	invalidDataBuf2.Write(rpIDHash[:])
	invalidDataBuf2.WriteByte(0x44) // flag: up = 0, uv = 1, attestation included, no extensions
	invalidDataBuf2.Write(counter)
	invalidDataBuf2.Write(aaguid[:])

	// truncated credential data (missing credential id, and cose key)
	var invalidDataBuf3 bytes.Buffer
	invalidDataBuf3.Write(rpIDHash[:])
	invalidDataBuf3.WriteByte(0x44) // flag: up = 0, uv = 1, attestation included, no extensions
	invalidDataBuf3.Write(counter)
	invalidDataBuf3.Write(aaguid[:])
	invalidDataBuf3.Write(credentialIDLength)

	// truncated credential data (missing cose key)
	var invalidDataBuf4 bytes.Buffer
	invalidDataBuf4.Write(rpIDHash[:])
	invalidDataBuf4.WriteByte(0x44) // flag: up = 0, uv = 1, attestation included, no extensions
	invalidDataBuf4.Write(counter)
	invalidDataBuf4.Write(aaguid[:])
	invalidDataBuf4.Write(credentialIDLength)
	invalidDataBuf4.Write(credentialID[:])

	// include extension
	var extensionIncluded bytes.Buffer
	extensionIncluded.Write(rpIDHash[:])
	extensionIncluded.WriteByte(0x80) // flag: up = 0, uv = 0, no attestation, extensions included
	extensionIncluded.Write(counter)

	testCases := []struct {
		name         string
		data         []byte
		wantErrorMsg string
	}{
		{"truncated authenticator data", invalidDataBuf1.Bytes(), "authenticator_data: failed to unmarshal: unexpected EOF"},
		{"truncated credential data", invalidDataBuf2.Bytes(), "authenticator_data: failed to unmarshal: unexpected EOF"},
		{"truncated credential data", invalidDataBuf3.Bytes(), "authenticator_data: failed to unmarshal: unexpected EOF"},
		{"truncated credential data", invalidDataBuf4.Bytes(), "credential: failed to unmarshal: EOF"},
		{"authenticator extension not supported", extensionIncluded.Bytes(), "authenticator data extension is not supported"},
	}

	for _, tc := range testCases {
		if _, _, err := parseAuthenticatorData(tc.data); err == nil {
			t.Errorf("%s: parseAuthenticatorData() returns no error,  want error containing substring %q", tc.name, tc.wantErrorMsg)
		} else if !strings.Contains(err.Error(), tc.wantErrorMsg) {
			t.Errorf("%s: parseAuthenticatorData() returns error %q,  want error containing substring %q", tc.name, err, tc.wantErrorMsg)
		}
	}
}

func TestParseAttestationObjectError(t *testing.T) {
	coseKeyES256 := map[int]interface{}{
		labelKty: coseKeyTypeEllipticCurve,
		labelAlg: COSEAlgES256,
		labelCrv: coseCurveP256,
		labelX:   []byte{0x65, 0xed, 0xa5, 0xa1, 0x25, 0x77, 0xc2, 0xba, 0xe8, 0x29, 0x43, 0x7f, 0xe3, 0x38, 0x70, 0x1a, 0x10, 0xaa, 0xa3, 0x75, 0xe1, 0xbb, 0x5b, 0x5d, 0xe1, 0x08, 0xde, 0x43, 0x9c, 0x08, 0x55, 0x1d},
		labelY:   []byte{0x1e, 0x52, 0xed, 0x75, 0x70, 0x11, 0x63, 0xf7, 0xf9, 0xe4, 0x0d, 0xdf, 0x9f, 0x34, 0x1b, 0x3d, 0xc9, 0xba, 0x86, 0x0a, 0xf7, 0xe0, 0xca, 0x7c, 0xa7, 0xe9, 0xee, 0xcd, 0x00, 0x84, 0xd1, 0x9c},
	}
	credentialKeyData, err := cbor.Marshal(coseKeyES256, cbor.EncOptions{Canonical: true})
	if err != nil {
		panic(err)
	}

	rpIDHash := sha256.Sum256([]byte("localhost"))
	counter := []byte{0, 0, 0, 12}
	aaguid := [16]byte{}
	credentialIDLength := []byte{0, 8}
	credentialID := [8]byte{}

	var authnDataBuf bytes.Buffer
	authnDataBuf.Write(rpIDHash[:])
	authnDataBuf.WriteByte(0x44) // flag: up = 0, uv = 1, attestation = 1, extensions = 0
	authnDataBuf.Write(counter)
	authnDataBuf.Write(aaguid[:])
	authnDataBuf.Write(credentialIDLength)
	authnDataBuf.Write(credentialID[:])
	authnDataBuf.Write(credentialKeyData)

	var authnDataNoCredentialBuf bytes.Buffer
	authnDataNoCredentialBuf.Write(rpIDHash[:])
	authnDataNoCredentialBuf.WriteByte(0x04) // flag: up = 0, uv = 1, attestation = 0, extensions = 0
	authnDataNoCredentialBuf.Write(counter)

	attStmt := map[string]interface{}{}

	emptyAuthnData := map[string]interface{}{
		"authData": []byte{},
		"fmt":      "mock",
		"attStmt":  attStmt,
	}

	emptyFmt := map[string]interface{}{
		"authData": authnDataBuf.Bytes(),
		"fmt":      "",
		"attStmt":  attStmt,
	}

	badAuthn := map[string]interface{}{
		"authData": []byte{1, 2, 3},
		"fmt":      "mock",
		"attStmt":  attStmt,
	}

	notRegisteredFmt := map[string]interface{}{
		"authData": authnDataBuf.Bytes(),
		"fmt":      "mock",
		"attStmt":  attStmt,
	}

	noCredential := map[string]interface{}{
		"authData": authnDataNoCredentialBuf.Bytes(),
		"fmt":      "mock",
		"attStmt":  attStmt,
	}

	testCases := []struct {
		name         string
		data         []byte
		wantErrorMsg string
	}{
		{"invalid input cbor data", []byte("hello"), "attestation_object: failed to unmarshal: unexpected EOF"},
		{"empty authn data", cborMarshal(emptyAuthnData), "attestation_object: missing authenticator data"},
		{"empty fmt", cborMarshal(emptyFmt), "attestation_object: missing attestation statement format"},
		{"bad authn data", cborMarshal(badAuthn), "authenticator_data: failed to unmarshal: unexpected EOF"},
		{"attestation statement format not registered", cborMarshal(notRegisteredFmt), "attestation statement format mock is not registered"},
		{"authn data does not include credential data", cborMarshal(noCredential), "attestation_object: missing credential data"},
	}

	for _, tc := range testCases {
		if _, _, err := parseAttestationObject(tc.data); err == nil {
			t.Errorf("%s: parseAttestationObject() returns no error, want error containing substring %q", tc.name, tc.wantErrorMsg)
		} else if !strings.Contains(err.Error(), tc.wantErrorMsg) {
			t.Errorf("%s: parseAttestationObject() returns error %q, want error containing substring %q", tc.name, err, tc.wantErrorMsg)
		}
	}
}
