// Copyright (c) 2019 Faye Amacker. All rights reserved.
// Use of this source code is governed by Apache License 2.0 found in the LICENSE file.

package webauthn

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

var (
	// Test data from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	assertion1 = `{
		"rawId": "AAhH7cnPRBkcukjnc2G2GM1H5dkVs9P1q2VErhD57pkzKVjBbixdsufjXhUOfiD27D0VA-fPKUVYNGE2XYcjhihtYODQv-xEarplsa7Ix6hK13FA6uyRxMgHC3PhTbx-rbq_RMUbaJ-HoGVt-c820ifdoagkFR02Van8Vr9q67Bn6zHNDT_DNrQbtpIUqqX_Rg2p5o6F7bVO3uOJG9hUNgUb",
		"response": {
			"clientDataJSON":    "eyJjaGFsbGVuZ2UiOiJlYVR5VU5ueVBERGRLOFNORWdURVV2ejFROGR5bGtqalRpbVlkNVg3UUFvLUY4X1oxbHNKaTNCaWxVcEZaSGtJQ05EV1k4cjlpdm5UZ1c3LVhaQzNxUSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
			"authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAABaw",
			"signature":         "MEYCIQD6dF3B0ZoaLA0r78oyRdoMNR0bN93Zi4cF_75hFAH6pQIhALY0UIsrh03u_f4yKOwzwD6Cj3_GWLJiioTT9580s1a7",
			"userHandle":        ""
		},
		"type": "public-key"
	}`
	assertion1Id        = "AAhH7cnPRBkcukjnc2G2GM1H5dkVs9P1q2VErhD57pkzKVjBbixdsufjXhUOfiD27D0VA-fPKUVYNGE2XYcjhihtYODQv-xEarplsa7Ix6hK13FA6uyRxMgHC3PhTbx-rbq_RMUbaJ-HoGVt-c820ifdoagkFR02Van8Vr9q67Bn6zHNDT_DNrQbtpIUqqX_Rg2p5o6F7bVO3uOJG9hUNgUb"
	assertion1Sig       = "MEYCIQD6dF3B0ZoaLA0r78oyRdoMNR0bN93Zi4cF_75hFAH6pQIhALY0UIsrh03u_f4yKOwzwD6Cj3_GWLJiioTT9580s1a7"
	assertion1Challenge = "eaTyUNnyPDDdK8SNEgTEUvz1Q8dylkjjTimYd5X7QAo-F8_Z1lsJi3BilUpFZHkICNDWY8r9ivnTgW7-XZC3qQ"
	assertion1RPIDHash  = []byte{
		0x49, 0x96, 0x0d, 0xe5, 0x88, 0x0e, 0x8c, 0x68, 0x74, 0x34, 0x17, 0x0f, 0x64, 0x76, 0x60, 0x5b,
		0x8f, 0xe4, 0xae, 0xb9, 0xa2, 0x86, 0x32, 0xc7, 0x99, 0x5c, 0xf3, 0xba, 0x83, 0x1d, 0x97, 0x63}

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
	assertion2Id        = "AwVUFfSwuMV1DRHfYmNry1IUGW03wEw9aTAR7kJM1nw"
	assertion2Sig       = "ElyXBPkS6ps0aod8pSEwdbaeG04SUSoucEHaulPrK3eBk3R4aePjTB-SjiPbya5rxzbuUIYO0UnqkpZrb19ZywWqwQ7qVxZzxSq7BCZmJhcML7j54eK_2nszVwXXVgO7WxpBcy_JQMxjwjXw6wNAxmnJ-H3TJJO82x4-9pDkno-GjUH2ObYk9NtkgylyMcENUaPYqajSLX-q5k14T2g839UC3xzsg71xHXQSeHgzPt6f3TXpNxNNcBYJAMm8-exKsoMkxHPDLkzK1wd5giietdoT25XQ72i8fjSSL8eiS1gllEjwbqLJn5zMQbWlgpSzJy3lK634sdeZtmMpXbRtMA"
	assertion2Challenge = "m7ZU0Z-_IiwviFnF1JXeJjFhVBincW69E1Ctj8AQ-Ybb1uc41bMHtItg6JACh1sOj_ZXjonw2acj_JD2i-axEQ"
	assertion2RPIDHash  = []byte{
		0x95, 0x69, 0x08, 0x8f, 0x1e, 0xce, 0xe3, 0x23, 0x29, 0x54, 0x03, 0x5d, 0xbd, 0x10, 0xd7, 0xca,
		0xe3, 0x91, 0x30, 0x5a, 0x27, 0x51, 0xb5, 0x59, 0xbb, 0x8f, 0xd7, 0xcb, 0xb2, 0x29, 0xbd, 0xd4}

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

	// Test data adapted from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	assertionMissingClientData = `{
		"id":    "AAhH7cnPRBkcukjnc2G2GM1H5dkVs9P1q2VErhD57pkzKVjBbixdsufjXhUOfiD27D0VA-fPKUVYNGE2XYcjhihtYODQv-xEarplsa7Ix6hK13FA6uyRxMgHC3PhTbx-rbq_RMUbaJ-HoGVt-c820ifdoagkFR02Van8Vr9q67Bn6zHNDT_DNrQbtpIUqqX_Rg2p5o6F7bVO3uOJG9hUNgUb",
		"rawId": "AAhH7cnPRBkcukjnc2G2GM1H5dkVs9P1q2VErhD57pkzKVjBbixdsufjXhUOfiD27D0VA-fPKUVYNGE2XYcjhihtYODQv-xEarplsa7Ix6hK13FA6uyRxMgHC3PhTbx-rbq_RMUbaJ-HoGVt-c820ifdoagkFR02Van8Vr9q67Bn6zHNDT_DNrQbtpIUqqX_Rg2p5o6F7bVO3uOJG9hUNgUb",
		"response": {
			"authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAABaw",
			"signature":         "MEYCIQD6dF3B0ZoaLA0r78oyRdoMNR0bN93Zi4cF_75hFAH6pQIhALY0UIsrh03u_f4yKOwzwD6Cj3_GWLJiioTT9580s1a7",
			"userHandle":        ""
		},
		"type": "public-key"
	}`

	// Test data adapted from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	assertionMissingAuthenticatorData = `{
		"id":    "AAhH7cnPRBkcukjnc2G2GM1H5dkVs9P1q2VErhD57pkzKVjBbixdsufjXhUOfiD27D0VA-fPKUVYNGE2XYcjhihtYODQv-xEarplsa7Ix6hK13FA6uyRxMgHC3PhTbx-rbq_RMUbaJ-HoGVt-c820ifdoagkFR02Van8Vr9q67Bn6zHNDT_DNrQbtpIUqqX_Rg2p5o6F7bVO3uOJG9hUNgUb",
		"rawId": "AAhH7cnPRBkcukjnc2G2GM1H5dkVs9P1q2VErhD57pkzKVjBbixdsufjXhUOfiD27D0VA-fPKUVYNGE2XYcjhihtYODQv-xEarplsa7Ix6hK13FA6uyRxMgHC3PhTbx-rbq_RMUbaJ-HoGVt-c820ifdoagkFR02Van8Vr9q67Bn6zHNDT_DNrQbtpIUqqX_Rg2p5o6F7bVO3uOJG9hUNgUb",
		"response": {
			"clientDataJSON": "eyJjaGFsbGVuZ2UiOiJlYVR5VU5ueVBERGRLOFNORWdURVV2ejFROGR5bGtqalRpbVlkNVg3UUFvLUY4X1oxbHNKaTNCaWxVcEZaSGtJQ05EV1k4cjlpdm5UZ1c3LVhaQzNxUSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
			"signature":      "MEYCIQD6dF3B0ZoaLA0r78oyRdoMNR0bN93Zi4cF_75hFAH6pQIhALY0UIsrh03u_f4yKOwzwD6Cj3_GWLJiioTT9580s1a7",
			"userHandle":     ""
		},
		"type": "public-key"
	}`

	// Test data adapted from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	assertionMissingSignature = `{
		"id":    "AAhH7cnPRBkcukjnc2G2GM1H5dkVs9P1q2VErhD57pkzKVjBbixdsufjXhUOfiD27D0VA-fPKUVYNGE2XYcjhihtYODQv-xEarplsa7Ix6hK13FA6uyRxMgHC3PhTbx-rbq_RMUbaJ-HoGVt-c820ifdoagkFR02Van8Vr9q67Bn6zHNDT_DNrQbtpIUqqX_Rg2p5o6F7bVO3uOJG9hUNgUb",
		"rawId": "AAhH7cnPRBkcukjnc2G2GM1H5dkVs9P1q2VErhD57pkzKVjBbixdsufjXhUOfiD27D0VA-fPKUVYNGE2XYcjhihtYODQv-xEarplsa7Ix6hK13FA6uyRxMgHC3PhTbx-rbq_RMUbaJ-HoGVt-c820ifdoagkFR02Van8Vr9q67Bn6zHNDT_DNrQbtpIUqqX_Rg2p5o6F7bVO3uOJG9hUNgUb",
		"response": {
			"clientDataJSON":    "eyJjaGFsbGVuZ2UiOiJlYVR5VU5ueVBERGRLOFNORWdURVV2ejFROGR5bGtqalRpbVlkNVg3UUFvLUY4X1oxbHNKaTNCaWxVcEZaSGtJQ05EV1k4cjlpdm5UZ1c3LVhaQzNxUSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
			"authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAABaw",
			"userHandle":        ""
		},
		"type": "public-key"
	}`

	// Test data adapted from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	assertionMissingType = `{
		"id":    "AAhH7cnPRBkcukjnc2G2GM1H5dkVs9P1q2VErhD57pkzKVjBbixdsufjXhUOfiD27D0VA-fPKUVYNGE2XYcjhihtYODQv-xEarplsa7Ix6hK13FA6uyRxMgHC3PhTbx-rbq_RMUbaJ-HoGVt-c820ifdoagkFR02Van8Vr9q67Bn6zHNDT_DNrQbtpIUqqX_Rg2p5o6F7bVO3uOJG9hUNgUb",
		"rawId": "AAhH7cnPRBkcukjnc2G2GM1H5dkVs9P1q2VErhD57pkzKVjBbixdsufjXhUOfiD27D0VA-fPKUVYNGE2XYcjhihtYODQv-xEarplsa7Ix6hK13FA6uyRxMgHC3PhTbx-rbq_RMUbaJ-HoGVt-c820ifdoagkFR02Van8Vr9q67Bn6zHNDT_DNrQbtpIUqqX_Rg2p5o6F7bVO3uOJG9hUNgUb",
		"response": {
			"clientDataJSON":    "eyJjaGFsbGVuZ2UiOiJlYVR5VU5ueVBERGRLOFNORWdURVV2ejFROGR5bGtqalRpbVlkNVg3UUFvLUY4X1oxbHNKaTNCaWxVcEZaSGtJQ05EV1k4cjlpdm5UZ1c3LVhaQzNxUSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
			"authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAABaw",
			"signature":         "MEYCIQD6dF3B0ZoaLA0r78oyRdoMNR0bN93Zi4cF_75hFAH6pQIhALY0UIsrh03u_f4yKOwzwD6Cj3_GWLJiioTT9580s1a7",
			"userHandle":        ""
		}
	}`

	// Test data adapted from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	assertionInvalidID = `{
		"id": ":?",
		"response": {
			"clientDataJSON":    "eyJjaGFsbGVuZ2UiOiJlYVR5VU5ueVBERGRLOFNORWdURVV2ejFROGR5bGtqalRpbVlkNVg3UUFvLUY4X1oxbHNKaTNCaWxVcEZaSGtJQ05EV1k4cjlpdm5UZ1c3LVhaQzNxUSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
			"authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAABaw",
			"signature":         "MEYCIQD6dF3B0ZoaLA0r78oyRdoMNR0bN93Zi4cF_75hFAH6pQIhALY0UIsrh03u_f4yKOwzwD6Cj3_GWLJiioTT9580s1a7",
			"userHandle":        ""
		},
		"type": "public-key"
	}`

	// Test data adapted from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	assertionDecodedIDEmpty = `{
		"id": "\n",
		"response": {
			"clientDataJSON":    "eyJjaGFsbGVuZ2UiOiJlYVR5VU5ueVBERGRLOFNORWdURVV2ejFROGR5bGtqalRpbVlkNVg3UUFvLUY4X1oxbHNKaTNCaWxVcEZaSGtJQ05EV1k4cjlpdm5UZ1c3LVhaQzNxUSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
			"authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAABaw",
			"signature":         "MEYCIQD6dF3B0ZoaLA0r78oyRdoMNR0bN93Zi4cF_75hFAH6pQIhALY0UIsrh03u_f4yKOwzwD6Cj3_GWLJiioTT9580s1a7",
			"userHandle":        ""
		},
		"type": "public-key"
	}`

	// Test data adapted from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	assertionInvalidRawID = `{
		"rawId": ":?",
		"response": {
			"clientDataJSON":    "eyJjaGFsbGVuZ2UiOiJlYVR5VU5ueVBERGRLOFNORWdURVV2ejFROGR5bGtqalRpbVlkNVg3UUFvLUY4X1oxbHNKaTNCaWxVcEZaSGtJQ05EV1k4cjlpdm5UZ1c3LVhaQzNxUSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
			"authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAABaw",
			"signature":         "MEYCIQD6dF3B0ZoaLA0r78oyRdoMNR0bN93Zi4cF_75hFAH6pQIhALY0UIsrh03u_f4yKOwzwD6Cj3_GWLJiioTT9580s1a7",
			"userHandle":        ""
		},
		"type": "public-key"
	}`

	// Test data adapted from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	assertionDecodedRawIDEmpty = `{
		"rawId": "=0",
		"response": {
			"clientDataJSON":    "eyJjaGFsbGVuZ2UiOiJlYVR5VU5ueVBERGRLOFNORWdURVV2ejFROGR5bGtqalRpbVlkNVg3UUFvLUY4X1oxbHNKaTNCaWxVcEZaSGtJQ05EV1k4cjlpdm5UZ1c3LVhaQzNxUSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
			"authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAABaw",
			"signature":         "MEYCIQD6dF3B0ZoaLA0r78oyRdoMNR0bN93Zi4cF_75hFAH6pQIhALY0UIsrh03u_f4yKOwzwD6Cj3_GWLJiioTT9580s1a7",
			"userHandle":        ""
		},
		"type": "public-key"
	}`

	// Test data adapted from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	assertionInvalidClientData = `{
		"id":    "AAhH7cnPRBkcukjnc2G2GM1H5dkVs9P1q2VErhD57pkzKVjBbixdsufjXhUOfiD27D0VA-fPKUVYNGE2XYcjhihtYODQv-xEarplsa7Ix6hK13FA6uyRxMgHC3PhTbx-rbq_RMUbaJ-HoGVt-c820ifdoagkFR02Van8Vr9q67Bn6zHNDT_DNrQbtpIUqqX_Rg2p5o6F7bVO3uOJG9hUNgUb",
		"rawId": "AAhH7cnPRBkcukjnc2G2GM1H5dkVs9P1q2VErhD57pkzKVjBbixdsufjXhUOfiD27D0VA-fPKUVYNGE2XYcjhihtYODQv-xEarplsa7Ix6hK13FA6uyRxMgHC3PhTbx-rbq_RMUbaJ-HoGVt-c820ifdoagkFR02Van8Vr9q67Bn6zHNDT_DNrQbtpIUqqX_Rg2p5o6F7bVO3uOJG9hUNgUb",
		"response": {
			"clientDataJSON":    ":?",
			"authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAABaw",
			"signature":         "MEYCIQD6dF3B0ZoaLA0r78oyRdoMNR0bN93Zi4cF_75hFAH6pQIhALY0UIsrh03u_f4yKOwzwD6Cj3_GWLJiioTT9580s1a7",
			"userHandle":        ""
		},
		"type": "public-key"
	}`

	// Test data adapted from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	assertionInvalidAuthenticatorData = `{
		"id":    "AAhH7cnPRBkcukjnc2G2GM1H5dkVs9P1q2VErhD57pkzKVjBbixdsufjXhUOfiD27D0VA-fPKUVYNGE2XYcjhihtYODQv-xEarplsa7Ix6hK13FA6uyRxMgHC3PhTbx-rbq_RMUbaJ-HoGVt-c820ifdoagkFR02Van8Vr9q67Bn6zHNDT_DNrQbtpIUqqX_Rg2p5o6F7bVO3uOJG9hUNgUb",
		"rawId": "AAhH7cnPRBkcukjnc2G2GM1H5dkVs9P1q2VErhD57pkzKVjBbixdsufjXhUOfiD27D0VA-fPKUVYNGE2XYcjhihtYODQv-xEarplsa7Ix6hK13FA6uyRxMgHC3PhTbx-rbq_RMUbaJ-HoGVt-c820ifdoagkFR02Van8Vr9q67Bn6zHNDT_DNrQbtpIUqqX_Rg2p5o6F7bVO3uOJG9hUNgUb",
		"response": {
			"clientDataJSON":    "eyJjaGFsbGVuZ2UiOiJlYVR5VU5ueVBERGRLOFNORWdURVV2ejFROGR5bGtqalRpbVlkNVg3UUFvLUY4X1oxbHNKaTNCaWxVcEZaSGtJQ05EV1k4cjlpdm5UZ1c3LVhaQzNxUSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
			"authenticatorData": ":?",
			"signature":         "MEYCIQD6dF3B0ZoaLA0r78oyRdoMNR0bN93Zi4cF_75hFAH6pQIhALY0UIsrh03u_f4yKOwzwD6Cj3_GWLJiioTT9580s1a7",
			"userHandle":        ""
		},
		"type": "public-key"
	}`

	// Test data adapted from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	assertionInvalidSignature = `{
		"id":    "AAhH7cnPRBkcukjnc2G2GM1H5dkVs9P1q2VErhD57pkzKVjBbixdsufjXhUOfiD27D0VA-fPKUVYNGE2XYcjhihtYODQv-xEarplsa7Ix6hK13FA6uyRxMgHC3PhTbx-rbq_RMUbaJ-HoGVt-c820ifdoagkFR02Van8Vr9q67Bn6zHNDT_DNrQbtpIUqqX_Rg2p5o6F7bVO3uOJG9hUNgUb",
		"rawId": "AAhH7cnPRBkcukjnc2G2GM1H5dkVs9P1q2VErhD57pkzKVjBbixdsufjXhUOfiD27D0VA-fPKUVYNGE2XYcjhihtYODQv-xEarplsa7Ix6hK13FA6uyRxMgHC3PhTbx-rbq_RMUbaJ-HoGVt-c820ifdoagkFR02Van8Vr9q67Bn6zHNDT_DNrQbtpIUqqX_Rg2p5o6F7bVO3uOJG9hUNgUb",
		"response": {
			"clientDataJSON":    "eyJjaGFsbGVuZ2UiOiJlYVR5VU5ueVBERGRLOFNORWdURVV2ejFROGR5bGtqalRpbVlkNVg3UUFvLUY4X1oxbHNKaTNCaWxVcEZaSGtJQ05EV1k4cjlpdm5UZ1c3LVhaQzNxUSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
			"authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAABaw",
			"signature":         ":?",
			"userHandle":        ""
		},
		"type": "public-key"
	}`

	// Test data adapted from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	assertionInvalidUserHandle = `{
		"id":    "AAhH7cnPRBkcukjnc2G2GM1H5dkVs9P1q2VErhD57pkzKVjBbixdsufjXhUOfiD27D0VA-fPKUVYNGE2XYcjhihtYODQv-xEarplsa7Ix6hK13FA6uyRxMgHC3PhTbx-rbq_RMUbaJ-HoGVt-c820ifdoagkFR02Van8Vr9q67Bn6zHNDT_DNrQbtpIUqqX_Rg2p5o6F7bVO3uOJG9hUNgUb",
		"rawId": "AAhH7cnPRBkcukjnc2G2GM1H5dkVs9P1q2VErhD57pkzKVjBbixdsufjXhUOfiD27D0VA-fPKUVYNGE2XYcjhihtYODQv-xEarplsa7Ix6hK13FA6uyRxMgHC3PhTbx-rbq_RMUbaJ-HoGVt-c820ifdoagkFR02Van8Vr9q67Bn6zHNDT_DNrQbtpIUqqX_Rg2p5o6F7bVO3uOJG9hUNgUb",
		"response": {
			"clientDataJSON":    "eyJjaGFsbGVuZ2UiOiJlYVR5VU5ueVBERGRLOFNORWdURVV2ejFROGR5bGtqalRpbVlkNVg3UUFvLUY4X1oxbHNKaTNCaWxVcEZaSGtJQ05EV1k4cjlpdm5UZ1c3LVhaQzNxUSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
			"authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAABaw",
			"signature":         "MEYCIQD6dF3B0ZoaLA0r78oyRdoMNR0bN93Zi4cF_75hFAH6pQIhALY0UIsrh03u_f4yKOwzwD6Cj3_GWLJiioTT9580s1a7",
			"userHandle":        ":?"
		},
		"type": "public-key"
	}`

	// Test data adapted from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	assertionBadClientDataJSON = `{
		"rawId": "AAhH7cnPRBkcukjnc2G2GM1H5dkVs9P1q2VErhD57pkzKVjBbixdsufjXhUOfiD27D0VA-fPKUVYNGE2XYcjhihtYODQv-xEarplsa7Ix6hK13FA6uyRxMgHC3PhTbx-rbq_RMUbaJ-HoGVt-c820ifdoagkFR02Van8Vr9q67Bn6zHNDT_DNrQbtpIUqqX_Rg2p5o6F7bVO3uOJG9hUNgUb",
		"response": {
			"clientDataJSON":    "aGVsbG8=",
			"authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAABaw",
			"signature":         "MEYCIQD6dF3B0ZoaLA0r78oyRdoMNR0bN93Zi4cF_75hFAH6pQIhALY0UIsrh03u_f4yKOwzwD6Cj3_GWLJiioTT9580s1a7",
			"userHandle":        ""
		},
		"type": "public-key"
	}`

	// Test data adapted from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	assertionBadAuthenticatorData = `{
		"rawId": "AAhH7cnPRBkcukjnc2G2GM1H5dkVs9P1q2VErhD57pkzKVjBbixdsufjXhUOfiD27D0VA-fPKUVYNGE2XYcjhihtYODQv-xEarplsa7Ix6hK13FA6uyRxMgHC3PhTbx-rbq_RMUbaJ-HoGVt-c820ifdoagkFR02Van8Vr9q67Bn6zHNDT_DNrQbtpIUqqX_Rg2p5o6F7bVO3uOJG9hUNgUb",
		"response": {
			"clientDataJSON":    "eyJjaGFsbGVuZ2UiOiJlYVR5VU5ueVBERGRLOFNORWdURVV2ejFROGR5bGtqalRpbVlkNVg3UUFvLUY4X1oxbHNKaTNCaWxVcEZaSGtJQ05EV1k4cjlpdm5UZ1c3LVhaQzNxUSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
			"authenticatorData": "aGVsbG8=",
			"signature":         "MEYCIQD6dF3B0ZoaLA0r78oyRdoMNR0bN93Zi4cF_75hFAH6pQIhALY0UIsrh03u_f4yKOwzwD6Cj3_GWLJiioTT9580s1a7",
			"userHandle":        ""
		},
		"type": "public-key"
	}`

	// Test data adapted from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	assertionBadType = `{
		"id":    "AAhH7cnPRBkcukjnc2G2GM1H5dkVs9P1q2VErhD57pkzKVjBbixdsufjXhUOfiD27D0VA-fPKUVYNGE2XYcjhihtYODQv-xEarplsa7Ix6hK13FA6uyRxMgHC3PhTbx-rbq_RMUbaJ-HoGVt-c820ifdoagkFR02Van8Vr9q67Bn6zHNDT_DNrQbtpIUqqX_Rg2p5o6F7bVO3uOJG9hUNgUb",
		"rawId": "AAhH7cnPRBkcukjnc2G2GM1H5dkVs9P1q2VErhD57pkzKVjBbixdsufjXhUOfiD27D0VA-fPKUVYNGE2XYcjhihtYODQv-xEarplsa7Ix6hK13FA6uyRxMgHC3PhTbx-rbq_RMUbaJ-HoGVt-c820ifdoagkFR02Van8Vr9q67Bn6zHNDT_DNrQbtpIUqqX_Rg2p5o6F7bVO3uOJG9hUNgUb",
		"response": {
			"clientDataJSON":    "eyJjaGFsbGVuZ2UiOiJlYVR5VU5ueVBERGRLOFNORWdURVV2ejFROGR5bGtqalRpbVlkNVg3UUFvLUY4X1oxbHNKaTNCaWxVcEZaSGtJQ05EV1k4cjlpdm5UZ1c3LVhaQzNxUSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
			"authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAABaw",
			"signature":         "MEYCIQD6dF3B0ZoaLA0r78oyRdoMNR0bN93Zi4cF_75hFAH6pQIhALY0UIsrh03u_f4yKOwzwD6Cj3_GWLJiioTT9580s1a7",
			"userHandle":        ""
		},
		"type": "key"
	}`
)

type parseAssertionTest struct {
	name                     string
	assertion                []byte
	wantCredentialID         string
	wantCredentialRawID      []byte
	wantRawClientDataJSON    []byte
	wantRawAuthenticatorData []byte
	wantSignature            []byte
	wantUserHandle           []byte
	wantClientDataOrigin     string
	wantClientDataType       string
	wantClientDataChallenge  string
	wantTokenBindingStatus   string
	wantTokenBindingID       string
	wantRPIDHash             []byte
	wantUserPresent          bool
	wantUserVerified         bool
	wantCounter              uint32
	wantExtension            map[string]interface{}
}

type parseAssertionErrorTest struct {
	name         string
	assertion    []byte
	wantErrorMsg string
}

var parseAssertionTests = []parseAssertionTest{
	{
		name:                    "assertion without user handle",
		assertion:               []byte(assertion1),
		wantCredentialID:        assertion1Id,
		wantCredentialRawID:     base64Decode(assertion1Id),
		wantSignature:           base64Decode(assertion1Sig),
		wantUserHandle:          []byte{},
		wantClientDataOrigin:    "https://localhost:8443",
		wantClientDataType:      "webauthn.get",
		wantClientDataChallenge: assertion1Challenge,
		wantTokenBindingStatus:  "",
		wantTokenBindingID:      "",
		wantRPIDHash:            assertion1RPIDHash,
		wantUserPresent:         true,
		wantUserVerified:        false,
		wantCounter:             uint32(363),
		wantExtension:           nil,
	},
	{
		name:                    "assertion with user handle",
		assertion:               []byte(assertion2),
		wantCredentialID:        assertion2Id,
		wantCredentialRawID:     base64Decode(assertion2Id),
		wantSignature:           base64Decode(assertion2Sig),
		wantUserHandle:          base64Decode("YWs"),
		wantClientDataOrigin:    "https://webauthn.org",
		wantClientDataType:      "webauthn.get",
		wantClientDataChallenge: assertion2Challenge,
		wantTokenBindingStatus:  string(TokenBindingSupported),
		wantTokenBindingID:      "",
		wantRPIDHash:            assertion2RPIDHash,
		wantUserPresent:         true,
		wantUserVerified:        true,
		wantCounter:             uint32(1),
		wantExtension:           nil,
	},
}

var parseAssertionErrorTests = []parseAssertionErrorTest{
	{"missing ID and raw ID", []byte(assertionMissingIDAndRawID), "assertion: missing credential id and raw id"},
	{"missing client data", []byte(assertionMissingClientData), "assertion: missing client data"},
	{"missing authenticator data", []byte(assertionMissingAuthenticatorData), "assertion: missing authenticator data"},
	{"missing signature", []byte(assertionMissingSignature), "assertion: missing signature"},
	{"missing type", []byte(assertionMissingType), "assertion: missing type"},
	{"id is not base64 encoded", []byte(assertionInvalidID), "assertion: failed to base64 decode credential id"},
	{"base64 decoded id is empty", []byte(assertionDecodedIDEmpty), "assertion: base64 decoded credential id is empty"},
	{"raw id is not base64 encoded", []byte(assertionInvalidRawID), "assertion: failed to base64 decode credential raw id"},
	{"base64 decoded raw id is empty", []byte(assertionDecodedRawIDEmpty), "assertion: base64 decoded credential raw id is empty"},
	{"client data is not base64 encoded", []byte(assertionInvalidClientData), "assertion: failed to base64 decode client data"},
	{"authenticator data is not base64 encoded", []byte(assertionInvalidAuthenticatorData), "assertion: failed to base64 decode authenticator data"},
	{"signature is not base64 encoded", []byte(assertionInvalidSignature), "assertion: failed to base64 decode signature"},
	{"user handle is not base64 encoded", []byte(assertionInvalidUserHandle), "assertion: failed to base64 decode user handle"},
	{"client data is not well-formed JSON", []byte(assertionBadClientDataJSON), "client_data: failed to unmarshal: invalid character"},
	{"authenticator data is not well-formed", []byte(assertionBadAuthenticatorData), "authenticator_data: failed to unmarshal: unexpected EOF"},
	{"bad type", []byte(assertionBadType), "assertion: expected type as \"public-key\", got \"key\""},
}

func TestParseAssertion(t *testing.T) {
	for _, tc := range parseAssertionTests {
		t.Run(tc.name, func(t *testing.T) {
			var credentialAssertion PublicKeyCredentialAssertion
			if err := json.Unmarshal(tc.assertion, &credentialAssertion); err != nil {
				t.Fatalf("failed to unmarshal assertion %s: %q", string(tc.assertion), err)
			}

			// verify credential id and raw id
			if credentialAssertion.ID != tc.wantCredentialID {
				t.Errorf("credential id %s, want %s", credentialAssertion.ID, tc.wantCredentialID)
			}
			if !bytes.Equal(credentialAssertion.RawID, tc.wantCredentialRawID) {
				t.Errorf("credential raw id %v, want %v", credentialAssertion.RawID, tc.wantCredentialRawID)
			}
			if !bytes.Equal(credentialAssertion.Signature, tc.wantSignature) {
				t.Errorf("signature %v, want %v", credentialAssertion.Signature, tc.wantSignature)
			}
			if !bytes.Equal(credentialAssertion.UserHandle, tc.wantUserHandle) {
				t.Errorf("user handle %v, want %v", credentialAssertion.UserHandle, tc.wantUserHandle)
			}

			// verify client data
			if credentialAssertion.ClientData.Origin != tc.wantClientDataOrigin {
				t.Errorf("client data origin %s, want %s", credentialAssertion.ClientData.Origin, tc.wantClientDataOrigin)
			}
			if credentialAssertion.ClientData.Type != tc.wantClientDataType {
				t.Errorf("client data type %s, want %s", credentialAssertion.ClientData.Type, tc.wantClientDataType)
			}
			if credentialAssertion.ClientData.Challenge != tc.wantClientDataChallenge {
				t.Errorf("client data challenge %s, want %s", credentialAssertion.ClientData.Challenge, tc.wantClientDataChallenge)
			}
			if credentialAssertion.ClientData.TokenBinding == nil {
				if len(tc.wantTokenBindingStatus) != 0 {
					t.Errorf("client data has no token binding, want token binding status %s", tc.wantTokenBindingStatus)
				}
				if len(tc.wantTokenBindingID) != 0 {
					t.Errorf("client data has no token binding, want token binding id %s", tc.wantTokenBindingID)
				}
			} else {
				if string(credentialAssertion.ClientData.TokenBinding.Status) != tc.wantTokenBindingStatus {
					t.Errorf("client data token binding status %s, want %s", credentialAssertion.ClientData.TokenBinding.Status, tc.wantTokenBindingStatus)
				}
				if credentialAssertion.ClientData.TokenBinding.ID != tc.wantTokenBindingID {
					t.Errorf("client data token binding id %s, want %s", credentialAssertion.ClientData.TokenBinding.ID, tc.wantTokenBindingID)
				}
			}

			// verify authenticator data
			if !bytes.Equal(credentialAssertion.AuthnData.RPIDHash, tc.wantRPIDHash) {
				t.Errorf("rp id hash %0x, want %0x", credentialAssertion.AuthnData.RPIDHash, tc.wantRPIDHash)
			}
			if credentialAssertion.AuthnData.UserPresent != tc.wantUserPresent {
				t.Errorf("user present %t, want %t", credentialAssertion.AuthnData.UserPresent, tc.wantUserPresent)
			}
			if credentialAssertion.AuthnData.UserVerified != tc.wantUserVerified {
				t.Errorf("user verified %t, want %t", credentialAssertion.AuthnData.UserVerified, tc.wantUserVerified)
			}
			if credentialAssertion.AuthnData.Counter != tc.wantCounter {
				t.Errorf("counter %d, want %d", credentialAssertion.AuthnData.Counter, tc.wantCounter)
			}
			if !reflect.DeepEqual(credentialAssertion.AuthnData.Extensions, tc.wantExtension) {
				t.Errorf("extensions %v, want %v", credentialAssertion.AuthnData.Extensions, tc.wantExtension)
			}

			// verify attested credential data
			if credentialAssertion.AuthnData.AAGUID != nil {
				t.Errorf("AAGUID %0x, want nil", credentialAssertion.AuthnData.AAGUID)
			}
			if credentialAssertion.AuthnData.CredentialID != nil {
				t.Errorf("authenticator credential id %0x, want nil", credentialAssertion.AuthnData.CredentialID)
			}
			if credentialAssertion.AuthnData.Credential != nil {
				t.Errorf("credential %+v, want nil", credentialAssertion.AuthnData.Credential)
			}
		})
	}
}

func TestParseAssertionError(t *testing.T) {
	for _, tc := range parseAssertionErrorTests {
		t.Run(tc.name, func(t *testing.T) {
			var credentialAssertion PublicKeyCredentialAssertion
			if err := json.Unmarshal(tc.assertion, &credentialAssertion); err == nil {
				t.Errorf("unmarshal assertion %s returns no error, want error containing substring %q", string(tc.assertion), tc.wantErrorMsg)
			} else if !strings.Contains(err.Error(), tc.wantErrorMsg) {
				t.Errorf("unmarshal assertion %s returns error %q, want error containing substring %q", string(tc.assertion), err, tc.wantErrorMsg)
			}
		})
	}
}
