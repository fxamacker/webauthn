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
	"strings"
	"testing"
)

type configTest struct {
	name string
	cfg  *Config
}

type configErrorTest struct {
	name         string
	cfg          *Config
	wantErrorMsg string
}

var configTests = []configTest{
	{
		name: "config 1",
		cfg: &Config{
			RPID:                    "acme.com",
			RPName:                  "ACME Corporation",
			RPIcon:                  "https://acme.com/avatar.png",
			Timeout:                 uint64(30000),
			ChallengeLength:         64,
			AuthenticatorAttachment: AuthenticatorPlatform,
			ResidentKey:             ResidentKeyPreferred,
			UserVerification:        UserVerificationPreferred,
			Attestation:             AttestationNone,
			CredentialAlgs:          []int{COSEAlgES256, COSEAlgPS256, COSEAlgRS256},
		},
	},
}

var configErrorTests = []configErrorTest{
	{
		name: "invalid timeout",
		cfg: &Config{
			RPID:                    "acme.com",
			RPName:                  "ACME Corporation",
			RPIcon:                  "https://acme.com/avatar.png",
			Timeout:                 uint64(0),
			ChallengeLength:         64,
			AuthenticatorAttachment: AuthenticatorPlatform,
			ResidentKey:             ResidentKeyPreferred,
			UserVerification:        UserVerificationPreferred,
			Attestation:             AttestationNone,
			CredentialAlgs:          []int{COSEAlgES512},
		},
		wantErrorMsg: "timeout must be a positive number",
	},
	{
		name: "empty rp name",
		cfg: &Config{
			RPID:                    "acme.com",
			RPName:                  "",
			RPIcon:                  "https://acme.com/avatar.png",
			Timeout:                 uint64(30000),
			ChallengeLength:         64,
			AuthenticatorAttachment: AuthenticatorPlatform,
			ResidentKey:             ResidentKeyPreferred,
			UserVerification:        UserVerificationPreferred,
			Attestation:             AttestationNone,
			CredentialAlgs:          []int{COSEAlgES512},
		},
		wantErrorMsg: "rp name is required",
	},
	{
		name: "invalid challenge length",
		cfg: &Config{
			RPID:                    "acme.com",
			RPName:                  "ACME Corporation",
			RPIcon:                  "https://acme.com/avatar.png",
			Timeout:                 uint64(30000),
			ChallengeLength:         8,
			AuthenticatorAttachment: AuthenticatorPlatform,
			ResidentKey:             ResidentKeyPreferred,
			UserVerification:        UserVerificationPreferred,
			Attestation:             AttestationNone,
			CredentialAlgs:          []int{COSEAlgES512},
		},
		wantErrorMsg: "challenge must be at least",
	},
	{
		name: "invalid authenticator attachment",
		cfg: &Config{
			RPID:                    "acme.com",
			RPName:                  "ACME Corporation",
			RPIcon:                  "https://acme.com/avatar.png",
			Timeout:                 uint64(30000),
			ChallengeLength:         64,
			AuthenticatorAttachment: "usb",
			ResidentKey:             ResidentKeyPreferred,
			UserVerification:        UserVerificationPreferred,
			Attestation:             AttestationNone,
			CredentialAlgs:          []int{COSEAlgES512},
		},
		wantErrorMsg: "authenticator attachment must be \"\", \"platform\", or \"cross-platform\"",
	},
	{
		name: "invalid user verification",
		cfg: &Config{
			RPID:                    "acme.com",
			RPName:                  "ACME Corporation",
			RPIcon:                  "https://acme.com/avatar.png",
			Timeout:                 uint64(30000),
			ChallengeLength:         64,
			AuthenticatorAttachment: AuthenticatorPlatform,
			ResidentKey:             ResidentKeyPreferred,
			UserVerification:        "must",
			Attestation:             AttestationNone,
			CredentialAlgs:          []int{COSEAlgES512},
		},
		wantErrorMsg: "user verification must be \"required\", \"preferred\", or \"discouraged\"",
	},
	{
		name: "invalid attestation preference",
		cfg: &Config{
			RPID:                    "acme.com",
			RPName:                  "ACME Corporation",
			RPIcon:                  "https://acme.com/avatar.png",
			Timeout:                 uint64(30000),
			ChallengeLength:         64,
			AuthenticatorAttachment: AuthenticatorPlatform,
			ResidentKey:             ResidentKeyPreferred,
			UserVerification:        UserVerificationPreferred,
			Attestation:             "no",
			CredentialAlgs:          []int{COSEAlgES512},
		},
		wantErrorMsg: "attestation must be \"none\", \"indirect\", or \"direct\"",
	},
	{
		name: "empty credential algorithm",
		cfg: &Config{
			RPID:                    "acme.com",
			RPName:                  "ACME Corporation",
			RPIcon:                  "https://acme.com/avatar.png",
			Timeout:                 uint64(30000),
			ChallengeLength:         64,
			AuthenticatorAttachment: AuthenticatorPlatform,
			ResidentKey:             ResidentKeyPreferred,
			UserVerification:        UserVerificationPreferred,
			Attestation:             AttestationNone,
			CredentialAlgs:          []int{},
		},
		wantErrorMsg: "there must be at least one credential algorithm",
	},
	{
		name: "invalid credential algorithm",
		cfg: &Config{
			RPID:                    "acme.com",
			RPName:                  "ACME Corporation",
			RPIcon:                  "https://acme.com/avatar.png",
			Timeout:                 uint64(30000),
			ChallengeLength:         64,
			AuthenticatorAttachment: AuthenticatorPlatform,
			ResidentKey:             ResidentKeyPreferred,
			UserVerification:        UserVerificationPreferred,
			Attestation:             AttestationNone,
			CredentialAlgs:          []int{-1},
		},
		wantErrorMsg: "credential algorithm -1 is not registered",
	},
}

func TestConfig(t *testing.T) {
	for _, tc := range configTests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.cfg.Valid(); err != nil {
				t.Errorf("(*Config).Valid() returns error %q", err)
			}
		})
	}
}

func TestConfigError(t *testing.T) {
	for _, tc := range configErrorTests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.cfg.Valid(); err == nil {
				t.Errorf("(*Config).Valid() returns no error,  want error containing substring %q", tc.wantErrorMsg)
			} else if !strings.Contains(err.Error(), tc.wantErrorMsg) {
				t.Errorf("(*Config).Valid() returns error %q,  want error containing substring %q", err, tc.wantErrorMsg)
			}
		})
	}
}
