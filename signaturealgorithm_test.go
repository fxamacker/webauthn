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
	"crypto"
	"crypto/x509"
	"testing"
)

func TestSignatureAlgorithm(t *testing.T) {
	testCases := []struct {
		coseAlg       int
		wantSigAlg    x509.SignatureAlgorithm
		wantPubKeyAlg x509.PublicKeyAlgorithm
		wantHash      crypto.Hash
		wantIsRSA     bool
		wantIsRSAPSS  bool
		wantIsECDSA   bool
	}{
		{COSEAlgES256, x509.ECDSAWithSHA256, x509.ECDSA, crypto.SHA256, false, false, true},
		{COSEAlgES384, x509.ECDSAWithSHA384, x509.ECDSA, crypto.SHA384, false, false, true},
		{COSEAlgES512, x509.ECDSAWithSHA512, x509.ECDSA, crypto.SHA512, false, false, true},
		{COSEAlgPS256, x509.SHA256WithRSAPSS, x509.RSA, crypto.SHA256, true, true, false},
		{COSEAlgPS384, x509.SHA384WithRSAPSS, x509.RSA, crypto.SHA384, true, true, false},
		{COSEAlgPS512, x509.SHA512WithRSAPSS, x509.RSA, crypto.SHA512, true, true, false},
		{COSEAlgRS1, x509.SHA1WithRSA, x509.RSA, crypto.SHA1, true, false, false},
		{COSEAlgRS256, x509.SHA256WithRSA, x509.RSA, crypto.SHA256, true, false, false},
		{COSEAlgRS384, x509.SHA384WithRSA, x509.RSA, crypto.SHA384, true, false, false},
		{COSEAlgRS512, x509.SHA512WithRSA, x509.RSA, crypto.SHA512, true, false, false},
	}

	for _, tc := range testCases {
		if sigAlg, err := CoseAlgToSignatureAlgorithm(tc.coseAlg); err != nil {
			t.Errorf("SignatureAlgorithm(%d) returns error %q", tc.coseAlg, err)
		} else {
			if sigAlg.Algorithm != tc.wantSigAlg {
				t.Errorf("SignatureAlgorithm(%d).Algorithm = %s, want %s", tc.coseAlg, sigAlg.Algorithm, tc.wantSigAlg)
			}
			if sigAlg.PublicKeyAlgorithm != tc.wantPubKeyAlg {
				t.Errorf("SignatureAlgorithm(%d).PublicKeyAlgorithm = %s, want %s", tc.coseAlg, sigAlg.PublicKeyAlgorithm, tc.wantPubKeyAlg)
			}
			if sigAlg.Hash != tc.wantHash {
				t.Errorf("SignatureAlgorithm(%d).Hash = %v, want %v", tc.coseAlg, sigAlg.Hash, tc.wantHash)
			}
			if sigAlg.IsRSA() != tc.wantIsRSA {
				t.Errorf("SignatureAlgorithm(%d).IsRSA() = %t , want %t", tc.coseAlg, sigAlg.IsRSA(), tc.wantIsRSA)
			}
			if sigAlg.IsRSAPSS() != tc.wantIsRSAPSS {
				t.Errorf("SignatureAlgorithm(%d).IsRSAPSS() = %t, want %t", tc.coseAlg, sigAlg.IsRSAPSS(), tc.wantIsRSAPSS)
			}
			if sigAlg.IsECDSA() != tc.wantIsECDSA {
				t.Errorf("SignatureAlgorithm(%d).IsECDSA() = %t, want %t", tc.coseAlg, sigAlg.IsECDSA(), tc.wantIsECDSA)
			}
			if !signatureAlgorithmRegistered(tc.coseAlg) {
				t.Errorf("COSEAlgorithmAvailable(%d) returns false, want true", tc.coseAlg)
			}
		}
	}
}

/*
func TestRegisterAndUnregisterSignatureAlgorithm(t *testing.T) {
	coseAlgRS1 := -65535 // RSASSA-PKCS1-v1_5 with SHA-1

	RegisterSignatureAlgorithm(coseAlgRS1, x509.SHA1WithRSA, x509.RSA, crypto.SHA1)

	if sigAlg, err := CoseAlgToSignatureAlgorithm(coseAlgRS1); err != nil {
		t.Errorf("SignatureAlgorithm(%d) returns error %q", coseAlgRS1, err)
	} else {
		if sigAlg.Algorithm != x509.SHA1WithRSA {
			t.Errorf("SignatureAlgorithm(%d).Algorithm = %s, want %s", coseAlgRS1, sigAlg.Algorithm, x509.SHA1WithRSA)
		}
		if sigAlg.PublicKeyAlgorithm != x509.RSA {
			t.Errorf("SignatureAlgorithm(%d).PublicKeyAlgorithm = %s, want %s", coseAlgRS1, sigAlg.PublicKeyAlgorithm, x509.RSA)
		}
		if sigAlg.Hash != crypto.SHA1 {
			t.Errorf("SignatureAlgorithm(%d).Hash = %v, want %v", coseAlgRS1, sigAlg.Hash, crypto.SHA1)
		}
		if !sigAlg.IsRSA() {
			t.Errorf("SignatureAlgorithm(%d).IsRSA() = false, want true", coseAlgRS1)
		}
		if sigAlg.IsRSAPSS() {
			t.Errorf("SignatureAlgorithm(%d).IsRSAPSS() = true, want false", coseAlgRS1)
		}
		if sigAlg.IsECDSA() {
			t.Errorf("SignatureAlgorithm(%d).IsECDSA() = true, want false", coseAlgRS1)
		}
	}

	if !signatureAlgorithmRegistered(coseAlgRS1) {
		t.Errorf("COSEAlgorithmAvailable(%d) returns false, want true", coseAlgRS1)
	}

	UnregisterSignatureAlgorithm(coseAlgRS1)

	if _, err := CoseAlgToSignatureAlgorithm(coseAlgRS1); err == nil {
		t.Errorf("SignatureAlgorithm(%d) returns no error, want error containing substring \"unsupported COSE algorithm\"", coseAlgRS1)
	}

	if signatureAlgorithmRegistered(coseAlgRS1) {
		t.Errorf("COSEAlgorithmAvailable(%d) returns true, want false", coseAlgRS1)
	}
}

func TestUnregisteredSignatureAlgorithm(t *testing.T) {
	coseAlgRS1 := -65535 // RSASSA-PKCS1-v1_5 with SHA-1

	if _, err := CoseAlgToSignatureAlgorithm(coseAlgRS1); err == nil {
		t.Errorf("SignatureAlgorithm(%d) returns no error, want error containing substring \"unsupported COSE algorithm\"", coseAlgRS1)
	} else if !strings.Contains(err.Error(), "COSE algorithm -65535 is not registered") {
		t.Errorf("SignatureAlgorithm(%d) returns error %q, want error containing substring \"unsupported COSE algorithm\"", coseAlgRS1, err)
	}

	if signatureAlgorithmRegistered(coseAlgRS1) {
		t.Errorf("COSEAlgorithmAvailable(%d) returns true, want false", coseAlgRS1)
	}
}
*/
