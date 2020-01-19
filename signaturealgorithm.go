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
	"strconv"
	"sync"
	"sync/atomic"
)

// Supported COSE algorithm identifier registered in the IANA COSE Algorithm registry.
const (
	COSEAlgES256 = -7     // ECDSA with SHA-256
	COSEAlgES384 = -35    // ECDSA with SHA-384
	COSEAlgES512 = -36    // ECDSA with SHA-512
	COSEAlgPS256 = -37    // RSASSA-PSS with SHA-256
	COSEAlgPS384 = -38    // RSASSA-PSS with SHA-384
	COSEAlgPS512 = -39    // RSASSA-PSS with SHA-512
	COSEAlgRS1   = -65535 // RSASSA-PKCS1-v1_5 with SHA-1
	COSEAlgRS256 = -257   // RSASSA-PKCS1-v1_5 with SHA-256
	COSEAlgRS384 = -258   // RSASSA-PKCS1-v1_5 with SHA-384
	COSEAlgRS512 = -259   // RSASSA-PKCS1-v1_5 with SHA-512
)

// SignatureAlgorithm represents signature algorithm, and its corresponding public key algorithm,
// hash function, and COSE algorithm identifier.
type SignatureAlgorithm struct {
	Algorithm          x509.SignatureAlgorithm
	PublicKeyAlgorithm x509.PublicKeyAlgorithm
	Hash               crypto.Hash
	COSEAlgorithm      int
}

// IsRSA returns if signature algorithm uses RSA public key.
func (alg SignatureAlgorithm) IsRSA() bool {
	return alg.PublicKeyAlgorithm == x509.RSA
}

// IsRSAPSS returns if signature algorithm uses RSAPSS public key.
func (alg SignatureAlgorithm) IsRSAPSS() bool {
	switch alg.Algorithm {
	case x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
		return true
	default:
		return false
	}
}

// IsECDSA returns if signature algorithm uses ECDSA public key.
func (alg SignatureAlgorithm) IsECDSA() bool {
	return alg.PublicKeyAlgorithm == x509.ECDSA
}

// CoseAlgToSignatureAlgorithm returns signature algorithm of given COSE algorithm identifier.
func CoseAlgToSignatureAlgorithm(coseAlg int) (SignatureAlgorithm, error) {
	algs, _ := atomicCOSEAlgorithms.Load().([]SignatureAlgorithm)
	for _, alg := range algs {
		if alg.COSEAlgorithm == coseAlg {
			return alg, nil
		}
	}
	return SignatureAlgorithm{}, &UnregisteredFeatureError{Feature: "COSE algorithm " + strconv.Itoa(coseAlg)}
}

var (
	coseAlgorithmsMu     sync.Mutex
	atomicCOSEAlgorithms atomic.Value
)

// RegisterSignatureAlgorithm registers the given COSE algorithm identifier with corresponding
// signature algorithm, public key algorithm, and hash function.
func RegisterSignatureAlgorithm(coseAlg int, sigAlg x509.SignatureAlgorithm, pkAlg x509.PublicKeyAlgorithm, hash crypto.Hash) {
	registered := false
	coseAlgorithmsMu.Lock()
	algs, _ := atomicCOSEAlgorithms.Load().([]SignatureAlgorithm)
	for i := 0; i < len(algs); i++ {
		if algs[i].COSEAlgorithm == coseAlg {
			algs[i] = SignatureAlgorithm{sigAlg, pkAlg, hash, coseAlg}
			registered = true
			break
		}
	}
	if registered {
		atomicCOSEAlgorithms.Store(algs)
	} else {
		atomicCOSEAlgorithms.Store(append(algs, SignatureAlgorithm{sigAlg, pkAlg, hash, coseAlg}))
	}
	coseAlgorithmsMu.Unlock()
}

// UnregisterSignatureAlgorithm unregisters the given COSE algorithm.
func UnregisterSignatureAlgorithm(coseAlg int) {
	coseAlgorithmsMu.Lock()
	algs, _ := atomicCOSEAlgorithms.Load().([]SignatureAlgorithm)
	for i := 0; i < len(algs); i++ {
		if algs[i].COSEAlgorithm == coseAlg {
			atomicCOSEAlgorithms.Store(append(algs[:i], algs[i+1:]...))
			break
		}
	}
	coseAlgorithmsMu.Unlock()
}

// signatureAlgorithmRegistered returns if the given COSE algorithm is registered.
func signatureAlgorithmRegistered(coseAlg int) bool {
	algs, _ := atomicCOSEAlgorithms.Load().([]SignatureAlgorithm)
	for _, alg := range algs {
		if alg.COSEAlgorithm == coseAlg {
			return true
		}
	}
	return false
}

func init() {
	RegisterSignatureAlgorithm(COSEAlgES256, x509.ECDSAWithSHA256, x509.ECDSA, crypto.SHA256)
	RegisterSignatureAlgorithm(COSEAlgES384, x509.ECDSAWithSHA384, x509.ECDSA, crypto.SHA384)
	RegisterSignatureAlgorithm(COSEAlgES512, x509.ECDSAWithSHA512, x509.ECDSA, crypto.SHA512)
	RegisterSignatureAlgorithm(COSEAlgPS256, x509.SHA256WithRSAPSS, x509.RSA, crypto.SHA256)
	RegisterSignatureAlgorithm(COSEAlgPS384, x509.SHA384WithRSAPSS, x509.RSA, crypto.SHA384)
	RegisterSignatureAlgorithm(COSEAlgPS512, x509.SHA512WithRSAPSS, x509.RSA, crypto.SHA512)
	RegisterSignatureAlgorithm(COSEAlgRS1, x509.SHA1WithRSA, x509.RSA, crypto.SHA1)
	RegisterSignatureAlgorithm(COSEAlgRS256, x509.SHA256WithRSA, x509.RSA, crypto.SHA256)
	RegisterSignatureAlgorithm(COSEAlgRS384, x509.SHA384WithRSA, x509.RSA, crypto.SHA384)
	RegisterSignatureAlgorithm(COSEAlgRS512, x509.SHA512WithRSA, x509.RSA, crypto.SHA512)
}
