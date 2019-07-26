// Copyright (c) 2019 Faye Amacker. All rights reserved.
// Use of this source code is governed by Apache License 2.0 found in the LICENSE file.

package webauthn

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strconv"

	"github.com/fxamacker/cbor"
)

// Credential represents credential algorithm and public key used to verify assertion signatures.
type Credential struct {
	Raw []byte
	SignatureAlgorithm
	crypto.PublicKey
}

// MarshalPKIXPublicKeyPEM serializes public key to PEM-encoded PKIX format.
func (c *Credential) MarshalPKIXPublicKeyPEM() ([]byte, error) {
	publicKeyPKIX, err := x509.MarshalPKIXPublicKey(c.PublicKey)
	if err != nil {
		return nil, err
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyPKIX,
	})
	return publicKeyPEM, nil
}

// Verify verifies the signature of hashed message using credential algorithm and public key.
func (c *Credential) Verify(message []byte, signature []byte) error {
	h := c.Hash.New()
	h.Write(message)
	digest := h.Sum(nil)

	switch pk := c.PublicKey.(type) {
	case *rsa.PublicKey:
		if c.IsRSAPSS() {
			return rsa.VerifyPSS(pk, c.Hash, digest, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
		}
		return rsa.VerifyPKCS1v15(pk, c.Hash, digest, signature)
	case *ecdsa.PublicKey:
		type ecdsaSignature struct {
			R, S *big.Int
		}
		var ecdsaSig ecdsaSignature
		if rest, err := asn1.Unmarshal(signature, &ecdsaSig); err != nil {
			return err
		} else if len(rest) != 0 {
			return errors.New("trailing data after ECDSA signature")
		}
		if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
			return errors.New("ECDSA signature contained zero or negative values")
		}
		if !ecdsa.Verify(pk, digest, ecdsaSig.R, ecdsaSig.S) {
			return errors.New("ECDSA signature verification failed")
		}
		return nil
	default:
		return &UnsupportedFeatureError{Feature: fmt.Sprintf("credential public key of type %T", c.PublicKey)}
	}
}

type coseKeyType int

const (
	coseKeyTypeEllipticCurve coseKeyType = 2
	coseKeyTypeRSA           coseKeyType = 3
)

func (kty coseKeyType) isRSA() bool {
	return kty == coseKeyTypeRSA
}

func (kty coseKeyType) isEllipticCurve() bool {
	return kty == coseKeyTypeEllipticCurve
}

type coseEllipticCurve int

const (
	coseCurveP256 coseEllipticCurve = 1 // P-256
	coseCurveP384 coseEllipticCurve = 2 // P-384
	coseCurveP512 coseEllipticCurve = 3 // P-512
)

func (crv coseEllipticCurve) curve() elliptic.Curve {
	switch crv {
	case coseCurveP256:
		return elliptic.P256()
	case coseCurveP384:
		return elliptic.P384()
	case coseCurveP512:
		return elliptic.P521()
	default:
		return nil
	}
}

const (
	labelKty = 1
	labelAlg = 3
	labelCrv = -1
	labelX   = -2
	labelY   = -3
	labelN   = -1
	labelE   = -2
)

// ParseCredential parses credential public key encoded in COSE_Key format.
func ParseCredential(coseKeyData []byte) (c *Credential, rest []byte, err error) {
	m := make(map[int]interface{})

	decoder := cbor.NewDecoder(bytes.NewReader(coseKeyData))
	if err = decoder.Decode(&m); err != nil {
		return nil, nil, &UnmarshalSyntaxError{Type: "credential", Msg: err.Error()}
	}

	rest = coseKeyData[decoder.NumBytesRead():]

	// Key type identification.
	ktyIntf, ok := m[labelKty]
	if !ok {
		return nil, nil, &UnmarshalMissingFieldError{Type: "credential", Field: "key type"}
	}
	var kty int
	switch v := ktyIntf.(type) {
	case uint64:
		kty = int(v)
	case int64:
		kty = int(v)
	default:
		return nil, nil, &UnmarshalBadDataError{Type: "credential", Msg: "invalid key type"}
	}

	// Key usage restriction.
	algIntf, ok := m[labelAlg]
	if !ok {
		return nil, nil, &UnmarshalMissingFieldError{Type: "credential", Field: "algorithm"}
	}
	var alg int
	switch v := algIntf.(type) {
	case uint64:
		alg = int(v)
	case int64:
		alg = int(v)
	default:
		return nil, nil, &UnmarshalBadDataError{Type: "credential", Msg: "invalid algorithm"}
	}

	signatureAlgorithm, err := CoseAlgToSignatureAlgorithm(alg)
	if err != nil {
		return nil, nil, err
	}

	if len(m) == 4 {
		if !signatureAlgorithm.IsRSA() || !coseKeyType(kty).isRSA() {
			return nil, nil, &UnmarshalBadDataError{Type: "credential", Msg: "COSE key type " + strconv.Itoa(kty) + " and algorithm " + strconv.Itoa(alg) + " are mismatched"}
		}
		pubKey, err := parseRSAPublicKey(m)
		if err != nil {
			return nil, nil, err
		}
		return &Credential{coseKeyData, signatureAlgorithm, pubKey}, rest, nil
	} else if len(m) == 5 {
		if !signatureAlgorithm.IsECDSA() || !coseKeyType(kty).isEllipticCurve() {
			return nil, nil, &UnmarshalBadDataError{Type: "credential", Msg: "COSE key type " + strconv.Itoa(kty) + " and algorithm " + strconv.Itoa(alg) + " are mismatched"}
		}
		pubKey, err := parseECDSAPublicKey(m)
		if err != nil {
			return nil, nil, err
		}
		return &Credential{coseKeyData, signatureAlgorithm, pubKey}, rest, nil
	} else {
		return nil, nil, &UnsupportedFeatureError{Feature: "credential of COSE key type " + strconv.Itoa(kty) + " and algorithm " + strconv.Itoa(alg)}
	}
}

func parseECDSAPublicKey(m map[int]interface{}) (crypto.PublicKey, error) {
	crvIntf, ok := m[labelCrv]
	if !ok {
		return nil, &UnmarshalMissingFieldError{Type: "credential", Field: "ECDSA curve"}
	}
	var crvID int
	switch v := crvIntf.(type) {
	case uint64:
		crvID = int(v)
	case int64:
		crvID = int(v)
	default:
		return nil, &UnmarshalBadDataError{Type: "credential", Msg: "invalid ECDSA curve"}
	}

	curve := coseEllipticCurve(crvID).curve()
	if curve == nil {
		return nil, &UnsupportedFeatureError{Feature: "credential COSE curve " + strconv.Itoa(crvID)}
	}

	xIntf, ok := m[labelX]
	if !ok {
		return nil, &UnmarshalMissingFieldError{Type: "credential", Field: "ECDSA x"}
	}
	rawX, ok := xIntf.([]byte)
	if !ok {
		return nil, &UnmarshalBadDataError{Type: "credential", Msg: "invalid ECDSA x"}
	}

	yIntf, ok := m[labelY]
	if !ok {
		return nil, &UnmarshalMissingFieldError{Type: "credential", Field: "ECDSA y"}
	}
	rawY, ok := yIntf.([]byte)
	if !ok {
		return nil, &UnmarshalBadDataError{Type: "credential", Msg: "invalid ECDSA y"}
	}

	x := new(big.Int).SetBytes(rawX)
	y := new(big.Int).SetBytes(rawY)
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func parseRSAPublicKey(m map[int]interface{}) (crypto.PublicKey, error) {
	nIntf, ok := m[labelN]
	if !ok {
		return nil, &UnmarshalMissingFieldError{Type: "credential", Field: "RSA n"}
	}
	rawN, ok := nIntf.([]byte)
	if !ok {
		return nil, &UnmarshalBadDataError{Type: "credential", Msg: "invalid RSA n"}
	}

	eIntf, ok := m[labelE]
	if !ok {
		return nil, &UnmarshalMissingFieldError{Type: "credential", Field: "RSA e"}
	}
	rawE, ok := eIntf.([]byte)
	if !ok {
		return nil, &UnmarshalBadDataError{Type: "credential", Msg: "invalid RSA e"}
	}

	n := new(big.Int).SetBytes(rawN)
	e := new(big.Int).SetBytes(rawE)
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}
