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

	"github.com/fxamacker/cbor/v2"
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

// ParseCredential parses credential public key encoded in COSE_Key format.
func ParseCredential(coseKeyData []byte) (c *Credential, rest []byte, err error) {
	type rawCredential struct {
		Kty    int             `cbor:"1,keyasint"`
		Alg    int             `cbor:"3,keyasint"`
		CrvOrN cbor.RawMessage `cbor:"-1,keyasint"`
		XOrE   cbor.RawMessage `cbor:"-2,keyasint"`
		Y      cbor.RawMessage `cbor:"-3,keyasint"`
	}
	var raw rawCredential
	decoder := cbor.NewDecoder(bytes.NewReader(coseKeyData))
	if err = decoder.Decode(&raw); err != nil {
		return nil, nil, &UnmarshalSyntaxError{Type: "credential", Msg: err.Error()}
	}
	rest = coseKeyData[decoder.NumBytesRead():]

	signatureAlgorithm, err := CoseAlgToSignatureAlgorithm(raw.Alg)
	if err != nil {
		return nil, nil, err
	}

	if coseKeyType(raw.Kty).isRSA() {
		if !signatureAlgorithm.IsRSA() {
			return nil, nil, &UnmarshalBadDataError{Type: "credential", Msg: "COSE key type " + strconv.Itoa(raw.Kty) + " and algorithm " + strconv.Itoa(raw.Alg) + " are mismatched"}
		}
		if raw.CrvOrN == nil {
			return nil, nil, &UnmarshalMissingFieldError{Type: "credential", Field: "RSA n"}
		}
		if raw.XOrE == nil {
			return nil, nil, &UnmarshalMissingFieldError{Type: "credential", Field: "RSA e"}
		}
		var nb []byte
		if err := cbor.Unmarshal(raw.CrvOrN, &nb); err != nil {
			return nil, nil, &UnmarshalBadDataError{Type: "credential", Msg: "invalid RSA n"}
		}
		var eb []byte
		if err := cbor.Unmarshal(raw.XOrE, &eb); err != nil {
			return nil, nil, &UnmarshalBadDataError{Type: "credential", Msg: "invalid RSA e"}
		}
		n := new(big.Int).SetBytes(nb)
		e := new(big.Int).SetBytes(eb)
		return &Credential{coseKeyData, signatureAlgorithm, &rsa.PublicKey{N: n, E: int(e.Int64())}}, rest, nil
	}

	if coseKeyType(raw.Kty).isEllipticCurve() {
		if !signatureAlgorithm.IsECDSA() {
			return nil, nil, &UnmarshalBadDataError{Type: "credential", Msg: "COSE key type " + strconv.Itoa(raw.Kty) + " and algorithm " + strconv.Itoa(raw.Alg) + " are mismatched"}
		}
		if raw.CrvOrN == nil {
			return nil, nil, &UnmarshalMissingFieldError{Type: "credential", Field: "ECDSA curve"}
		}
		if raw.XOrE == nil {
			return nil, nil, &UnmarshalMissingFieldError{Type: "credential", Field: "ECDSA x"}
		}
		if raw.Y == nil {
			return nil, nil, &UnmarshalMissingFieldError{Type: "credential", Field: "ECDSA y"}
		}
		var crvID int
		if err := cbor.Unmarshal(raw.CrvOrN, &crvID); err != nil {
			return nil, nil, &UnmarshalBadDataError{Type: "credential", Msg: "invalid ECDSA curve"}
		}
		curve := coseEllipticCurve(crvID).curve()
		if curve == nil {
			return nil, nil, &UnsupportedFeatureError{Feature: "credential COSE curve " + strconv.Itoa(crvID)}
		}
		var xb []byte
		if err := cbor.Unmarshal(raw.XOrE, &xb); err != nil {
			return nil, nil, &UnmarshalBadDataError{Type: "credential", Msg: "invalid ECDSA x"}
		}
		var yb []byte
		if err := cbor.Unmarshal(raw.Y, &yb); err != nil {
			return nil, nil, &UnmarshalBadDataError{Type: "credential", Msg: "invalid ECDSA y"}
		}
		x := new(big.Int).SetBytes(xb)
		y := new(big.Int).SetBytes(yb)
		return &Credential{coseKeyData, signatureAlgorithm, &ecdsa.PublicKey{Curve: curve, X: x, Y: y}}, rest, nil
	}

	return nil, nil, &UnsupportedFeatureError{Feature: "credential of COSE key type " + strconv.Itoa(raw.Kty) + " and algorithm " + strconv.Itoa(raw.Alg)}
}
