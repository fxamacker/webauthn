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

package packed

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/fxamacker/webauthn"
)

var oidPackedCertificateExt = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}

type packedAttestationStatement struct {
	webauthn.SignatureAlgorithm                     // Algorithm used to generate the attestation signature.
	sig                         []byte              // Signature.
	attestnCert                 *x509.Certificate   // Attestation certificate.
	caCerts                     []*x509.Certificate // Attestation certificate chain.
	ecdaaKeyID                  []byte              // The identifier of the ECDAA-Issuer public key.
}

func parseAttestation(data []byte) (webauthn.AttestationStatement, error) {
	type rawAttStmt struct {
		Alg        int      `cbor:"alg"` // A COSEAlgorithmIdentifier containing the identifier of the algorithm used to generate the attestation signature.
		Sig        []byte   `cbor:"sig"`
		X5C        [][]byte `cbor:"x5c"`
		ECDAAKeyID []byte   `cbor:"ecdaaKeyId"` // The identifier of the ECDAA-Issuer public key.
	}

	var raw rawAttStmt
	var err error
	if err = cbor.Unmarshal(data, &raw); err != nil {
		return nil, &webauthn.UnmarshalSyntaxError{Type: "packed attestation", Msg: err.Error()}
	}

	if raw.Alg == 0 {
		return nil, &webauthn.UnmarshalMissingFieldError{Type: "packed attestation", Field: "alg"}
	}
	if len(raw.Sig) == 0 {
		return nil, &webauthn.UnmarshalMissingFieldError{Type: "packed attestation", Field: "sig"}
	}
	if len(raw.X5C) > 0 && len(raw.ECDAAKeyID) > 0 {
		return nil, &webauthn.UnmarshalBadDataError{Type: "packed attestation", Msg: "packed attestation can not have both x5c and ecdaaKeyId fields"}
	}

	attStmt := &packedAttestationStatement{sig: raw.Sig}

	if attStmt.SignatureAlgorithm, err = webauthn.CoseAlgToSignatureAlgorithm(raw.Alg); err != nil {
		return nil, err
	}

	for i := 0; i < len(raw.X5C); i++ {
		c, err := x509.ParseCertificate(raw.X5C[i])
		if err != nil {
			return nil, &webauthn.UnmarshalSyntaxError{Type: "packed attestation", Field: fmt.Sprintf("x5c[%d]", i), Msg: err.Error()}
		}
		if i == 0 {
			attStmt.attestnCert = c
		} else {
			attStmt.caCerts = append(attStmt.caCerts, c)
		}
	}

	if len(raw.ECDAAKeyID) > 0 {
		attStmt.ecdaaKeyID = raw.ECDAAKeyID
		return nil, &webauthn.UnsupportedFeatureError{Feature: "Elliptic Curve based Direct Anonymous Attestation (ECDAA)"}
	}

	return attStmt, nil
}

// Verify implements the webauthn.AttestationStatement interface.  It follows
// fido-u2f attestation statement verification procedure defined in
// http://w3c.github.io/webauthn/#sctn-packed-attestation
func (attStmt *packedAttestationStatement) Verify(clientDataHash []byte, authnData *webauthn.AuthenticatorData) (attType webauthn.AttestationType, trustPath interface{}, err error) {
	rawAuthnData := authnData.Raw
	signed := make([]byte, len(rawAuthnData)+len(clientDataHash))
	copy(signed, rawAuthnData)
	copy(signed[len(rawAuthnData):], clientDataHash)

	if attStmt.attestnCert != nil {
		// Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash
		// using attestation public key in attestnCert with the algorithm specified in alg.
		if err = attStmt.attestnCert.CheckSignature(attStmt.Algorithm, signed, attStmt.sig); err != nil {
			err = &webauthn.VerificationError{Type: "packed attestation", Field: "signature", Msg: err.Error()}
			return
		}

		// Verify leaf certificate by building certificate chain.
		if trustPath, err = verifyAttestationCert(attStmt.attestnCert, attStmt.caCerts); err != nil {
			err = &webauthn.VerificationError{Type: "packed attestation", Field: "certificate", Msg: err.Error()}
			return
		}

		// todo: check for revocation

		// Verify that attestnCert meets requirements.
		if err = verifyPackedAttestationStatementCert(attStmt.attestnCert); err != nil {
			err = &webauthn.VerificationError{Type: "packed attestation", Field: "certificate requirement", Msg: err.Error()}
			return
		}

		// If attestnCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid)
		// verify that value of the this extension matches aaguid in authenticatorData.
		if err = matchAAGUIDWithCertificateExtensionIfExists(attStmt.attestnCert, authnData.AAGUID); err != nil {
			err = &webauthn.VerificationError{Type: "packed attestation", Field: "certificate extension " + oidPackedCertificateExt.String(), Msg: err.Error()}
			return
		}

		// Optionally, inspect x5c and consult externally provided knowledge to determine whether
		// attStmt conveys a Basic or AttCA attestation.

		// If successful, return implementation-specific values representing attestation type Basic,
		// AttCA or uncertainty, and attestation trust path x5c.
		return webauthn.AttestationTypeBasic, trustPath, nil
	} else if len(attStmt.ecdaaKeyID) > 0 {
		return webauthn.AttestationTypeECDAA, attStmt.ecdaaKeyID, &webauthn.UnsupportedFeatureError{Feature: "Elliptic Curve based Direct Anonymous Attestation (ECDAA)"}
	} else {
		// Validate that alg matches the algorithm of credentialPublicKey in authenticatorData.
		if attStmt.Algorithm != authnData.Credential.Algorithm {
			err = &webauthn.VerificationError{Type: "packed attestation", Field: "alg", Msg: "self attestation algorithm does not match credential algorithm"}
			return
		}

		// Verify that sig is a valid signature over the concatenation of authenticatorData and
		// clientDataHash using the credential public key with alg.
		if err = authnData.Credential.Verify(signed, attStmt.sig); err != nil {
			err = &webauthn.VerificationError{Type: "packed attestation", Field: "signature", Msg: err.Error()}
			return
		}

		// If successful, return implementation-specific values representing attestation type Self
		// and an empty attestation trust path.
		return webauthn.AttestationTypeSelf, nil, nil
	}
}

func verifyAttestationCert(attestnCert *x509.Certificate, caCerts []*x509.Certificate) (trustPath []*x509.Certificate, err error) {
	var verifyOptions x509.VerifyOptions

	if len(caCerts) > 0 {
		lastCert := caCerts[len(caCerts)-1]
		if bytes.Equal(lastCert.RawIssuer, lastCert.RawSubject) && lastCert.IsCA {
			caCerts = caCerts[:len(caCerts)-1]

			verifyOptions.Roots = x509.NewCertPool()
			verifyOptions.Roots.AddCert(lastCert)
		}
		if len(caCerts) > 0 {
			verifyOptions.Intermediates = x509.NewCertPool()
			for _, c := range caCerts {
				verifyOptions.Intermediates.AddCert(c)
			}
		}
	} else if len(caCerts) == 0 {
		if bytes.Equal(attestnCert.RawIssuer, attestnCert.RawSubject) {
			verifyOptions.Roots = x509.NewCertPool()
			verifyOptions.Roots.AddCert(attestnCert)
		}
	}

	var chains [][]*x509.Certificate
	chains, err = attestnCert.Verify(verifyOptions)
	if err != nil {
		return nil, err
	}
	return chains[0], nil
}

func verifyPackedAttestationStatementCert(c *x509.Certificate) error {
	// Version MUST be set to 3 (which is indicated by an ASN.1 INTEGER with value 2).
	if c.Version != 3 {
		return fmt.Errorf("expected certificate version 3, got version %d", c.Version)
	}

	// Subject field MUST be set to:
	// - Subject-C: ISO 3166 code specifying the country where the Authenticator vendor is incorporated
	// - Subject-O: Legal name of the Authenticator vendor (UTF8String)
	// - Subject-OU: Literal string “Authenticator Attestation” (UTF8String)
	// - Subject-CN: A UTF8String of the vendor’s choosing
	subject := c.Subject
	if c := subject.Country; len(c) == 0 || len(c[0]) != 2 {
		return errors.New("certificate \"country name\" must be set to two character ISO 3166 code")
	}
	if o := subject.Organization; len(o) == 0 {
		return errors.New("certificate missing \"organization name\"")
	}
	if ou := subject.OrganizationalUnit; len(ou) == 0 || ou[0] != "Authenticator Attestation" {
		return errors.New("certificate \"organization unit name\" must be \"Authenticator Attestation\"")
	}
	if cn := subject.CommonName; len(cn) == 0 {
		return errors.New("certificate missing \"common name\"")
	}

	// The Basic Constraints extension MUST have the CA component set to false.
	if c.IsCA {
		return errors.New("certificate's basic constraints extension does not have the CA component set to false")
	}

	// todo: An Authority Information Access (AIA) extension with entry id-ad-ocsp and a CRL
	// Distribution Point extension [RFC5280] are both OPTIONAL as the status of many attestation
	// certificates is available through authenticator metadata service.

	return nil
}

func matchAAGUIDWithCertificateExtensionIfExists(c *x509.Certificate, aaguid []byte) error {
	for _, ext := range c.Extensions {
		if ext.Id.Equal(oidPackedCertificateExt) {
			if ext.Critical {
				return errors.New("certificate extension must not be marked as critical")
			}
			var rawValue asn1.RawValue
			if rest, err := asn1.Unmarshal(ext.Value, &rawValue); err != nil {
				return errors.New("failed to unmarshal certificate extension: " + err.Error())
			} else if len(rest) != 0 {
				return errors.New("trailing data after certificate extension")
			}
			if !bytes.Equal(rawValue.Bytes, aaguid) {
				return errors.New("aaguid does not match certificate extension")
			}
			return nil
		}
	}
	return nil
}

func init() {
	webauthn.RegisterAttestationFormat("packed", parseAttestation)
}
