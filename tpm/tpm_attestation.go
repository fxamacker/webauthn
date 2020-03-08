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

package tpm

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/fxamacker/cbor/v2"
	"github.com/fxamacker/webauthn"
)

var (
	oidExtensionSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidTcgKpAikCertificate     = asn1.ObjectIdentifier{2, 23, 133, 8, 3}
	oidTPMManufacturer         = asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	oidTPMModel                = asn1.ObjectIdentifier{2, 23, 133, 2, 2}
	oidTPMVersion              = asn1.ObjectIdentifier{2, 23, 133, 2, 3}
	oidTPMCertificateExt       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}
)

// tpmsAttest represents TPM structure TPMS_ATTEST, as specified in https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf section 10.12.8.
type tpmsAttest struct {
	magic                   uint32 // The indication that this structure was created by a TPM (always TPM_GENERATED_VALUE).
	typ                     string // Type of the attestation structure.
	qualifiedSignerHashType string // Hashing algorithm for qualified signer.
	qualifiedSigner         []byte // Digest of the qualified name of the signing key.
	extraData               []byte // External information supplied by caller.
	clockInfo               []byte // Clock, resetCount, restartCount, and Safe.
	firmwareVersion         []byte // TPM-vendor-specific value identifying the version number of the firmware.
	nameHashType            string // Hashing algorithm for name.
	name                    []byte // Digest of the name of the certified object.
	qualifiedNameHashType   string // Hashing algorithm for qualified name.
	qualifiedName           []byte // Digest of the qualified name of the certified object.
}

// tpmaObject represents TPM structure TPMA_OBJECT, as specified in https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf section 8.3.1.
type tpmaObject struct {
	fixedTPM             bool
	stClear              bool
	fixedParent          bool
	sensitiveDataOrigin  bool
	userWithAuth         bool
	adminWithPolicy      bool
	noDA                 bool
	encryptedDuplication bool
	restricted           bool
	decrypt              bool
	signOrEncrypt        bool
}

// tpmuPublicParms represents the union of TPM structures TPMS_RSA_PARMS and TPMS_ECC_PARMS, as specified in https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf section 12.2.3.5 and 12.2.3.6.
type tpmuPublicParms struct {
	symmetric string // TPMS_RSA_PARMS and TPMS_ECC_PARMS: symmetric algorithm used for decryption.  If the key is not a restricted decryption key, this field shall be set to TPM_ALG_NULL (0x0010).
	scheme    string // TPMS_RSA_PARMS and TPMS_ECC_PARMS: algorithm scheme, such as TPM_ALG_RSASSA (0x0014), TPM_ALG_RSAPSS (0x0016) for RSA and TPM_ALG_ECDSA (0x0018) for ECC.
	keyBits   uint16 // TPMS_RSA_PARMS: number of bits in the public modulus.
	exponent  uint32 // TPMS_RSA_PARMS: the public exponent.  When zero, indicates that the exponent is default of 2^16+1(65537)
	curveID   string // TPMS_ECC_PARMS: curve ID.
	kdf       string // TPMS_ECC_PARMS: optional key derivation scheme.  MUST be NULL.
}

// tpmtPublic represents TPM structure TPMT_PUBLIC, as specified in https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf section 12.2.4.
// Only support "TPM_ALG_RSA" and "TPM_ALG_ECC" algorithm.
type tpmtPublic struct {
	typ              string          // Algorithm associated with this object.
	nameAlg          string          // Algorithm used for computing the name of the object.
	objectAttributes tpmaObject      // Attributes that, along with type, determine the manipulations of this object.
	authPolicy       []byte          // Optional policy for using this key.
	parameters       tpmuPublicParms // Algorithm or strcuture details.
	rsaN             []byte          // RSA n coefficient, only for typ "TPM_ALG_RSA", stored in TPMT_PUBLIC structure unique field.
	eccX, eccY       []byte          // ECC x and y coordinates, only for typ "TPM_ALG_ECC", stored in TPMT_PUBLIC structure unique field.
}

type tpmAttestationStatement struct {
	ver                         string              // The version of TPM specification to which the signature conforms.
	webauthn.SignatureAlgorithm                     // The algorithm used to generate the attestation signature.
	aikCert                     *x509.Certificate   // AIK certificate used for the attestation.
	caCerts                     []*x509.Certificate // AIK certificate chain.
	ecdaaKeyID                  []byte              // The identifier of the ECDAA-Issuer public key.
	rawSig                      []byte              // Complete raw sig content.
	rawCerInfo                  []byte              // Complete raw certInfo content.
	rawPubArea                  []byte              // Complete raw pubArea content.
	certInfo                    *tpmsAttest         // The TPMS_ATTEST structure over which signature was computed, as specified in https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf section 10.12.8.
	pubArea                     *tpmtPublic         // The TPMT_PUBLIC structure used by the TPM to represent the credential public key, as specified in https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf section 12.2.4.
}

func parseAttestation(data []byte) (webauthn.AttestationStatement, error) {
	type rawAttStmt struct {
		Ver        string   `cbor:"ver"`        // The version of TPM specification to which the signature conforms.
		Alg        int      `cbor:"alg"`        // A COSEAlgorithmIdentifier containing the identifier of the algorithm used to generate the attestation signature.
		X5C        [][]byte `cbor:"x5c"`        // AIK certificate followed by its certificate chain, in X.509 encoding.
		ECDAAKeyID []byte   `cbor:"ecdaaKeyId"` // The identifier of the ECDAA-Issuer public key.
		Sig        []byte   `cbor:"sig"`        // The attestation signature, in the form of TPMT_SIGNATURE structure, as specified in https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf section 11.3.4.
		CertInfo   []byte   `cbor:"certInfo"`   // The TPMS_ATTEST structure over which signature was computed, as specified in https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf section 10.12.8.
		PubArea    []byte   `cbor:"pubArea"`    // The TPMT_PUBLIC structure used by the TPM to represent the credential public key, as specified in https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf section 12.2.4.
	}

	var raw rawAttStmt
	var err error
	if err = cbor.Unmarshal(data, &raw); err != nil {
		return nil, &webauthn.UnmarshalSyntaxError{Type: "TPM attestation", Msg: err.Error()}
	}

	if len(raw.X5C) > 0 && len(raw.ECDAAKeyID) > 0 {
		return nil, &webauthn.UnmarshalBadDataError{Type: "TPM attestation", Msg: "TPM attestation can not have both x5c and ecdaaKeyId fields"}
	}

	attStmt := &tpmAttestationStatement{
		ver:        raw.Ver,
		rawSig:     raw.Sig,
		rawCerInfo: raw.CertInfo,
		rawPubArea: raw.PubArea,
	}

	if attStmt.SignatureAlgorithm, err = webauthn.CoseAlgToSignatureAlgorithm(raw.Alg); err != nil {
		return nil, err
	}

	for i := 0; i < len(raw.X5C); i++ {
		c, err := x509.ParseCertificate(raw.X5C[i])
		if err != nil {
			return nil, &webauthn.UnmarshalSyntaxError{Type: "TPM attestation", Field: fmt.Sprintf("x5c[%d]", i), Msg: err.Error()}
		}
		if i == 0 {
			attStmt.aikCert = c
		} else {
			attStmt.caCerts = append(attStmt.caCerts, c)
		}
	}

	if len(raw.ECDAAKeyID) > 0 {
		attStmt.ecdaaKeyID = raw.ECDAAKeyID
		return nil, &webauthn.UnsupportedFeatureError{Feature: "Elliptic Curve based Direct Anonymous Attestation (ECDAA)"}
	}

	if attStmt.certInfo, err = parseTPMCertInfo(raw.CertInfo); err != nil {
		return nil, err
	}

	if attStmt.pubArea, err = parseTPMPubArea(raw.PubArea); err != nil {
		return nil, err
	}

	return attStmt, nil
}

func parseTPMCertInfo(data []byte) (certInfo *tpmsAttest, err error) {
	if len(data) < 6 {
		return nil, &webauthn.UnmarshalSyntaxError{Type: "TPM attestation", Field: "certInfo", Msg: "unexpected EOF"}
	}

	certInfo = &tpmsAttest{}

	certInfo.magic, data = binary.BigEndian.Uint32(data[:4]), data[4:]

	certInfo.typ, data = tpmStructureTags[int(binary.BigEndian.Uint16(data[:2]))], data[2:]

	if certInfo.qualifiedSignerHashType, certInfo.qualifiedSigner, data, err = getTPM2bName(data); err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, &webauthn.UnmarshalSyntaxError{Type: "TPM attestation", Field: "certInfo", Msg: "unexpected EOF"}
		}
		return nil, &webauthn.UnmarshalSyntaxError{Type: "TPM attestation", Field: "certInfo.qualifiedSigner", Msg: err.Error()}
	}

	if certInfo.extraData, data, err = getTPM2bData(data); err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, &webauthn.UnmarshalSyntaxError{Type: "TPM attestation", Field: "certInfo", Msg: "unexpected EOF"}
		}
		return nil, &webauthn.UnmarshalSyntaxError{Type: "TPM attestation", Field: "certInfo.extraData", Msg: err.Error()}
	}

	if len(data) < 17 {
		return nil, &webauthn.UnmarshalSyntaxError{Type: "TPM attestation", Field: "certInfo", Msg: "unexpected EOF"}
	}
	certInfo.clockInfo, data = data[:17], data[17:]

	if len(data) < 8 {
		return nil, &webauthn.UnmarshalSyntaxError{Type: "TPM attestation", Field: "certInfo", Msg: "unexpected EOF"}
	}
	certInfo.firmwareVersion, data = data[:8], data[8:]

	if certInfo.nameHashType, certInfo.name, data, err = getTPM2bName(data); err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, &webauthn.UnmarshalSyntaxError{Type: "TPM attestation", Field: "certInfo", Msg: "unexpected EOF"}
		}
		return nil, &webauthn.UnmarshalSyntaxError{Type: "TPM attestation", Field: "certInfo.name", Msg: err.Error()}
	}

	if certInfo.qualifiedNameHashType, certInfo.qualifiedName, data, err = getTPM2bName(data); err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, &webauthn.UnmarshalSyntaxError{Type: "TPM attestation", Field: "certInfo", Msg: "unexpected EOF"}
		}
		return nil, &webauthn.UnmarshalSyntaxError{Type: "TPM attestation", Field: "certInfo.qualifiedName", Msg: err.Error()}
	}

	if len(data) != 0 {
		return nil, &webauthn.UnmarshalBadDataError{Type: "TPM attestation", Msg: "trailing data after certInfo"}
	}

	return certInfo, nil
}

func parseTPMPubArea(data []byte) (pubArea *tpmtPublic, err error) {
	if len(data) < 8 {
		return nil, &webauthn.UnmarshalSyntaxError{Type: "TPM attestation", Field: "pubArea", Msg: "unexpected EOF"}
	}

	pubArea = &tpmtPublic{}

	pubArea.typ, data = tpmAlgorithms[int(binary.BigEndian.Uint16(data[:2]))], data[2:]

	pubArea.nameAlg, data = tpmAlgorithms[int(binary.BigEndian.Uint16(data[:2]))], data[2:]

	objectAttributesInt, data := binary.BigEndian.Uint32(data[:4]), data[4:]
	pubArea.objectAttributes.fixedTPM = (objectAttributesInt & (1 << 1)) != 0
	pubArea.objectAttributes.stClear = (objectAttributesInt & (1 << 2)) != 0
	pubArea.objectAttributes.fixedParent = (objectAttributesInt & (1 << 4)) != 0
	pubArea.objectAttributes.sensitiveDataOrigin = (objectAttributesInt & (1 << 5)) != 0
	pubArea.objectAttributes.userWithAuth = (objectAttributesInt & (1 << 6)) != 0
	pubArea.objectAttributes.adminWithPolicy = (objectAttributesInt & (1 << 7)) != 0
	pubArea.objectAttributes.noDA = (objectAttributesInt & (1 << 10)) != 0
	pubArea.objectAttributes.encryptedDuplication = (objectAttributesInt & (1 << 11)) != 0
	pubArea.objectAttributes.restricted = (objectAttributesInt & (1 << 16)) != 0
	pubArea.objectAttributes.decrypt = (objectAttributesInt & (1 << 17)) != 0
	pubArea.objectAttributes.signOrEncrypt = (objectAttributesInt & (1 << 18)) != 0

	if pubArea.authPolicy, data, err = getTPM2bData(data); err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, &webauthn.UnmarshalSyntaxError{Type: "TPM attestation", Field: "pubArea", Msg: "unexpected EOF"}
		}
		return nil, &webauthn.UnmarshalSyntaxError{Type: "TPM attestation", Field: "pubArea.authPolicy", Msg: err.Error()}
	}

	if pubArea.typ == "TPM_ALG_RSA" {
		if len(data) < 10 {
			return nil, &webauthn.UnmarshalSyntaxError{Type: "TPM attestation", Field: "pubArea", Msg: "unexpected EOF"}
		}
		pubArea.parameters.symmetric = tpmAlgorithms[int(binary.BigEndian.Uint16(data[:2]))]
		pubArea.parameters.scheme = tpmAlgorithms[int(binary.BigEndian.Uint16(data[2:4]))]
		pubArea.parameters.keyBits = binary.BigEndian.Uint16(data[4:6])
		pubArea.parameters.exponent = binary.BigEndian.Uint32(data[6:10])
		if pubArea.parameters.exponent == 0 {
			pubArea.parameters.exponent = 65537 // default exponent value
		}
		data = data[10:]

		if pubArea.rsaN, data, err = getTPM2bData(data); err != nil {
			if err == io.ErrUnexpectedEOF {
				return nil, &webauthn.UnmarshalSyntaxError{Type: "TPM attestation", Field: "pubArea", Msg: "unexpected EOF"}
			}
			return nil, &webauthn.UnmarshalSyntaxError{Type: "TPM attestation", Field: "pubArea.rsaN", Msg: err.Error()}
		}
	} else if pubArea.typ == "TPM_ALG_ECC" {
		if len(data) < 8 {
			return nil, &webauthn.UnmarshalSyntaxError{Type: "TPM attestation", Field: "pubArea", Msg: "unexpected EOF"}
		}
		pubArea.parameters.symmetric = tpmAlgorithms[int(binary.BigEndian.Uint16(data[:2]))]
		pubArea.parameters.scheme = tpmAlgorithms[int(binary.BigEndian.Uint16(data[2:4]))]
		pubArea.parameters.curveID = tpmECCCurve[int(binary.BigEndian.Uint16(data[4:6]))]
		pubArea.parameters.kdf = tpmAlgorithms[int(binary.BigEndian.Uint16(data[6:8]))]
		data = data[8:]

		if pubArea.eccX, data, err = getTPM2bData(data); err != nil {
			if err == io.ErrUnexpectedEOF {
				return nil, &webauthn.UnmarshalSyntaxError{Type: "TPM attestation", Field: "pubArea", Msg: "unexpected EOF"}
			}
			return nil, &webauthn.UnmarshalSyntaxError{Type: "TPM attestation", Field: "pubArea.eccX", Msg: err.Error()}
		}
		if pubArea.eccY, data, err = getTPM2bData(data); err != nil {
			if err == io.ErrUnexpectedEOF {
				return nil, &webauthn.UnmarshalSyntaxError{Type: "TPM attestation", Field: "pubArea", Msg: "unexpected EOF"}
			}
			return nil, &webauthn.UnmarshalSyntaxError{Type: "TPM attestation", Field: "pubArea.eccY", Msg: err.Error()}
		}
	} else {
		return nil, &webauthn.UnsupportedFeatureError{Feature: "TPM attestation public key type " + pubArea.typ}
	}

	if len(data) != 0 {
		return nil, &webauthn.UnmarshalBadDataError{Type: "TPM attestation", Msg: "trailing data after pubArea"}
	}

	return pubArea, nil
}

func getTPM2bData(data []byte) (element []byte, rest []byte, err error) {
	if len(data) < 2 {
		err = io.ErrUnexpectedEOF
		return
	}
	elementLen := int(binary.BigEndian.Uint16(data[:2]))

	if len(data) < 2+elementLen {
		err = io.ErrUnexpectedEOF
		return
	}
	element, rest = data[2:2+elementLen], data[2+elementLen:]
	return
}

func getTPM2bName(data []byte) (hashType string, name []byte, rest []byte, err error) {
	var element []byte
	if element, rest, err = getTPM2bData(data); err != nil {
		return
	}
	if len(element) < 2 {
		err = io.ErrUnexpectedEOF
		return
	}
	hashType = tpmAlgorithms[int(binary.BigEndian.Uint16(element[:2]))]
	name = element[2:]
	return
}

// Verify implements the webauthn.AttestationStatement interface.  It follows android-key attestation statement verification procedure defined in https://w3c.github.io/webauthn/ section 8.3, also refers to https://medium.com/@herrjemand/verifying-fido-tpm2-0-attestation-fc7243847498 for clarification.
func (attStmt *tpmAttestationStatement) Verify(clientDataHash []byte, authnData *webauthn.AuthenticatorData) (attType webauthn.AttestationType, trustPath interface{}, err error) {
	// Verify that the ver is set to "2.0".
	if attStmt.ver != "2.0" {
		err = &webauthn.VerificationError{Type: "TPM attestation", Field: "version", Msg: "expected version 2.0, got version " + attStmt.ver}
		return
	}

	// Verify that the public key specified by the parameters and unique fields of pubArea is idential to the credentialPublicKey in the attestedCredentialData in authenticatorData.
	if attStmt.pubArea.typ == "TPM_ALG_RSA" {
		credentialPubKey, ok := authnData.Credential.PublicKey.(*rsa.PublicKey)
		if !ok {
			err = &webauthn.VerificationError{Type: "TPM attestation", Field: "public key", Msg: "public key type specified in pubArea does not match credential public key type"}
			return
		}
		// Compare RSA public key n coefficient.
		if !bytes.Equal(attStmt.pubArea.rsaN, credentialPubKey.N.Bytes()) {
			err = &webauthn.VerificationError{Type: "TPM attestation", Field: "public key", Msg: "RSA public key n coefficient specified in pubArea does not match credential public key n coefficient"}
			return
		}
		// Compare RSA public key exponent.
		if attStmt.pubArea.parameters.exponent != uint32(credentialPubKey.E) {
			err = &webauthn.VerificationError{Type: "TPM attestation", Field: "public key", Msg: "RSA public key exponent specified in pubArea does not match credential public key exponent"}
			return
		}
	} else if attStmt.pubArea.typ == "TPM_ALG_ECC" {
		credentialPubKey, ok := authnData.Credential.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			err = &webauthn.VerificationError{Type: "TPM attestation", Field: "public key", Msg: "public key type specified in pubArea does not match credential public key type"}
			return
		}
		// Compare ECDSA public key curve.
		switch attStmt.pubArea.parameters.curveID {
		case "TPM_ECC_NIST_P224":
			if credentialPubKey.Curve.Params().BitSize != 224 {
				err = &webauthn.VerificationError{Type: "TPM attestation", Field: "public key", Msg: "ECC public key curve does not match credential public key curve"}
				return
			}
		case "TPM_ECC_NIST_P256":
			if credentialPubKey.Curve.Params().BitSize != 256 {
				err = &webauthn.VerificationError{Type: "TPM attestation", Field: "public key", Msg: "ECC public key curve does not match credential public key curve"}
				return
			}
		case "TPM_ECC_NIST_P384":
			if credentialPubKey.Curve.Params().BitSize != 384 {
				err = &webauthn.VerificationError{Type: "TPM attestation", Field: "public key", Msg: "ECC public key curve does not match credential public key curve"}
				return
			}
		case "TPM_ECC_NIST_P521":
			if credentialPubKey.Curve.Params().BitSize != 521 {
				err = &webauthn.VerificationError{Type: "TPM attestation", Field: "public key", Msg: "ECC public key curve does not match credential public key curve"}
				return
			}
		default:
			err = &webauthn.UnsupportedFeatureError{Feature: "TPM ECC public key curve " + attStmt.pubArea.parameters.curveID}
			return
		}
		// Compare ECDSA public key x and y coordinates.
		if !bytes.Equal(attStmt.pubArea.eccX, credentialPubKey.X.Bytes()) {
			err = &webauthn.VerificationError{Type: "TPM attestation", Field: "public key", Msg: "ECC public key x coordinate specified in pubArea does not match credential public key x coordinate"}
			return
		}
		if !bytes.Equal(attStmt.pubArea.eccY, credentialPubKey.Y.Bytes()) {
			err = &webauthn.VerificationError{Type: "TPM attestation", Field: "public key", Msg: "ECC public key y coordinate specified in pubArea does not match credential public key y coordinate"}
			return
		}
	} else {
		err = &webauthn.UnsupportedFeatureError{Feature: "TPM attestation public key type " + attStmt.pubArea.typ}
		return
	}

	// Validate that certInfo is valid:
	// - Verify that magic is set to TPM_GENERATED_VALUE.
	if attStmt.certInfo.magic != 0xff544347 { // TPM_GENERATED_VALUE
		err = &webauthn.VerificationError{Type: "TPM attestation", Field: "certInfo.magic", Msg: fmt.Sprintf("expected certInfo.magic %d, got %d", 0xff544347, attStmt.certInfo.magic)}
		return
	}

	// - Verify that type is set to TPM_ST_ATTEST_CERTIFY.
	if attStmt.certInfo.typ != "TPM_ST_ATTEST_CERTIFY" {
		err = &webauthn.VerificationError{Type: "TPM attestation", Field: "certInfo.typ", Msg: "expected certInfo.typ \"TPM_ST_ATTEST_CERTIFY\", got " + attStmt.certInfo.typ}
		return
	}

	// - Verify that extraData is set to the hash of concatenation of authenticatorData and clientDataHash using the hash algorithm employed in "alg".
	rawAuthnData := authnData.Raw
	attToBeSigned := make([]byte, len(rawAuthnData)+len(clientDataHash))
	copy(attToBeSigned, rawAuthnData)
	copy(attToBeSigned[len(rawAuthnData):], clientDataHash)

	h := attStmt.Hash.New()
	h.Write(attToBeSigned)
	authnClientDataHash := h.Sum(nil)
	if !bytes.Equal(authnClientDataHash, attStmt.certInfo.extraData) {
		err = &webauthn.VerificationError{Type: "TPM attestation", Field: "certInfo.extraData", Msg: "extraData doesn't match hash of authenticator data and client data hash"}
		return
	}

	// - Verify that attested contains a TPMS_CERTIFY_INFO structure as specified in [TPMv2-Part2] section 10.12.3, whose name field contains a valid Name for pubArea, as computed using the algorithm in the nameAlg field of pubArea using the procedure specified in [TPMv2-Part1] section 16.
	switch attStmt.pubArea.nameAlg {
	case "TPM_ALG_SHA256":
		h = crypto.SHA256.New()
	case "TPM_ALG_SHA384":
		h = crypto.SHA384.New()
	case "TPM_ALG_SHA512":
		h = crypto.SHA512.New()
	default:
		err = &webauthn.UnsupportedFeatureError{Feature: "TPM attestation public key nameAlg " + attStmt.pubArea.nameAlg}
		return
	}
	h.Write(attStmt.rawPubArea)
	computedPubAreaName := h.Sum(nil)
	if !bytes.Equal(computedPubAreaName, attStmt.certInfo.name) {
		err = &webauthn.VerificationError{Type: "TPM attestation", Field: "certInfo.name", Msg: "pubArea name does not match computed name"}
		return
	}

	// - Note that the remaining fields in the "Standard Attesation Structure" [TPMv2-Part2] section 31.2, i.e., qualifiedSigner, clockInfo and firmwareVersion are ignored.  These fields MAY be used as an input to risk engines.

	if attStmt.aikCert != nil {
		// Verify the sig is a valid signature over certInfo using the attestation public key in aikCert with the algorithm specified in alg.
		if err = attStmt.aikCert.CheckSignature(attStmt.Algorithm, attStmt.rawCerInfo, attStmt.rawSig); err != nil {
			err = &webauthn.VerificationError{Type: "TPM attestation", Field: "signature", Msg: err.Error()}
			return
		}

		// Verify that aikCert meets the certificate requirements https://w3c.github.io/webauthn/ section 8.3.1.
		if err = verifyTPMAttestationStatementCert(attStmt.aikCert); err != nil {
			err = &webauthn.VerificationError{Type: "TPM attestation", Field: "certificate requirement", Msg: err.Error()}
			return
		}

		// If aikCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) verify that value of the this extension matches the aaguid in authenticatorData.
		if err = matchAAGUIDWithCertificateExtensionIfExists(attStmt.aikCert, authnData.AAGUID); err != nil {
			err = &webauthn.VerificationError{Type: "TPM attestation", Field: "certificate extension " + oidTPMCertificateExt.String(), Msg: err.Error()}
			return
		}

		// Remove SubjectAltName extension from aikCert's UnhandledCriticalExtensions because certificate verification fails if there is any UnhandledCriticalExtensions.
		for i, oid := range attStmt.aikCert.UnhandledCriticalExtensions {
			if oid.Equal(oidExtensionSubjectAltName) {
				attStmt.aikCert.UnhandledCriticalExtensions = append(attStmt.aikCert.UnhandledCriticalExtensions[:i], attStmt.aikCert.UnhandledCriticalExtensions[i+1:]...)
				break
			}
		}

		// Verify aikCert by building certificate chain.
		if trustPath, err = verifyAttestationCert(attStmt.aikCert, attStmt.caCerts); err != nil {
			err = &webauthn.VerificationError{Type: "TPM attestation", Field: "certificate", Msg: err.Error()}
			return
		}

		// If successful, return implementation-specific values representing attestation type AttCA and attestation trust path x5c.
		return webauthn.AttestationTypeCA, trustPath, nil
	}
	if len(attStmt.ecdaaKeyID) > 0 {
		return webauthn.AttestationTypeECDAA, attStmt.ecdaaKeyID, &webauthn.UnsupportedFeatureError{Feature: "Elliptic Curve based Direct Anonymous Attestation (ECDAA)"}
	}
	return
}

func verifyTPMAttestationStatementCert(c *x509.Certificate) error {
	// Version MUST be set to 3.
	if c.Version != 3 {
		return fmt.Errorf("expected certificate version 3, got version %d", c.Version)
	}

	// Subject field MUST be set to empty.
	var subjectRawValue asn1.RawValue
	if _, err := asn1.Unmarshal(c.RawSubject, &subjectRawValue); err != nil {
		return errors.New("failed to parse certificate subject field: " + err.Error())
	}
	if len(subjectRawValue.Bytes) != 0 {
		return errors.New("certificate subject field is not empty")
	}

	// Subject Alternative Name extension MUST be set as defined in https://trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf section 3.2.9.
	// The issuer MUST include TPM manufacturer, TPM part number and TPM firmware version, using the directoryNameform within the GeneralName structure.
	// The TPM manufacturer identifies the manufacturer of the TPM.  This value MUST be the vendor ID defined in the TCG Vendor ID Registry.
	// The TPM part number is encoded as a string and is manufacturer-specific.
	// The TPM firmware version is a manfacturer-specific implementation version of the TPM.
	tpmManufacturer, tpmModel, tpmVersion, err := parseSANExtension(c)
	if err != nil {
		return err
	}
	if tpmManufacturer == nil {
		return errors.New("certificate SAN extension doesn't have TPM manufacturer")
	} else if tpmManufacturer, ok := tpmManufacturer.(string); !ok {
		return errors.New("TPM manufacturer is of wrong type")
	} else if _, ok := tpmManufacturers[tpmManufacturer]; !ok {
		return errors.New("TPM manufacturer \"" + tpmManufacturer + "\" is not recognized")
	}
	if tpmModel == nil {
		return errors.New("certificate SAN extension doesn't have TPM part number")
	}
	if tpmVersion == nil {
		return errors.New("certificate SAN extension doesn't have TPM firmware version")
	}

	// The Extended Key Usage extension MUST contain the "joint-iso-itu-t(2) internationalorganizations(23) 133 tcg-kp(8) tcg-kp-AIKCertificate(3)" OID.
	var foundExtKeyUsgTcgKpAikCertificate bool
	for _, oid := range c.UnknownExtKeyUsage {
		if oid.Equal(oidTcgKpAikCertificate) {
			foundExtKeyUsgTcgKpAikCertificate = true
			break
		}
	}
	if !foundExtKeyUsgTcgKpAikCertificate {
		return errors.New("certificate extended key usage extension does not have " + oidTcgKpAikCertificate.String() + "(\"tcg-kp-aik-certificate\")")
	}

	// The Basic Constraints extension MUST have the CA component set to false.
	if c.IsCA {
		return errors.New("certificate's basic constraints extension does not have the CA component set to false")
	}

	// An Authority Information Access (AIA) extension with entry id-ad-ocsp and a CRL Distribution Point extension [RFC5280] are both OPTIONAL as the status of many attestation certificates is available through metadata service.

	return nil
}

func matchAAGUIDWithCertificateExtensionIfExists(c *x509.Certificate, aaguid []byte) error {
	for _, ext := range c.Extensions {
		if ext.Id.Equal(oidTPMCertificateExt) {
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

func parseSANExtension(c *x509.Certificate) (tpmManufacturer, tpmModel, tpmVersion interface{}, err error) {
	var sanValue []byte
	for _, ext := range c.Extensions {
		if ext.Id.Equal(oidExtensionSubjectAltName) {
			sanValue = ext.Value
			break
		}
	}
	if len(sanValue) == 0 {
		err = errors.New("missing certificate SAN extension")
		return
	}
	var seq asn1.RawValue
	var rest []byte
	rest, err = asn1.Unmarshal(sanValue, &seq)
	if err != nil {
		err = errors.New("failed to unmarshal certificate SAN extension: " + err.Error())
		return
	} else if len(rest) != 0 {
		err = errors.New("trailing data after certificate SAN extension")
		return
	}
	if !seq.IsCompound || seq.Tag != asn1.TagSequence || seq.Class != asn1.ClassUniversal {
		err = errors.New("bad data in certificate SAN extension")
		return
	}
	rest = seq.Bytes
	for len(rest) > 0 {
		var v asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			err = errors.New("failed to unmarshal certificate SAN extension element: " + err.Error())
			return
		}
		if v.Tag == 4 { // directoryName [4] Name
			var rdns pkix.RDNSequence
			var r []byte
			if r, err = asn1.Unmarshal(v.Bytes, &rdns); err != nil {
				err = errors.New("failed to unmarshal certificate SAN extension element: " + err.Error())
				return
			} else if len(r) != 0 {
				err = errors.New("trailing data after certificate SAN directoryName")
				return
			}
			for _, rdn := range rdns {
				if len(rdn) == 0 {
					continue
				}
				for _, atv := range rdn {
					if atv.Type.Equal(oidTPMManufacturer) {
						tpmManufacturer = atv.Value
					} else if atv.Type.Equal(oidTPMModel) {
						tpmModel = atv.Value
					} else if atv.Type.Equal(oidTPMVersion) {
						tpmVersion = atv.Value
					}
				}
			}
			return
		}
	}
	err = errors.New("missing certificate extension")
	return
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
	}

	var chains [][]*x509.Certificate
	chains, err = attestnCert.Verify(verifyOptions)
	if err != nil {
		return nil, err
	}
	return chains[0], nil
}

var tpmAlgorithms = map[int]string{
	0x0000: "TPM_ALG_ERROR",
	0x0001: "TPM_ALG_RSA",
	//0x0004: "TPM_ALG_SHA",
	0x0004: "TPM_ALG_SHA1",
	0x0005: "TPM_ALG_HMAC",
	0x0006: "TPM_ALG_AES",
	0x0007: "TPM_ALG_MGF1",
	0x0008: "TPM_ALG_KEYEDHASH",
	0x000A: "TPM_ALG_XOR",
	0x000B: "TPM_ALG_SHA256",
	0x000C: "TPM_ALG_SHA384",
	0x000D: "TPM_ALG_SHA512",
	0x0010: "TPM_ALG_NULL",
	0x0012: "TPM_ALG_SM3_256",
	0x0013: "TPM_ALG_SM4",
	0x0014: "TPM_ALG_RSASSA",
	0x0015: "TPM_ALG_RSAES",
	0x0016: "TPM_ALG_RSAPSS",
	0x0017: "TPM_ALG_OAEP",
	0x0018: "TPM_ALG_ECDSA",
	0x0019: "TPM_ALG_ECDH",
	0x001A: "TPM_ALG_ECDAA",
	0x001B: "TPM_ALG_SM2",
	0x001C: "TPM_ALG_ECSCHNORR",
	0x001D: "TPM_ALG_ECMQV",
	0x0020: "TPM_ALG_KDF1_SP800_56A",
	0x0021: "TPM_ALG_KDF2",
	0x0022: "TPM_ALG_KDF1_SP800_108",
	0x0023: "TPM_ALG_ECC",
	0x0025: "TPM_ALG_SYMCIPHER",
	0x0026: "TPM_ALG_CAMELLIA",
	0x0040: "TPM_ALG_CTR",
	0x0041: "TPM_ALG_OFB",
	0x0042: "TPM_ALG_CBC",
	0x0043: "TPM_ALG_CFB",
	0x0044: "TPM_ALG_ECB",
}

var tpmECCCurve = map[int]string{
	0x0000: "TPM_ECC_NONE",
	0x0001: "TPM_ECC_NIST_P192",
	0x0002: "TPM_ECC_NIST_P224",
	0x0003: "TPM_ECC_NIST_P256",
	0x0004: "TPM_ECC_NIST_P384",
	0x0005: "TPM_ECC_NIST_P521",
	0x0010: "TPM_ECC_BN_P256",
	0x0011: "TPM_ECC_BN_P638",
	0x0020: "TPM_ECC_SM2_P256",
}

var tpmStructureTags = map[int]string{
	0x00C4: "TPM_ST_RSP_COMMAND",
	0X8000: "TPM_ST_NULL",
	0x8001: "TPM_ST_NO_SESSIONS",
	0x8002: "TPM_ST_SESSIONS",
	0x8014: "TPM_ST_ATTEST_NV",
	0x8015: "TPM_ST_ATTEST_COMMAND_AUDIT",
	0x8016: "TPM_ST_ATTEST_SESSION_AUDIT",
	0x8017: "TPM_ST_ATTEST_CERTIFY",
	0x8018: "TPM_ST_ATTEST_QUOTE",
	0x8019: "TPM_ST_ATTEST_TIME",
	0x801A: "TPM_ST_ATTEST_CREATION",
	0x8021: "TPM_ST_CREATION",
	0x8022: "TPM_ST_VERIFIED",
	0x8023: "TPM_ST_AUTH_SECRET",
	0x8024: "TPM_ST_HASHCHECK",
	0x8025: "TPM_ST_AUTH_SIGNED",
	0x8029: "TPM_ST_FU_MANIFEST",
}

var tpmManufacturers = map[string]map[string]string{
	"id:414D4400": {
		"name": "AMD",
		"id":   "AMD",
	},
	"id:41544D4C": {
		"name": "Atmel",
		"id":   "ATML",
	},
	"id:4252434D": {
		"name": "Broadcom",
		"id":   "BRCM",
	},
	"id:48504500": {
		"name": "HPE",
		"id":   "HPE",
	},
	"id:49424d00": {
		"name": "IBM",
		"id":   "IBM",
	},
	"id:49465800": {
		"name": "Infineon",
		"id":   "IFX",
	},
	"id:494E5443": {
		"name": "Intel",
		"id":   "INTC",
	},
	"id:4C454E00": {
		"name": "Lenovo",
		"id":   "LEN",
	},
	"id:4D534654": {
		"name": "Microsoft",
		"id":   "MSFT",
	},
	"id:4E534D20": {
		"name": "National Semiconductor",
		"id":   "NSM",
	},
	"id:4E545A00": {
		"name": "Nationz",
		"id":   "NTZ",
	},
	"id:4E544300": {
		"name": "Nuvoton Technology",
		"id":   "NTC",
	},
	"id:51434F4D": {
		"name": "Qualcomm",
		"id":   "QCOM",
	},
	"id:534D5343": {
		"name": "SMSC",
		"id":   "SMSC",
	},
	"id:53544D20": {
		"name": "ST Microelectronics",
		"id":   "STM",
	},
	"id:534D534E": {
		"name": "Samsung",
		"id":   "SMSN",
	},
	"id:534E5300": {
		"name": "Sinosun",
		"id":   "SNS",
	},
	"id:54584E00": {
		"name": "Texas Instruments",
		"id":   "TXN",
	},
	"id:57454300": {
		"name": "Winbond",
		"id":   "WEC",
	},
	"id:524F4343": {
		"name": "Fuzhou Rockchip",
		"id":   "ROCC",
	},
	"id:474F4F47": {
		"name": "Google",
		"id":   "GOOG",
	},
}

func init() {
	webauthn.RegisterAttestationFormat("tpm", parseAttestation)
}
