// Copyright (c) 2019 Faye Amacker. All rights reserved.
// Use of this source code is governed by Apache License 2.0 found in the LICENSE file.

package webauthn

import (
	"bytes"
	"fmt"
)

var noneAttestationStatementCBORBytes = []byte{0xa0}

type noneAttestationStatement struct {
}

func parseNoneAttestation(data []byte) (AttestationStatement, error) {
	if !bytes.Equal(data, noneAttestationStatementCBORBytes) {
		return nil, &UnmarshalSyntaxError{Type: "none attestation", Msg: fmt.Sprintf("got %02x, want %02x, ", data, noneAttestationStatementCBORBytes)}
	}
	return &noneAttestationStatement{}, nil
}

// Verify implements the AttestationStatement interface.  It follows none attestation statement
// verification procedure defined in http://w3c.github.io/webauthn/#sctn-none-attestation
func (attStmt *noneAttestationStatement) Verify(clientDataHash []byte, authnData *AuthenticatorData) (attType AttestationType, trustPath interface{}, err error) {
	return AttestationTypeNone, nil, nil
}

func init() {
	RegisterAttestationFormat("none", parseNoneAttestation)
}
