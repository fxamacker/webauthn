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
