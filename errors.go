// Copyright (c) 2019 Faye Amacker. All rights reserved.
// Use of this source code is governed by Apache License 2.0 found in the LICENSE file.

package webauthn

import "strings"

// UnmarshalSyntaxError describes a syntax error resulting from parsing webauthn data.
type UnmarshalSyntaxError struct {
	Type  string
	Field string
	Msg   string
}

func (e *UnmarshalSyntaxError) Error() string {
	if e.Field == "" {
		return "webauthn/" + transformType(e.Type) + ": failed to unmarshal: " + e.Msg
	}
	return "webauthn/" + transformType(e.Type) + ": failed to unmarshal " + e.Field + ": " + e.Msg
}

// UnmarshalMissingFieldError results when a required field is missing.
type UnmarshalMissingFieldError struct {
	Type  string
	Field string
}

func (e *UnmarshalMissingFieldError) Error() string {
	return "webauthn/" + transformType(e.Type) + ": missing " + e.Field
}

// UnmarshalBadDataError results when invalid data is detected.
type UnmarshalBadDataError struct {
	Type string
	Msg  string
}

func (e *UnmarshalBadDataError) Error() string {
	return "webauthn/" + transformType(e.Type) + ": " + e.Msg
}

// UnsupportedFeatureError describes a feature that is not supported.
type UnsupportedFeatureError struct {
	Feature string
}

func (e *UnsupportedFeatureError) Error() string {
	return "webauthn: " + e.Feature + " is not supported"
}

// UnregisteredFeatureError describes a feature that is not registered.
type UnregisteredFeatureError struct {
	Feature string
}

func (e *UnregisteredFeatureError) Error() string {
	return "webauthn: " + e.Feature + " is not registered"
}

// VerificationError describes an error resulting from verifying webauthn data.
type VerificationError struct {
	Type  string
	Field string
	Msg   string
}

func (e *VerificationError) Error() string {
	s := "webauthn/" + transformType(e.Type) + ": failed to verify " + e.Field
	if e.Msg != "" {
		s += ": " + e.Msg
	}
	return s
}

func transformType(typ string) string {
	return strings.Replace(strings.ToLower(typ), " ", "_", -1)
}
