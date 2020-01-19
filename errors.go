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
