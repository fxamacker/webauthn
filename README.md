[![Build Status](https://travis-ci.com/fxamacker/webauthn.svg?branch=master)](https://travis-ci.com/fxamacker/webauthn)
[![Go Report Card](https://goreportcard.com/badge/github.com/fxamacker/webauthn)](https://goreportcard.com/report/github.com/fxamacker/webauthn)
[![GoDoc](http://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)](http://godoc.org/github.com/fxamacker/webauthn)
[![GitHub](https://img.shields.io/github/license/fxamacker/webauthn)](https://github.com/fxamacker/webauthn/blob/master/LICENSE)

# WebAuthn server library (Go/Golang)

This [WebAuthn](https://en.wikipedia.org/wiki/WebAuthn) server library provides registration and authentication for clients using FIDO2 keys, FIDO U2F keys, TPM, and etc.

* It's decoupled from `net/http` and doesn't force you to use a framework.  So it's easy to use in existing projects.

* It's modular so you only import the attestation formats you need.  This helps your software avoid bloat.

* Six attestation formats are provided: fidou2f, androidkeystore, androidsafetynet, packed, tpm, and none.

* It doesn't import unreliable packages. It imports [fxamacker/cbor](https://github.com/fxamacker/cbor) because it doesn't crash and it's the most well-tested CBOR library available (v1.5 has 375+ tests and passed 3+ billion execs in coverage-guided fuzzing).

A [demo webapp (webauthn-demo)](https://www.github.com/fxamacker/webauthn-demo) shows how to use this library with a security token like the YubiKey pictured here.

<p align="center">
  <img src="https://user-images.githubusercontent.com/57072051/68431219-4e066780-0177-11ea-8a3f-5a137cc76cf1.png" alt="Picture of FIDO U2F key">
</p>

## What's WebAuthn?
WebAuthn (Web Authentication) is a [W3C web standard](https://www.w3.org/TR/webauthn/) for authenticating users to web-based apps and services.  It's a core component of [FIDO2](https://en.wikipedia.org/wiki/FIDO2_Project), the successor of FIDO U2F legacy protocol.

## Design Goals
fxamacker/webauthn is designed to be:

* __small and no unreliable imports__ -- only 1 external dependency [fxamacker/cbor](https://www.github.com/fxamacker/cbor)
* __simple and lightweight__ -- decoupled from `net/http` and is not a framework
* __modular__ -- 5 separate attestation packages (packed, tpm, androidkeystore, androidsafetynet, and fidou2f), so you only import what you need.

## Status
It's functional enough to demo but unit tests need work.  Expired certs embedded in test data can make unit tests to fail.  A temporary workaround is to fake datetime when running unit tests locally until expired test data are replaced.

* __replace expired certs in unit tests__ -- automate replacement of test certs and/or make expiration dates longer
* __more tests and fuzzing__ -- add more extensive tests and fuzzing like fxamacker/cbor and fxamacker/cbor-fuzz
* __standards compliance__ -- publish results of standards conformance tests when ready to announce

## Features

* Easy server-side authentication for clients using FIDO2 keys, legacy FIDO U2F keys, and etc.
* Register credential algorithm for use
* Register attestation format for use
* Create new attestation format by implementing AttestationStatement interface
* Credential algorithms: RS1, RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, and ES512
* Credential public key types: RSA, RSA-PSS, and ECDSA
* Credential public key curves: P-256, P-384, and P-521
* Attestation formats: fido-u2f, android-key, android-safetynet, packed, tpm, and none
* Attestation types: Basic, Self, and None

## System Requirements

* Go 1.12 (or newer)
* Tested on x86_64 but it should work on other little-endian systems supported by Go.

## Installation 

```
go get github.com/fxamacker/webauthn
```

## High-level API

See [API docs](https://godoc.org/github.com/fxamacker/webauthn).

__Create assertion or attestation options:__

NewAssertionOptions creates [PublicKeyCredentialRequestOptions](https://w3c.github.io/webauthn/#dictionary-assertion-options).  NewAttestationOptions creates [PublicKeyCredentialCreationOptions](https://w3c.github.io/webauthn/#dictionary-makecredentialoptions).  Config represents Relying Party settings used to create those options.  Config is initialized at startup and used throughout the program.  User contains user data for which the Relying Party requests attestation or assertion.

```
func NewAssertionOptions(config *Config, user *User) (*PublicKeyCredentialRequestOptions, error)
func NewAttestationOptions(config *Config, user *User) (*PublicKeyCredentialCreationOptions, error)
```

__Parse assertion or attestation:__

ParseAssertion returns parsed [PublicKeyCredentialAssertion](https://w3c.github.io/webauthn/#iface-pkcredential).  ParseAttestation returns parsed [PublicKeyCredentialAttestation](https://w3c.github.io/webauthn/#iface-pkcredential).

```
func ParseAssertion(r io.Reader) (*PublicKeyCredentialAssertion, error)
func ParseAttestation(r io.Reader) (*PublicKeyCredentialAttestation, error)
```

__Verify assertion or attestation:__

VerifyAssertion verifies [PublicKeyCredentialAssertion](https://w3c.github.io/webauthn/#iface-pkcredential), returned by ParseAssertion.  AssertionExpectedData contains data needed to [verify an assertion](https://w3c.github.io/webauthn/#sctn-verifying-assertion).  

VerifyAttestation verifies [PublicKeyCredentialAttestation](https://w3c.github.io/webauthn/#iface-pkcredential), returned by ParseAttestation.  AttestationExpectedData contains data needed to [verify an attestation](https://w3c.github.io/webauthn/#sctn-registering-a-new-credential) before registering a new credential.  VerifyAttestation returns [attestation type](https://w3c.github.io/webauthn/#sctn-attestation-types) and [attestation trust path](https://w3c.github.io/webauthn/#attestation-trust-path).  Library users need to assess the attestation trustworthiness by verifying that attestation type is acceptable and trust path can be trusted.

```
func VerifyAssertion(credentialAssertion *PublicKeyCredentialAssertion, expected *AssertionExpectedData) error
func VerifyAttestation(credentialAttestation *PublicKeyCredentialAttestation, expected *AttestationExpectedData) (attType AttestationType, trustPath interface{}, err error)
```

## Examples

See [examples](example_test.go).

__Initialize Relying Party config:__

```
// cfg is initialized at startup and used throughout the program to create attestation and assertion options.  
cfg := &webauthn.Config{
    RPID:                    "localhost",
    RPName:                  "WebAuthn local host",
    Timeout:                 uint64(30000),
    ChallengeLength:         64,
    AuthenticatorAttachment: webauthn.AuthenticatorPlatform,
    ResidentKey:             webauthn.ResidentKeyPreferred,
    UserVerification:        webauthn.UserVerificationPreferred,
    Attestation:             webauthn.AttestationDirect,
    CredentialAlgs:          []int{webauthn.COSEAlgES256, webauthn.COSEAlgES384, webauthn.COSEAlgES512},
}
err := cfg.Valid()
if err != nil {
    return err
}
```

__Create attestation options:__

```
// user contains user data for which the Relying Party requests attestation or assertion.
user := &webauthn.User{
    ID:          []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 
    Name:        "Jane Doe",
    DisplayName: "Jane",
}
creationOptions, err := webauthn.NewAttestationOptions(cfg, user)
if err != nil {
    return err
}
creationOptionsJSON, err := json.Marshal(creationOptions)
if err != nil {
    return err
}
// Save user and creationOptions in session to verify attestation later.
// Send creationOptionsJSON to web client, which passes it to navigator.credentials.create().
```

__Parse and verify attestation:__

```
// Parse PublicKeyCredentialAttestation returned by navigator.credentials.create().
credentialAttestation, err := webauthn.ParseAttestation(r)
if err != nil {
    return err
}
// Create AttestationExpectedData object from session's user and creationOptions.
expected := &webauthn.AttestationExpectedData{
    Origin:           "https://localhost:8443",
    RPID:             "localhost",
    CredentialAlgs:   []int{webauthn.COSEAlgES256, webauthn.COSEAlgES384, webauthn.COSEAlgES512},
    Challenge:        "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w",
    UserVerification: webauthn.UserVerificationPreferred,
}
attType, trustPath, err := webauthn.VerifyAttestation(credentialAttestation, expected)
if err != nil {
    return err
}
// Verify that attType is acceptable and trustPath can be trusted.
// Save user info, credential id, algorithm, public key, and counter to persistent store.
// User is registered.
```

__Create assertion options:__

```
// user contains user data for which the Relying Party requests attestation or assertion.
user := &webauthn.User{
    ID:          []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 
    Name:        "Jane Doe",
    DisplayName: "Jane",
    CredentialIDs: [][]byte{
        []byte{11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26}, 
    },
}
requestOptions, err := webauthn.NewAssertionOptions(cfg, user)
if err != nil {
    return err
}
requestOptionsJSON, err := json.Marshal(requestOptions)
if err != nil {
    return err
}
// Save user and requestOptions in session to verify assertion later.
// Send requestOptionsJSON to web client, which passes it to navigator.credentials.get().
```

__Parse and verify assertion:__

```
// Parse PublicKeyCredentialAssertion returned by navigator.credentials.get().
credentialAssertion, err := webauthn.ParseAssertion(r)
if err != nil {
    return err
}
// Create AssertionExpectedData object from session's user and requestOptions.
expected := &webauthn.AssertionExpectedData{
    Origin:            "https://localhost:8443",
    RPID:              "localhost",
    Challenge:         "eaTyUNnyPDDdK8SNEgTEUvz1Q8dylkjjTimYd5X7QAo-F8_Z1lsJi3BilUpFZHkICNDWY8r9ivnTgW7-XZC3qQ",
    UserVerification:  webauthn.UserVerificationPreferred,
    UserID:            []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 
    UserCredentialIDs: [][]byte{
        []byte{11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26}, 
    },
    PrevCounter:       uint32(362),
    Credential:        credential,
}
err = webauthn.VerifyAssertion(credentialAssertion, expected)
if err != nil {
    return err
}
// Update counter in persistent store.
// User is authenticated.
```

## Limitations

This library doesn't support:

* Attestation validation through FIDO Metadata Service
* Extensions
* Token Binding
* CA attestation
* Elliptic Curve Direct Anonymous Attestation (ECDAA)

## Security Policy

Security fixes are provided for the latest released version.

To report security vulnerabilities, please email faye.github@gmail.com and allow time for the problem to be resolved before reporting it to the public.

## Special Thanks

* Montgomery Edwards⁴⁴⁸ [(x448)](https://github.com/x448) for updating README.md and filing helpful issues.

* Ackermann Yuriy [(herrjemand)](https://github.com/herrjemand) for his extensive [tutorials](https://medium.com/@herrjemand) on WebAuthn/FIDO2.  

* Adam Powers [(apowers313)](https://github.com/apowers313) for [fido2-lib](https://github.com/apowers313/fido2-lib) because that pointed me in the direction of separating WebAuthn functionality from any networking protocol.  

This library uses attestation and assertion test data from both herrjemand and apowers313.

## License

Copyright 2019-present [Faye Amacker](https://github.com/fxamacker)

fxamacker/webauthn is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full license text.
