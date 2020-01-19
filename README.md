<!--[![Build Status](https://travis-ci.com/fxamacker/webauthn.svg?branch=master)](https://travis-ci.com/fxamacker/webauthn)-->
[![Go Report Card](https://goreportcard.com/badge/github.com/fxamacker/webauthn)](https://goreportcard.com/report/github.com/fxamacker/webauthn)
[![GoDoc](http://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)](http://godoc.org/github.com/fxamacker/webauthn)
[![GitHub](https://img.shields.io/github/license/fxamacker/webauthn)](https://github.com/fxamacker/webauthn/blob/master/LICENSE)

# fxamacker/webauthn - FIDO2 server library in Go

WebAuthn (Web Authentication) is a [web standard](https://w3c.github.io/webauthn/) for authenticating users to web-based apps and services.  It's a core component of FIDO2, the successor of FIDO U2F legacy protocol.

This library performs server-side authentication for clients using FIDO2 keys, legacy FIDO U2F keys, etc.

<p align="center">
  <img src="https://user-images.githubusercontent.com/57072051/68431219-4e066780-0177-11ea-8a3f-5a137cc76cf1.png" alt="Picture of FIDO U2F key">
</p>

**It's easy to use without rewriting your projects**, because it's decoupled from `net/http` and isn't a framework.

For a simple webapp demo, see [`webauthn-demo`](https://www.github.com/fxamacker/webauthn-demo).

## Project Goals ##
fxamacker/webauthn is designed to be:
* **small and nearly self-contained** -- only 1 external dependency: [fxamacker/cbor](https://www.github.com/fxamacker/cbor)
* **simple and lightweight** -- decoupled from `net/http` and is not a framework
* **modular** -- 5 separate attestation packages (packed, tpm, androidkeystore, androidsafetynet, and fidou2f), so you only import what you need.

## Status ##
**Expired certificates embedded in test data cause tests to fail**, so that should be resolved. Test datetime can be faked locally, but online tests will show failure and scare people.
* :construction: **replace expired test certs** -- test certs expire and cause tests to fail, find a way to automate replacement
* :construction: **more tests and fuzzing** -- add extensive tests and fuzzing similar to fxamacker/cbor and fxamacker/cbor-fuzz
* :construction: **standards compliance** -- pass and publish results of standards conformance tests

## Features
* Easy server-side authentication for clients using FIDO2 keys, legacy FIDO U2F keys, and etc.
* Register credential algorithm for use
* Register attestation format for use
* Create new attestation format by implementing AttestationStatement interface
* Credential algorithms: RS1, RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, and ES512
* Credential public key types: RSA, RSA-PSS, and ECDSA
* Credential public key curves: P-256, P-384, and P-521
* Attestation formats: packed, tpm, android-key, android-safetynet, fido-u2f, and none
* Attestation types: Basic, Self, and None

## Installation 

```
go get github.com/fxamacker/webauthn
```

## High-level API

See [API docs](https://godoc.org/github.com/fxamacker/webauthn).

**Create assertion or attestation options:**

NewAssertionOptions creates [PublicKeyCredentialRequestOptions](https://w3c.github.io/webauthn/#dictionary-assertion-options).  NewAttestationOptions creates [PublicKeyCredentialCreationOptions](https://w3c.github.io/webauthn/#dictionary-makecredentialoptions).  Config represents Relying Party settings used to create those options.  Config is initialized at startup and used throughout the program.  User contains user data for which the Relying Party requests attestation or assertion.

```
func NewAssertionOptions(config *Config, user *User) (*PublicKeyCredentialRequestOptions, error)
func NewAttestationOptions(config *Config, user *User) (*PublicKeyCredentialCreationOptions, error)
```

**Parse assertion or attestation:**

ParseAssertion returns parsed [PublicKeyCredentialAssertion](https://w3c.github.io/webauthn/#iface-pkcredential).  ParseAttestation returns parsed [PublicKeyCredentialAttestation](https://w3c.github.io/webauthn/#iface-pkcredential).

```
func ParseAssertion(r io.Reader) (*PublicKeyCredentialAssertion, error)
func ParseAttestation(r io.Reader) (*PublicKeyCredentialAttestation, error)
```

**Verify assertion or attestation:**

VerifyAssertion verifies [PublicKeyCredentialAssertion](https://w3c.github.io/webauthn/#iface-pkcredential), returned by ParseAssertion.  AssertionExpectedData contains data needed to [verify an assertion](https://w3c.github.io/webauthn/#sctn-verifying-assertion).  

VerifyAttestation verifies [PublicKeyCredentialAttestation](https://w3c.github.io/webauthn/#iface-pkcredential), returned by ParseAttestation.  AttestationExpectedData contains data needed to [verify an attestation](https://w3c.github.io/webauthn/#sctn-registering-a-new-credential) before registering a new credential.  VerifyAttestation returns [attestation type](https://w3c.github.io/webauthn/#sctn-attestation-types) and [attestation trust path](https://w3c.github.io/webauthn/#attestation-trust-path).  Library users need to assess the attestation trustworthiness by verifying that attestation type is acceptable and trust path can be trusted.

```
func VerifyAssertion(credentialAssertion *PublicKeyCredentialAssertion, expected *AssertionExpectedData) error
func VerifyAttestation(credentialAttestation *PublicKeyCredentialAttestation, expected *AttestationExpectedData) (attType AttestationType, trustPath interface{}, err error)
```

## Examples

See [examples](example_test.go).

**Initialize Relying Party config:**

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

**Create attestation options:**

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

**Parse and verify attestation:**

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

**Create assertion options:**

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

**Parse and verify assertion:**

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

## Credits

A huge thanks to [herrjemand](https://www.github.com/herrjemand) for his extensive [tutorials](https://medium.com/@herrjemand) on WebAuthn/FIDO2.  [apowers313](https://github.com/apowers313)'s [fido2-lib](https://github.com/apowers313/fido2-lib) pointed me in the direction of separating WebAuthn functionality from any networking protocol.  This library also uses attestation and assertion test data from herrjemand and apowers313.

## License 

Copyright (c) 2019 [Faye Amacker](https://github.com/fxamacker)

Licensed under [Apache License 2.0](LICENSE)
