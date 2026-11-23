// Package devicekey holds a device's own keys for one FarCast instance, and
// the public text made from them (ADR 0024 decision 4; design D2, D3 and D7).
//
// Per role, reader and writer, the device makes an anchor: a P-256 key and a
// self-signed CA certificate whose only subject field is the role's random ID.
// The anchor issues the role's leaf, from a key of its own, which is what the
// device presents at Google's token exchange. The anchor's certificate is the
// one trust anchor of that role's X509 provider; the human pastes it in, and
// nothing secret leaves the device. Every private key stays behind
// crypto.Signer, and one opening function per role and purpose (read,
// consented write, renewal, enrolment) holds the custody rules in one place.
//
// No command uses the package until M3b. In M3a only its own tests and the
// walk probe (a test file) import it, so farcast does not link it.
//
// Its custody checks read mode bits only. An access control list can let
// another account read a 0600 key, and the package does not read ACLs: the
// caller places the store where none reaches it (Store).
//
// The import rule:
//   - production files import the standard library only;
//   - test files import the standard library, devicekey itself, and
//     github.com/goccy/go-yaml (the root package only, to parse the trust
//     store document), which is already vendored and linked into farcast by
//     kube;
//   - nothing outside tests imports devicekey.
//
// TestDevicekeyImportsOnlyTheStandardLibrary holds the first two, and
// TestNothingShippedImportsDevicekey the third.
package devicekey
