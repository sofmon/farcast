package devicekey

import (
	"crypto"
	"errors"
	"fmt"
	"io"
)

// opaque hides a private key behind crypto.Signer: Public and Sign only. A
// caller cannot type-assert it back to *ecdsa.PrivateKey or *rsa.PrivateKey,
// marshal it, or read its scalar. Sign passes opts through, so TLS 1.3's
// RSA-PSS and ECDSA both work. fmt reaches the key only through an
// unexported interface field holding a pointer, and prints it as an address.
//
// Every crypto.Signer the package returns is an opaque. Nothing relies on
// clearing key memory, because Go's ECDSA keys cannot be cleared; the custody
// rules are what limit exposure.
//
// It also formats as fixed text when fmt reaches it directly. Under a verb a
// pointer does not take (%s, %q), fmt would otherwise print the key pointer
// again at depth 0 and dereference it (go1.27.4 src/fmt/print.go:384-387,
// :905-910); the scalar is then one more pointer down and prints as an
// address, but that rests on ecdsa.PrivateKey's layout.
type opaque struct{ k crypto.Signer }

// opaqueText is the fixed text every formatting of an opaque gives.
const opaqueText = "signer (not printed)"

// String is "signer (not printed)".
func (o opaque) String() string { return opaqueText }

// GoString is "signer (not printed)".
func (o opaque) GoString() string { return opaqueText }

// Format writes "signer (not printed)" for every verb.
func (o opaque) Format(f fmt.State, verb rune) { _, _ = io.WriteString(f, opaqueText) }

// errNoKey is what the zero opaque's Sign returns.
var errNoKey = errors.New("devicekey: the signer holds no key")

// Public is the key's public half; nil for the zero opaque.
func (o opaque) Public() crypto.PublicKey {
	if o.k == nil {
		return nil
	}
	return o.k.Public()
}

// Sign signs digest with the key, passing opts through.
func (o opaque) Sign(rnd io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if o.k == nil {
		return nil, errNoKey
	}
	return o.k.Sign(rnd, digest, opts)
}
