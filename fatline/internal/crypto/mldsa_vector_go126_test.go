//go:build !go1.27

package crypto

import (
	"crypto"
	"errors"
)

// Before Go 1.27 there is no crypto/mldsa, so the mldsa44_key request vector
// cannot be made, and TestPKIVectors says so rather than skip it.
func newVectorMLDSA44(string) (crypto.Signer, error) {
	return nil, errors.New("the mldsa44_key request vector needs Go 1.27 (crypto/mldsa)")
}
