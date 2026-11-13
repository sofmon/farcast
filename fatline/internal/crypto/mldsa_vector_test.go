//go:build go1.27

package crypto

import (
	"crypto"
	"crypto/mldsa"
	"crypto/sha256"
	"io"
)

// crypto/mldsa is Go 1.27's, and this module's language version is 1.26, so
// the ML-DSA-44 vector key lives in a file whose build constraint raises it.

// vectorMLDSA44 is an ML-DSA-44 key behind a signer that signs
// deterministically (ML-DSA signs randomized by default), so its request
// regenerates byte for byte.
type vectorMLDSA44 struct{ k *mldsa.PrivateKey }

// newVectorMLDSA44 derives the key's seed from label as vectorEd25519 does.
func newVectorMLDSA44(label string) (crypto.Signer, error) {
	seed := sha256.Sum256(vectorLabel(label))
	k, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), seed[:])
	if err != nil {
		return nil, err
	}
	return vectorMLDSA44{k}, nil
}

func (s vectorMLDSA44) Public() crypto.PublicKey { return s.k.Public() }

func (s vectorMLDSA44) Sign(_ io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.k.SignDeterministic(msg, opts)
}
