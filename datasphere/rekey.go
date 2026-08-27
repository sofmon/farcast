package datasphere

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/sofmon/farcast/datasphere/internal/crypto"
)

// Rekey rewrites the object stored under key so its data key is wrapped under
// the keyring's active key-encryption key, leaving the encrypted body exactly
// as it was. It reports whether anything changed.
//
// This is possible at all because neither blob format binds the key ID into
// the AAD that protects the body — an exclusion made precisely so rotation
// would never mean decrypt-everything-now.
//
// It is nonetheless not cheap, and the reason is worth stating where an
// operator can find it: a cloud object cannot be patched in place, so changing
// 68 bytes of header still costs a full download and a full upload. What this
// implementation does avoid is memory — the body streams through rather than
// being held — so rekeying a five-gigabyte object costs no more RAM than a
// five-kilobyte one.
//
// Rekey is nonce hygiene and keyring retirement. It is NOT compromise
// recovery: everything the cloud already saw stays exposed to whoever captured
// it, and names stay exposed until name-key rotation exists.
func (s *Store) Rekey(ctx context.Context, key string) (bool, error) {
	stored, err := s.StoredName(key)
	if err != nil {
		return false, err
	}
	kek, err := s.keys.ActiveKEK()
	if err != nil {
		return false, err
	}

	body, err := s.provider.GetStream(ctx, s.bucket, stored, 0, -1)
	if err != nil {
		return false, err
	}
	defer func() { _ = body.Close() }()

	head, err := readHead(body)
	if err != nil {
		return false, err
	}
	var current KeyID
	copy(current[:], head[5:5+len(current)])
	if current == kek.ID {
		return false, nil
	}

	prefix, err := crypto.RekeyPrefix(s.keys.lookup(), crypto.Key{ID: kek.ID.raw(), Material: kek.key}, head, rand.Reader)
	if err != nil {
		return false, err
	}
	sealedName, err := sealedNameOf(head)
	if err != nil {
		return false, err
	}
	copy(head, prefix)

	// head now holds the rewritten wrap fields followed by the rest of the
	// bytes already read off the object; body is whatever is left of it. None
	// of it is buffered beyond the header.
	rewritten := io.MultiReader(bytesReader(head), body)
	return true, s.provider.PutStream(ctx, s.bucket, StreamObject{
		Name: stored,
		Data: rewritten,
		Size: -1,
		Meta: map[string]string{MetaName: sealedName},
	})
}

// readHead reads at most a full header's worth of an object, tolerating a
// short object — a small blob simply is its header plus a little.
func readHead(r io.Reader) ([]byte, error) {
	head := make([]byte, crypto.MaxHeaderLen)
	n, err := io.ReadFull(r, head)
	if err != nil && n < crypto.HeaderLen {
		return nil, crypto.ErrIntegrity
	}
	return head[:n], nil
}

// sealedNameOf lifts the base64 metadata mirror out of a header that has
// already been read, so a rekey re-declares the same name it found.
func sealedNameOf(head []byte) (string, error) {
	nameLen := int(binary.BigEndian.Uint16(head[73:75]))
	if nameLen < crypto.NonceLen+crypto.TagLen || crypto.HeaderLen+nameLen > len(head) {
		return "", fmt.Errorf("%w: header does not contain a complete sealed name", crypto.ErrIntegrity)
	}
	return encodeMirror(head[crypto.HeaderLen : crypto.HeaderLen+nameLen]), nil
}
