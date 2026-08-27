package crypto

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Blob format v1 — the bytes DataSphere hands a cloud, and the only thing a
// cloud ever holds:
//
//	bytes    field
//	 0–3     magic "FCDS"
//	 4       version 0x01
//	 5–12    key ID of the KEK this blob's DEK is wrapped under
//	 13–24   wrap nonce
//	 25–72   wrapped DEK (32 B ciphertext + 16 B tag)
//	 73–74   sealed-name length (uint16 big-endian)
//	 …       sealed name: 12 B nonce ‖ ciphertext ‖ 16 B tag
//	 …       data nonce (12 B)
//	 …       data ciphertext ‖ 16 B tag
//
// Every object carries a fresh single-use DEK. That is what makes the data
// seal's nonce budget a non-question — a DEK is used exactly once, so a
// collision is structurally impossible — and what makes rotation a header
// rewrite instead of decrypt-everything-now. The wrap under the KEK is the
// only per-KEK GCM use: one invocation per write, which puts NIST SP
// 800-38D's random-nonce bound at roughly four billion writes per KEK, reset
// by rotation.
//
// Nonces are random even where a counter would be provably safe. The 24 bytes
// per object buy the property that a future bug reusing a key degrades to a
// bounded statistical risk rather than an instant catastrophe.

// Header is a parsed v1 header. Parsing authenticates nothing: every field
// here is attacker-writable until a GCM Open succeeds. It exists so the List
// fallback can reach the sealed name without decrypting a body, and so a
// header-only rekey can splice new wrap fields in.
type Header struct {
	KeyID      [KeyIDLen]byte
	WrapNonce  []byte
	WrappedDEK []byte
	SealedName []byte
	Body       []byte // data nonce ‖ ciphertext ‖ tag
	BodyOffset int    // where Body starts within the blob
}

// Seal builds the v1 blob for logicalKey, wrapping a fresh single-use DEK
// under kek and sealing the logical name for storedPath under nameKey. It
// returns the blob and, separately, the identical sealed-name block the caller
// mirrors into the provider's metadata map.
//
// storedPath and logicalKey must be a matching pair — the caller is expected to
// have derived the first from the second via TokenPath. Seal does not re-derive
// it: the name seal binds to storedPath while the body binds to logicalKey, so
// a mismatched pair produces a blob whose name mirror never authenticates under
// its own stored path. Store is the only caller today and computes both from
// one key; a future rename sweep must keep that discipline.
//
// Randomness is drawn from rnd in a fixed order — DEK, wrap nonce, name nonce,
// data nonce — so the golden vectors are reproducible from a seeded reader.
// That order is a testing convenience, not part of the wire format: any writer
// drawing real randomness produces a conforming blob.
func Seal(kek Key, nameKey []byte, storedPath, logicalKey string, plaintext []byte, rnd io.Reader) (blob, sealedName []byte, err error) {
	if err := ValidateLogicalKey(logicalKey); err != nil {
		return nil, nil, err
	}
	if len(plaintext) > MaxPlaintext {
		return nil, nil, fmt.Errorf("%w: %d bytes exceeds the %d-byte limit", ErrTooLarge, len(plaintext), MaxPlaintext)
	}
	kekGCM, err := newGCM(kek.Material)
	if err != nil {
		return nil, nil, err
	}

	dek := make([]byte, KeyLen)
	if _, err := io.ReadFull(rnd, dek); err != nil {
		return nil, nil, fmt.Errorf("datasphere: mint data key: %w", err)
	}
	defer clear(dek)
	wrapNonce := make([]byte, NonceLen)
	if _, err := io.ReadFull(rnd, wrapNonce); err != nil {
		return nil, nil, fmt.Errorf("datasphere: read wrap nonce: %w", err)
	}
	sealedName, err = SealName(nameKey, storedPath, logicalKey, rnd)
	if err != nil {
		return nil, nil, err
	}
	if len(sealedName) > int(^uint16(0)) {
		return nil, nil, fmt.Errorf("datasphere: sealed name of %d bytes overflows the length field", len(sealedName))
	}
	dataNonce := make([]byte, NonceLen)
	if _, err := io.ReadFull(rnd, dataNonce); err != nil {
		return nil, nil, fmt.Errorf("datasphere: read data nonce: %w", err)
	}

	dekGCM, err := newGCM(dek)
	if err != nil {
		return nil, nil, err
	}

	blob = make([]byte, HeaderLen, HeaderLen+len(sealedName)+NonceLen+len(plaintext)+TagLen)
	copy(blob[offMagic:], Magic[:])
	blob[offVersion] = Version
	copy(blob[offKeyID:], kek.ID[:])
	copy(blob[offWrapNonce:], wrapNonce)
	copy(blob[offWrappedDEK:], kekGCM.Seal(nil, wrapNonce, dek, wrapAAD(kek.ID)))
	binary.BigEndian.PutUint16(blob[offNameLen:], uint16(len(sealedName)))

	blob = append(blob, sealedName...)
	blob = append(blob, dataNonce...)
	blob = dekGCM.Seal(blob, dataNonce, plaintext, dataAAD(logicalKey))
	return blob, sealedName, nil
}

// Open authenticates and decrypts a v1 blob. logicalKey supplies the data
// seal's AAD, which is what binds a body to the name it was written under: a
// blob served in answer to a different key fails here, not silently.
//
// It returns either the exact authenticated plaintext or an error — never
// partial output. Every structural failure is ErrIntegrity; only a key ID the
// keyring does not hold is distinguishable, as ErrUnknownKey.
func Open(lookup KeyLookup, logicalKey string, b []byte) ([]byte, error) {
	h, err := ParseHeader(b)
	if err != nil {
		return nil, err
	}
	dek, err := h.unwrap(lookup)
	if err != nil {
		return nil, err
	}
	defer clear(dek)
	dekGCM, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	plaintext, err := dekGCM.Open(nil, h.Body[:NonceLen], h.Body[NonceLen:], dataAAD(logicalKey))
	if err != nil {
		return nil, ErrIntegrity
	}
	return plaintext, nil
}

// HeaderName unseals the authoritative logical name a blob carries.
//
// This is the copy that makes a blob self-describing: the bucket plus the keys
// file reconstruct every logical name with no local state and no reliance on
// the cloud having preserved an object's metadata map. Store.List uses the
// metadata mirror for speed and falls back here.
func HeaderName(nameKey []byte, storedPath string, b []byte) (string, error) {
	h, err := ParseHeader(b)
	if err != nil {
		return "", err
	}
	return OpenName(nameKey, storedPath, h.SealedName)
}

// Rekey rewrites a blob's key ID, wrap nonce, and wrapped DEK under newKEK,
// leaving every other byte — the sealed name and the whole body — untouched.
//
// It is possible precisely because the data seal's AAD excludes the key ID.
// That exclusion costs nothing: a body transplanted under a foreign header
// fails GCM regardless, since DEKs are single-use, and a cloud-side swap of
// two blobs fails on the logical-key binding at read time.
//
// Rotation is nonce hygiene and keyring retirement — once nothing references
// an old KEK it can leave keys.yaml, so a stolen stale backup stops decrypting
// current headers. It is not compromise recovery: everything a cloud already
// saw stays exposed to whoever captured it.
func Rekey(lookup KeyLookup, newKEK Key, b []byte, rnd io.Reader) ([]byte, error) {
	h, err := ParseHeader(b)
	if err != nil {
		return nil, err
	}
	newGCMKEK, err := newGCM(newKEK.Material)
	if err != nil {
		return nil, err
	}
	dek, err := h.unwrap(lookup)
	if err != nil {
		return nil, err
	}
	defer clear(dek)
	nonce := make([]byte, NonceLen)
	if _, err := io.ReadFull(rnd, nonce); err != nil {
		return nil, fmt.Errorf("datasphere: read wrap nonce: %w", err)
	}

	out := make([]byte, len(b))
	copy(out, b)
	copy(out[offKeyID:], newKEK.ID[:])
	copy(out[offWrapNonce:], nonce)
	copy(out[offWrappedDEK:], newGCMKEK.Seal(nil, nonce, dek, wrapAAD(newKEK.ID)))
	return out, nil
}

// ParseHeader splits a v1 blob into its fields, checking only that the bytes
// are structurally a v1 blob of the length they claim. Nothing it returns is
// trustworthy until a GCM Open succeeds over it.
//
// Bad magic, an unknown version, and a truncated blob all return ErrIntegrity
// rather than distinct errors: a caller must not be able to tell "not a
// DataSphere blob" from "tampered with", and no answer here justifies handing
// back plaintext.
func ParseHeader(b []byte) (Header, error) {
	if len(b) < HeaderLen {
		return Header{}, ErrIntegrity
	}
	if string(b[offMagic:offMagic+len(Magic)]) != string(Magic[:]) || b[offVersion] != Version {
		return Header{}, ErrIntegrity
	}
	nameLen := int(binary.BigEndian.Uint16(b[offNameLen:]))
	bodyOffset := HeaderLen + nameLen
	// A sealed name is at minimum a nonce and a tag; a body is at minimum a
	// nonce and a tag over an empty plaintext (a zero-byte object is legal).
	if nameLen < NonceLen+TagLen || len(b) < bodyOffset+NonceLen+TagLen {
		return Header{}, ErrIntegrity
	}
	h := Header{
		WrapNonce:  b[offWrapNonce : offWrapNonce+NonceLen],
		WrappedDEK: b[offWrappedDEK : offWrappedDEK+WrappedDEKLen],
		SealedName: b[HeaderLen:bodyOffset],
		Body:       b[bodyOffset:],
		BodyOffset: bodyOffset,
	}
	copy(h.KeyID[:], b[offKeyID:offKeyID+KeyIDLen])
	return h, nil
}

// unwrap recovers the blob's DEK, resolving the KEK the header names.
func (h Header) unwrap(lookup KeyLookup) ([]byte, error) {
	material, ok := lookup(h.KeyID)
	if !ok {
		return nil, fmt.Errorf("%w: key ID %x", ErrUnknownKey, h.KeyID)
	}
	kekGCM, err := newGCM(material)
	if err != nil {
		return nil, err
	}
	dek, err := kekGCM.Open(nil, h.WrapNonce, h.WrappedDEK, wrapAAD(h.KeyID))
	if err != nil {
		return nil, ErrIntegrity
	}
	return dek, nil
}

// dataAAD binds a body to the format version and to the exact logical key it
// was written under. The key ID is deliberately absent, so that a rekey can
// rewrite the wrap fields without invalidating every body it touches.
func dataAAD(logicalKey string) []byte {
	aad := make([]byte, 0, len(Magic)+1+len(logicalKey))
	aad = append(aad, Magic[:]...)
	aad = append(aad, Version)
	return append(aad, logicalKey...)
}

// wrapAAD binds a wrapped DEK to the format version and to the key ID the
// header advertises, so the header's routing field cannot be edited to point
// at another key without the unwrap failing.
func wrapAAD(id [KeyIDLen]byte) []byte {
	aad := make([]byte, 0, len(Magic)+1+KeyIDLen)
	aad = append(aad, Magic[:]...)
	aad = append(aad, Version)
	return append(aad, id[:]...)
}
