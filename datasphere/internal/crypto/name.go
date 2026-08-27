package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// Object names are metadata the cloud stores and indexes, and names are often
// the most sensitive metadata there is. This file is what keeps them out of
// the cloud's hands while still allowing the prefix listing the frozen SDK
// contract requires.
//
// Two independent mechanisms, both keyed off the keyring's stable name key:
//
//   - Tokenization maps a logical key to the opaque path it is stored under.
//     It is deterministic, because a cloud-side prefix list has to be
//     computable client-side, and path-chained, so that equality leakage is
//     confined to shared path prefixes — the minimum any List-compatible
//     scheme reveals.
//   - Sealing carries the logical name itself, encrypted, next to the object,
//     so a List can recover real names from one page of metadata and so that
//     the bucket plus the keys file alone reconstruct every name with no local
//     state at all.

// NameTokenKey derives the HMAC key that tokenizes stored paths. It is
// separate from the sealing keys so that the two uses of the name key never
// share key material.
func NameTokenKey(nameKey []byte) ([]byte, error) {
	return derive(nameKey, infoNameToken)
}

// TokenPath maps a logical key to the path it is stored under: segment i
// becomes the lowercase hex of HMAC-SHA-256 over the exact joined logical path
// prefix seg₁‖"/"‖…‖segᵢ, truncated to TokenBytes.
//
// Chaining is the whole point. Every /-aligned logical prefix stays
// independently computable — which is all cloud-side prefix listing needs,
// since equal logical path prefixes yield equal stored prefixes — while a
// segment's token depends on its ancestors. A per-segment construction would
// additionally correlate every occurrence of a common leaf name bucket-wide,
// with the reserved "system/" and "app/" literals as known plaintext.
//
// The key must already have passed ValidateLogicalKey.
func TokenPath(tokenKey []byte, logicalKey string) string {
	segments := strings.Split(logicalKey, "/")
	tokens := make([]string, len(segments))
	end := 0
	for i, seg := range segments {
		// Advance over "seg" and the "/" that preceded it, so logicalKey[:end]
		// is exactly seg₁‖"/"‖…‖segᵢ without rebuilding the string each round.
		if i > 0 {
			end++
		}
		end += len(seg)
		tokens[i] = token(tokenKey, logicalKey[:end])
	}
	return strings.Join(tokens, "/")
}

// TokenPrefix maps a logical prefix to the stored prefix to list under: the
// longest /-aligned portion of the prefix, tokenized.
//
// Anything after the last "/" cannot be tokenized — a token is an HMAC of a
// whole segment, and a partial segment is not one — so `users/al` lists under
// the token of `users/` and the caller filters the recovered logical names
// against the full prefix. That over-lists within one segment and is honest
// about it; the alternative is refusing prefixes the SDK contract accepts.
//
// An empty result means "list the whole bucket and filter client-side".
func TokenPrefix(tokenKey []byte, prefix string) string {
	cut := strings.LastIndex(prefix, "/")
	if cut < 0 {
		return ""
	}
	aligned := prefix[:cut]
	if aligned == "" {
		// The prefix opens with "/", naming an empty first segment. No valid
		// logical key has one, so there is nothing to narrow the listing with.
		return ""
	}
	return TokenPath(tokenKey, aligned) + "/"
}

func token(tokenKey []byte, path string) string {
	mac := hmac.New(sha256.New, tokenKey)
	mac.Write([]byte(path))
	return hex.EncodeToString(mac.Sum(nil)[:TokenBytes])
}

// SealName seals logicalKey for the object stored at storedPath and returns
// the block that is written both into the blob header and, base64-encoded,
// into the provider's metadata map.
//
// The sealing key is derived per object from storedPath, which is what removes
// the name key's GCM nonce budget: with a distinct key per object and a
// plaintext and AAD fixed per stored name, a nonce collision produces
// identical ciphertext and reveals nothing. That matters because the name key
// is the one key in this design that cannot rotate — deterministic tokens
// cannot survive a key change without renaming every stored object — so it
// must not be the key carrying a bound.
//
// The AAD is storedPath, which pins a sealed name to its object: a mapping
// lifted from one object onto another fails to authenticate. The format
// version is bound through the derivation's info string rather than the AAD.
func SealName(nameKey []byte, storedPath, logicalKey string, rnd io.Reader) ([]byte, error) {
	gcm, err := nameGCM(nameKey, storedPath)
	if err != nil {
		return nil, err
	}
	plaintext, err := padName(logicalKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, NonceLen)
	if _, err := io.ReadFull(rnd, nonce); err != nil {
		return nil, fmt.Errorf("datasphere: read name nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, []byte(storedPath)), nil
}

// OpenName reverses SealName. Every failure — a short block, a bad tag, a
// non-canonical interior — is ErrIntegrity: the caller learns the name could
// not be trusted, never which byte gave it away.
func OpenName(nameKey []byte, storedPath string, sealed []byte) (string, error) {
	if len(sealed) < NonceLen+TagLen {
		return "", ErrIntegrity
	}
	gcm, err := nameGCM(nameKey, storedPath)
	if err != nil {
		return "", err
	}
	plaintext, err := gcm.Open(nil, sealed[:NonceLen], sealed[NonceLen:], []byte(storedPath))
	if err != nil {
		return "", ErrIntegrity
	}
	return unpadName(plaintext)
}

// nameGCM builds the per-object AES-GCM for one stored path.
func nameGCM(nameKey []byte, storedPath string) (cipher.AEAD, error) {
	key, err := derive(nameKey, infoNameCryptPrefix+storedPath)
	if err != nil {
		return nil, fmt.Errorf("datasphere: derive name key: %w", err)
	}
	return newGCM(key)
}

// padName lays out a sealed name's plaintext: a uint16 big-endian length
// followed by the key's exact bytes, the whole thing zero-padded to a multiple
// of NamePadUnit. Padding the length prefix together with the name (rather
// than the name alone) is what makes the encoding canonical — there is exactly
// one valid plaintext per name.
func padName(logicalKey string) ([]byte, error) {
	if len(logicalKey) > MaxKeyBytes {
		return nil, wrapKeyErr("must be at most %d bytes, got %d", MaxKeyBytes, len(logicalKey))
	}
	out := make([]byte, paddedLen(2+len(logicalKey)))
	binary.BigEndian.PutUint16(out, uint16(len(logicalKey)))
	copy(out[2:], logicalKey)
	return out, nil
}

// unpadName reverses padName, rejecting anything but the one canonical
// encoding. Non-minimal padding and non-zero pad bytes are refused because
// either would be a channel a writer could smuggle bytes through, invisible to
// every reader that only looked at the name.
func unpadName(plaintext []byte) (string, error) {
	if len(plaintext) < 2 || len(plaintext)%NamePadUnit != 0 {
		return "", ErrIntegrity
	}
	n := int(binary.BigEndian.Uint16(plaintext))
	if 2+n > len(plaintext) || paddedLen(2+n) != len(plaintext) {
		return "", ErrIntegrity
	}
	for _, b := range plaintext[2+n:] {
		if b != 0 {
			return "", ErrIntegrity
		}
	}
	name := string(plaintext[2 : 2+n])
	if !utf8.ValidString(name) {
		return "", ErrIntegrity
	}
	return name, nil
}

// paddedLen rounds n up to the next multiple of NamePadUnit.
func paddedLen(n int) int {
	return ((n + NamePadUnit - 1) / NamePadUnit) * NamePadUnit
}

// newGCM builds AES-256-GCM over a KeyLen-byte key.
func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeyLen {
		return nil, fmt.Errorf("datasphere: key must be %d bytes, got %d", KeyLen, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("datasphere: build cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("datasphere: build AEAD: %w", err)
	}
	return gcm, nil
}
