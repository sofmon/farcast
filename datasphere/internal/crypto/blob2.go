package crypto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Blob format v2 — the chunked, streaming format:
//
//	bytes         field
//	 0–74         exactly as v1: magic, version 0x02, key ID, wrap nonce,
//	              wrapped DEK, sealed-name length
//	 75 …         sealed name — the v1 construction, unchanged
//	 75+L …       frame-nonce salt (8 B)
//	 83+L         frame-size exponent e; frame plaintext size P = 1<<e
//	 84+L …       frame 0, frame 1, …
//
// One fresh single-use DEK covers the whole object and is wrapped once, so a
// five-gigabyte file costs one KEK wrap rather than five thousand — which is
// what keeps v1's per-KEK budget of roughly 2³² writes intact instead of
// burning it thousands of times faster on a single large file.
//
// **The format is self-terminating.** Every frame but the last carries exactly
// P bytes of plaintext; the last carries strictly fewer, and a plaintext whose
// length is an exact multiple of P therefore ends with a zero-plaintext frame.
// That rule is what lets a reader stream without knowing the object's length
// in advance — it never has to ask the cloud how long something is, and so can
// never be lied to about it.
//
// What that buys, stated as attacks: truncating the object leaves a full frame
// last, so the reader runs out of input still expecting more and errors;
// extending it is caught by the explicit trailing-bytes check; reordering or
// replaying a frame fails on the frame index in the AAD; and a frame lifted
// from another object fails because DEKs are single-use.
//
// The one property v1 has that this cannot: authentication is per frame, so a
// reader learns of damage only when it reaches it, after earlier frames have
// already been written out. That is arithmetic, not a choice. Every caller
// must treat a non-nil error as "the output is incomplete and must not be
// used", and the CLI writes downloads to a temporary file it renames only on
// success.

// SealStream writes the v2 blob for logicalKey, reading plaintext from r and
// writing the blob to w.
//
// The caller supplies the sealed name rather than having it minted here, which
// v1 does not require: a streaming upload has to declare an object's metadata
// before it can send a body, so the mirror the caller puts in that metadata
// must exist before the first byte is written.
//
// Randomness is drawn from rnd in a fixed order — DEK, wrap nonce, frame salt
// — so golden vectors are reproducible from a seeded reader. That order is a
// testing convenience, not part of the wire format.
func SealStream(kek Key, storedPath, logicalKey string, sealedName []byte, exp byte, r io.Reader, w io.Writer, rnd io.Reader) error {
	if err := ValidateLogicalKey(logicalKey); err != nil {
		return err
	}
	if exp < MinChunkExp || exp > MaxChunkExp {
		return fmt.Errorf("datasphere: frame-size exponent %d is outside [%d,%d]", exp, MinChunkExp, MaxChunkExp)
	}
	kekGCM, err := newGCM(kek.Material)
	if err != nil {
		return err
	}
	if len(sealedName) < NonceLen+TagLen || len(sealedName) > int(^uint16(0)) {
		return fmt.Errorf("datasphere: sealed name of %d bytes is not a valid block", len(sealedName))
	}

	dek := make([]byte, KeyLen)
	if _, err := io.ReadFull(rnd, dek); err != nil {
		return fmt.Errorf("datasphere: mint data key: %w", err)
	}
	defer clear(dek)
	wrapNonce := make([]byte, NonceLen)
	if _, err := io.ReadFull(rnd, wrapNonce); err != nil {
		return fmt.Errorf("datasphere: read wrap nonce: %w", err)
	}
	salt := make([]byte, SaltLen)
	if _, err := io.ReadFull(rnd, salt); err != nil {
		return fmt.Errorf("datasphere: read frame salt: %w", err)
	}

	header := make([]byte, HeaderLen, MaxHeaderLen)
	copy(header[offMagic:], Magic[:])
	header[offVersion] = Version2
	copy(header[offKeyID:], kek.ID[:])
	copy(header[offWrapNonce:], wrapNonce)
	copy(header[offWrappedDEK:], kekGCM.Seal(nil, wrapNonce, dek, wrapAAD(Version2, kek.ID)))
	binary.BigEndian.PutUint16(header[offNameLen:], uint16(len(sealedName)))
	header = append(header, sealedName...)
	header = append(header, salt...)
	header = append(header, exp)
	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("datasphere: write blob header: %w", err)
	}

	dekGCM, err := newGCM(dek)
	if err != nil {
		return err
	}
	frameSize := 1 << exp
	plaintext := make([]byte, frameSize)
	nonce := make([]byte, NonceLen)
	copy(nonce, salt)

	for index := uint32(0); ; index++ {
		n, readErr := io.ReadFull(r, plaintext)
		final := errors.Is(readErr, io.EOF) || errors.Is(readErr, io.ErrUnexpectedEOF)
		if readErr != nil && !final {
			return fmt.Errorf("datasphere: read plaintext: %w", readErr)
		}
		binary.BigEndian.PutUint32(nonce[SaltLen:], index)
		frame := dekGCM.Seal(nil, nonce, plaintext[:n], frameAAD(exp, index, final, logicalKey))
		if _, err := w.Write(frame); err != nil {
			return fmt.Errorf("datasphere: write frame %d: %w", index, err)
		}
		if final {
			return nil
		}
		if index == ^uint32(0) {
			return errors.New("datasphere: object exceeds the frame count this format can address")
		}
	}
}

// OpenStream authenticates a blob of either version from r and writes its
// plaintext to w. A v1 blob streams as its single frame.
//
// It returns either a fully authenticated plaintext or an error — but, unlike
// Open, bytes already authenticated may have reached w before the error. A
// non-nil error means the output is incomplete and must not be used.
func OpenStream(lookup KeyLookup, logicalKey string, r io.Reader, w io.Writer) error {
	prefix := make([]byte, HeaderLen)
	if _, err := io.ReadFull(r, prefix); err != nil {
		return ErrIntegrity
	}
	nameLen := int(binary.BigEndian.Uint16(prefix[offNameLen:]))
	if nameLen < NonceLen+TagLen || nameLen > int(^uint16(0)) {
		return ErrIntegrity
	}
	rest := make([]byte, nameLen)
	if _, err := io.ReadFull(r, rest); err != nil {
		return ErrIntegrity
	}
	// Deliberately NOT parsed yet. A v1 header is only well-formed once its
	// body is present, and the body has not been read — parsing here would
	// reject every v1 blob as truncated. The version byte is all that is
	// needed to choose a path, and each path parses what it has.
	if prefix[offVersion] == Version {
		// A v1 blob is one GCM invocation over the whole body; there is no way
		// to authenticate part of it, so streaming it means buffering it. The
		// 64 MiB cap that made v1 an honest []byte format bounds that.
		body, err := readAtMost(r, MaxPlaintext+NonceLen+TagLen+1)
		if err != nil {
			return err
		}
		blob := make([]byte, 0, len(prefix)+len(rest)+len(body))
		blob = append(append(append(blob, prefix...), rest...), body...)
		plaintext, err := Open(lookup, logicalKey, blob)
		if err != nil {
			return err
		}
		_, err = w.Write(plaintext)
		return err
	}

	h, err := ParseHeader(append(append([]byte{}, prefix...), rest...))
	if err != nil {
		return err
	}
	tail := make([]byte, SaltLen+1)
	if _, err := io.ReadFull(r, tail); err != nil {
		return ErrIntegrity
	}
	salt, exp := tail[:SaltLen], tail[SaltLen]
	// Range-checked before it sizes anything: the exponent is cloud-writable
	// plaintext, and an unchecked one is a request to allocate gigabytes.
	if exp < MinChunkExp || exp > MaxChunkExp {
		return ErrIntegrity
	}

	dek, err := h.unwrap(lookup)
	if err != nil {
		return err
	}
	defer clear(dek)
	dekGCM, err := newGCM(dek)
	if err != nil {
		return err
	}

	frameSize := 1 << exp
	frame := make([]byte, frameSize+TagLen)
	nonce := make([]byte, NonceLen)
	copy(nonce, salt)

	for index := uint32(0); ; index++ {
		n, readErr := io.ReadFull(r, frame)
		final := errors.Is(readErr, io.EOF) || errors.Is(readErr, io.ErrUnexpectedEOF)
		if readErr != nil && !final {
			return fmt.Errorf("datasphere: read blob: %w", readErr)
		}
		if final && n < TagLen {
			// Not even a tag: the object was truncated mid-frame, or ends on a
			// frame boundary with the final frame missing entirely.
			return ErrIntegrity
		}
		binary.BigEndian.PutUint32(nonce[SaltLen:], index)
		plaintext, err := dekGCM.Open(nil, nonce, frame[:n], frameAAD(exp, index, final, logicalKey))
		if err != nil {
			return ErrIntegrity
		}
		if _, err := w.Write(plaintext); err != nil {
			return err
		}
		if !final {
			continue
		}
		// A final frame is strictly shorter than a full one, so an object
		// whose length is a multiple of the frame size ends in a zero-length
		// frame. Anything after it is an extension and is refused.
		if trailing, err := r.Read(make([]byte, 1)); trailing > 0 || (err != nil && !errors.Is(err, io.EOF)) {
			return ErrIntegrity
		}
		return nil
	}
}

// frameAAD binds a frame to the format version, the framing it was written
// under, its position, whether it ends the object, and the logical key.
//
// The key ID is deliberately absent, exactly as in v1: that exclusion is what
// keeps a rekey a header rewrite for streamed objects too.
func frameAAD(exp byte, index uint32, final bool, logicalKey string) []byte {
	aad := make([]byte, 0, len(Magic)+1+1+4+1+len(logicalKey))
	aad = append(aad, Magic[:]...)
	aad = append(aad, Version2, exp)
	aad = binary.BigEndian.AppendUint32(aad, index)
	if final {
		aad = append(aad, 1)
	} else {
		aad = append(aad, 0)
	}
	return append(aad, logicalKey...)
}

// readAtMost reads up to limit bytes, refusing anything longer rather than
// truncating it.
func readAtMost(r io.Reader, limit int) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, fmt.Errorf("%w: blob exceeds the %d-byte limit for the buffered format", ErrTooLarge, limit)
	}
	return data, nil
}

// cappedBuffer collects a bounded plaintext, refusing to grow past its limit.
// It is what lets the buffered Open accept a streamed object without giving up
// the size cap that makes a []byte API honest.
type cappedBuffer struct {
	buf   []byte
	limit int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if len(c.buf)+len(p) > c.limit {
		return 0, fmt.Errorf("%w: object exceeds the %d-byte limit; read it with ReadStream", ErrTooLarge, c.limit)
	}
	c.buf = append(c.buf, p...)
	return len(p), nil
}

func (c *cappedBuffer) Bytes() []byte { return c.buf }
