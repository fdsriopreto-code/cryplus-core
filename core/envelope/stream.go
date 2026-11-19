package envelope

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// Streaming format (STREAM construction, chunked AEAD):
//
//	"CPS1" | alg(1) | chunkSize u32 | kekVersion u32 | wrappedLen u16 | wrapped | noncePrefix
//	then repeated sealed chunks of chunkSize+overhead bytes (last may be shorter).
//
// Chunk nonce = noncePrefix || counter(u32 BE) || lastFlag(1). The flag makes
// truncation detectable; the counter makes reordering detectable. The chunk
// AAD binds algorithm, chunk size, nonce prefix and the caller Context, but
// not the KEK version or wrapped DEK, so the header can be re-wrapped.

const (
	streamMagic     = "CPS1"
	DefaultChunk    = 64 * 1024
	maxChunk        = 16 * 1024 * 1024
	streamHeaderMin = 4 + 1 + 4 + 4 + 2
)

var ErrStream = errors.New("envelope: malformed or truncated stream")

func nonceSize(alg Algorithm) (int, error) {
	switch alg {
	case XChaCha20Poly1305:
		return chacha20poly1305.NonceSizeX, nil
	case AES256GCM:
		return 12, nil
	}
	return 0, ErrStream
}

func streamAAD(alg Algorithm, chunk uint32, prefix []byte, c Context) []byte {
	out := []byte("cp/s")
	out = append(out, byte(alg))
	out = binary.BigEndian.AppendUint32(out, chunk)
	out = append(out, prefix...)
	return append(out, c.AAD()...)
}

func chunkNonce(prefix []byte, ctr uint32, last bool) []byte {
	n := make([]byte, 0, len(prefix)+5)
	n = append(n, prefix...)
	n = binary.BigEndian.AppendUint32(n, ctr)
	if last {
		return append(n, 1)
	}
	return append(n, 0)
}

type streamWriter struct {
	w    io.Writer
	aead interface {
		Seal(dst, nonce, plaintext, additionalData []byte) []byte
	}
	prefix []byte
	aad    []byte
	chunk  int
	buf    []byte
	ctr    uint32
	err    error
	closed bool
}

// EncryptWriter returns a WriteCloser that encrypts everything written to it
// into w. Close MUST be called: it seals the final chunk, and a stream that
// was not closed is rejected as truncated by the reader.
func (s *Service) EncryptWriter(ctx context.Context, c Context, w io.Writer) (io.WriteCloser, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	dek := make([]byte, 32)
	if _, err := io.ReadFull(s.rng(), dek); err != nil {
		return nil, err
	}
	defer zero(dek)
	ver := s.Provider.CurrentVersion()
	wrapped, err := s.Provider.Wrap(ctx, ver, c.Tenant, dek, c.AAD())
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(s.Alg, dek)
	if err != nil {
		return nil, err
	}
	ns, err := nonceSize(s.Alg)
	if err != nil {
		return nil, err
	}
	prefix := make([]byte, ns-5)
	if _, err := io.ReadFull(s.rng(), prefix); err != nil {
		return nil, err
	}
	hdr := writeHeader(s.Alg, DefaultChunk, ver, wrapped, prefix)
	if _, err := w.Write(hdr); err != nil {
		return nil, err
	}
	return &streamWriter{
		w: w, aead: aead, prefix: prefix,
		aad:   streamAAD(s.Alg, DefaultChunk, prefix, c),
		chunk: DefaultChunk, buf: make([]byte, 0, DefaultChunk),
	}, nil
}

func writeHeader(alg Algorithm, chunk, ver uint32, wrapped, prefix []byte) []byte {
	h := make([]byte, 0, streamHeaderMin+len(wrapped)+len(prefix))
	h = append(h, streamMagic...)
	h = append(h, byte(alg))
	h = binary.BigEndian.AppendUint32(h, chunk)
	h = binary.BigEndian.AppendUint32(h, ver)
	h = binary.BigEndian.AppendUint16(h, uint16(len(wrapped)))
	h = append(h, wrapped...)
	return append(h, prefix...)
}

func (sw *streamWriter) flush(last bool) error {
	out := sw.aead.Seal(nil, chunkNonce(sw.prefix, sw.ctr, last), sw.buf, sw.aad)
	sw.ctr++
	sw.buf = sw.buf[:0]
	_, err := sw.w.Write(out)
	return err
}

func (sw *streamWriter) Write(p []byte) (int, error) {
	if sw.err != nil {
		return 0, sw.err
	}
	if sw.closed {
		return 0, errors.New("envelope: write after close")
	}
	n := len(p)
	for len(p) > 0 {
		// Only flush a full chunk once more data arrives, so Close always
		// has the final chunk to mark as last.
		if len(sw.buf) == sw.chunk {
			if err := sw.flush(false); err != nil {
				sw.err = err
				return 0, err
			}
		}
		take := sw.chunk - len(sw.buf)
		if take > len(p) {
			take = len(p)
		}
		sw.buf = append(sw.buf, p[:take]...)
		p = p[take:]
	}
	return n, nil
}

func (sw *streamWriter) Close() error {
	if sw.closed {
		return sw.err
	}
	sw.closed = true
	if sw.err != nil {
		return sw.err
	}
	sw.err = sw.flush(true)
	return sw.err
}

type streamHeader struct {
	alg     Algorithm
	chunk   uint32
	kekVer  uint32
	wrapped []byte
	prefix  []byte
}

func readHeader(r io.Reader) (*streamHeader, error) {
	fixed := make([]byte, streamHeaderMin)
	if _, err := io.ReadFull(r, fixed); err != nil || string(fixed[:4]) != streamMagic {
		return nil, ErrStream
	}
	h := &streamHeader{
		alg:    Algorithm(fixed[4]),
		chunk:  binary.BigEndian.Uint32(fixed[5:9]),
		kekVer: binary.BigEndian.Uint32(fixed[9:13]),
	}
	wl := int(binary.BigEndian.Uint16(fixed[13:15]))
	ns, err := nonceSize(h.alg)
	if err != nil || h.chunk == 0 || h.chunk > maxChunk {
		return nil, ErrStream
	}
	rest := make([]byte, wl+ns-5)
	if _, err := io.ReadFull(r, rest); err != nil {
		return nil, ErrStream
	}
	h.wrapped, h.prefix = rest[:wl], rest[wl:]
	return h, nil
}

type streamReader struct {
	r    *bufio.Reader
	aead interface {
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
		Overhead() int
	}
	prefix []byte
	aad    []byte
	chunk  int
	ctr    uint32
	out    []byte
	done   bool
	err    error
}

// DecryptReader returns a Reader yielding the plaintext of an encrypted
// stream. Data is released only after its chunk authenticates; a truncated,
// reordered or tampered stream ends in an error, never in silent short data.
func (s *Service) DecryptReader(ctx context.Context, c Context, r io.Reader) (io.Reader, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	h, err := readHeader(r)
	if err != nil {
		return nil, err
	}
	dek, err := s.Provider.Unwrap(ctx, h.kekVer, c.Tenant, h.wrapped, c.AAD())
	if err != nil {
		return nil, ErrDecrypt
	}
	defer zero(dek)
	aead, err := newAEAD(h.alg, dek)
	if err != nil {
		return nil, ErrDecrypt
	}
	return &streamReader{
		r: bufio.NewReaderSize(r, int(h.chunk)+aead.Overhead()+1), aead: aead,
		prefix: h.prefix, aad: streamAAD(h.alg, h.chunk, h.prefix, c), chunk: int(h.chunk),
	}, nil
}

func (sr *streamReader) Read(p []byte) (int, error) {
	for len(sr.out) == 0 {
		if sr.err != nil {
			return 0, sr.err
		}
		if sr.done {
			return 0, io.EOF
		}
		if err := sr.next(); err != nil {
			sr.err = err
			return 0, err
		}
	}
	n := copy(p, sr.out)
	sr.out = sr.out[n:]
	return n, nil
}

func (sr *streamReader) next() error {
	size := sr.chunk + sr.aead.Overhead()
	buf := make([]byte, size)
	n, err := io.ReadFull(sr.r, buf)
	switch {
	case err == nil:
	case errors.Is(err, io.ErrUnexpectedEOF):
	case errors.Is(err, io.EOF):
		return ErrStream // stream ended without a final chunk
	default:
		return err
	}
	buf = buf[:n]
	// A chunk is the last one iff nothing follows it.
	_, perr := sr.r.Peek(1)
	last := errors.Is(perr, io.EOF)
	if !last && perr != nil {
		return perr
	}
	if n < sr.aead.Overhead() || (!last && n != size) {
		return ErrStream
	}
	pt, err := sr.aead.Open(nil, chunkNonce(sr.prefix, sr.ctr, last), buf, sr.aad)
	if err != nil {
		return ErrDecrypt
	}
	sr.ctr++
	sr.out = pt
	sr.done = last
	return nil
}

// RewrapStreamHeader copies an encrypted stream from r to w with its DEK
// re-wrapped under the current KEK version. Payload bytes are copied
// verbatim without decryption.
func (s *Service) RewrapStreamHeader(ctx context.Context, c Context, r io.Reader, w io.Writer) (bool, error) {
	if err := c.validate(); err != nil {
		return false, err
	}
	h, err := readHeader(r)
	if err != nil {
		return false, err
	}
	cur := s.Provider.CurrentVersion()
	if h.kekVer == cur {
		hdr := writeHeader(h.alg, h.chunk, h.kekVer, h.wrapped, h.prefix)
		if _, err := w.Write(hdr); err != nil {
			return false, err
		}
		_, err := io.Copy(w, r)
		return false, err
	}
	dek, err := s.Provider.Unwrap(ctx, h.kekVer, c.Tenant, h.wrapped, c.AAD())
	if err != nil {
		return false, ErrDecrypt
	}
	defer zero(dek)
	nw, err := s.Provider.Wrap(ctx, cur, c.Tenant, dek, c.AAD())
	if err != nil {
		return false, err
	}
	if _, err := w.Write(writeHeader(h.alg, h.chunk, cur, nw, h.prefix)); err != nil {
		return false, err
	}
	_, err = io.Copy(w, r)
	return true, err
}
