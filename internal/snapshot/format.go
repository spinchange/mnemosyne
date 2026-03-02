package snapshot

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	HeaderSize = 72
	Magic      = "MSNP"
	Version    = 0x01
	KDFVersion = 0x01
)

var (
	ErrInvalidMagic   = errors.New("invalid snapshot magic")
	ErrInvalidVersion = errors.New("invalid snapshot version")
)

type Header struct {
	Magic            [4]byte  // "MSNP"
	Version          uint8    // 0x01
	KDFVersion       uint8    // 0x01
	Argon2Memory     uint32
	Argon2Iterations uint32
	Argon2Parallel   uint8
	Salt             [16]byte // Matches argon2_salt in config
	SnapshotID       uint64
	CreatedAt        int64
	Reserved         [33]byte // Padding to reach 72 bytes
}

func (h *Header) Marshal() []byte {
	buf := make([]byte, HeaderSize)
	copy(buf[0:4], h.Magic[:])
	buf[4] = h.Version
	buf[5] = h.KDFVersion
	binary.BigEndian.PutUint32(buf[6:10], h.Argon2Memory)
	binary.BigEndian.PutUint32(buf[10:14], h.Argon2Iterations)
	buf[14] = h.Argon2Parallel
	copy(buf[15:31], h.Salt[:])
	binary.BigEndian.PutUint64(buf[31:39], h.SnapshotID)
	binary.BigEndian.PutUint64(buf[39:47], uint64(h.CreatedAt))
	copy(buf[47:], h.Reserved[:])
	return buf
}

func UnmarshalHeader(data []byte) (*Header, error) {
	if len(data) < HeaderSize {
		return nil, fmt.Errorf("header too short: %d", len(data))
	}

	h := &Header{}
	copy(h.Magic[:], data[0:4])
	if string(h.Magic[:]) != Magic {
		return nil, ErrInvalidMagic
	}

	h.Version = data[4]
	if h.Version != Version {
		return nil, ErrInvalidVersion
	}

	h.KDFVersion = data[5]
	h.Argon2Memory = binary.BigEndian.Uint32(data[6:10])
	h.Argon2Iterations = binary.BigEndian.Uint32(data[10:14])
	h.Argon2Parallel = data[14]
	copy(h.Salt[:], data[15:31])
	h.SnapshotID = binary.BigEndian.Uint64(data[31:39])
	h.CreatedAt = int64(binary.BigEndian.Uint64(data[39:47]))
	copy(h.Reserved[:], data[47:])

	return h, nil
}

// FormatSnapshotAAD creates AAD that commits to the cleartext header and snapshot ID.
func FormatSnapshotAAD(headerBytes []byte, snapshotID uint64) []byte {
	// Header (72) + "snapshot:" (9) + uint64 (8) = 89 bytes
	aad := make([]byte, len(headerBytes)+9+8)
	copy(aad, headerBytes)
	copy(aad[len(headerBytes):], []byte("snapshot:"))
	binary.BigEndian.PutUint64(aad[len(headerBytes)+9:], snapshotID)
	return aad
}
