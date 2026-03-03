package snapshot

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"mnemosyne/internal/crypto"
	"mnemosyne/internal/store"
	"os"
	"time"
)

func CreateSnapshot(s *store.SQLiteStore, dataKey []byte, id uint64, path string) error {
	// 1. Fetch data using provided key to avoid store session race
	entries, triggers, err := s.ExportData(dataKey)
	if err != nil {
		return fmt.Errorf("export data: %w", err)
	}

	// 2. Construct Snapshot
	snap := Snapshot{
		SchemaVersion: 1,
		AppVersion:    "0.1.0", // TODO: use actual version
		SnapshotID:    id,
		CreatedAt:     time.Now(),
		EntryCount:    len(entries),
		Entries:       entries,
		Triggers:      triggers,
	}

	// 3. Marshal to JSON
	jsonData, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}
	defer crypto.Zero(jsonData)

	// 4. Gzip
	var gzipped bytes.Buffer
	gw := gzip.NewWriter(&gzipped)
	if _, err := gw.Write(jsonData); err != nil {
		return fmt.Errorf("gzip write: %w", err)
	}
	if err := gw.Close(); err != nil {
		return fmt.Errorf("gzip close: %w", err)
	}
	defer crypto.Zero(gzipped.Bytes())

	// 5. Get Argon2 params for header
	m, t, p, salt, err := s.GetArgon2Params()
	if err != nil {
		return fmt.Errorf("get argon2 params: %w", err)
	}

	// 6. Construct Header
	h := &Header{
		Version:          Version,
		KDFVersion:       KDFVersion,
		Argon2Memory:     m,
		Argon2Iterations: t,
		Argon2Parallel:   p,
		SnapshotID:       id,
		CreatedAt:        snap.CreatedAt.Unix(),
	}
	copy(h.Magic[:], Magic)
	copy(h.Salt[:], salt)

	headerBytes := h.Marshal()

	// 7. Encrypt
	aad := FormatSnapshotAAD(headerBytes, id)
	// We use the existing crypto.Encrypt which expects Version1 (0x01) internally.
	// Our snapshot header also uses 0x01.
	encrypted, err := crypto.Encrypt(dataKey, gzipped.Bytes(), aad)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	// 8. Write to disk
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(headerBytes); err != nil {
		return fmt.Errorf("write header: %w", err)
	}
	if _, err := f.Write(encrypted); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}

	return nil
}
