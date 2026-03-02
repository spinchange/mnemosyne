package snapshot

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"mnemosyne/internal/crypto"
	"mnemosyne/internal/store"
	"os"
)

func Restore(dbPath string, snapshotFile string, password []byte) error {
	defer crypto.Zero(password)

	// 1. Read file
	data, err := os.ReadFile(snapshotFile)
	if err != nil {
		return fmt.Errorf("read snapshot: %w", err)
	}

	// 2. Parse Header
	h, err := UnmarshalHeader(data)
	if err != nil {
		return fmt.Errorf("unmarshal header: %w", err)
	}

	// 3. Derive Keys for Decryption
	dataKey, verifyKey, err := crypto.DeriveKeys(password, h.Salt[:], h.Argon2Memory, h.Argon2Iterations, h.Argon2Parallel)
	if err != nil {
		return fmt.Errorf("derive keys: %w", err)
	}
	defer crypto.Zero(dataKey)
	defer crypto.Zero(verifyKey)

	// 4. Decrypt
	headerBytes := data[:HeaderSize]
	payload := data[HeaderSize:]
	aad := FormatSnapshotAAD(headerBytes, h.SnapshotID)

	decrypted, err := crypto.Decrypt(dataKey, payload, aad)
	if err != nil {
		return fmt.Errorf("decrypt snapshot: %w", err)
	}

	// 5. Decompress
	gr, err := gzip.NewReader(bytes.NewReader(decrypted))
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gr.Close()

	jsonBytes, err := io.ReadAll(gr)
	if err != nil {
		return fmt.Errorf("read gzipped data: %w", err)
	}

	// 6. Unmarshal
	var snap Snapshot
	if err := json.Unmarshal(jsonBytes, &snap); err != nil {
		return fmt.Errorf("unmarshal json: %w", err)
	}

	// 7. Initialize NEW Store
	if _, err := os.Stat(dbPath); err == nil {
		return fmt.Errorf("database file already exists at %s", dbPath)
	}

	s, err := store.NewSQLiteStore(dbPath)
	if err != nil {
		return fmt.Errorf("create new store: %w", err)
	}
	defer s.Close()

	// 8. Setup Encryption in new store using original params
	// Note: SetupRestore also defers zeroing the password, which is safe to call twice.
	err = s.SetupRestore(password, h.Salt[:], h.Argon2Memory, h.Argon2Iterations, h.Argon2Parallel)
	if err != nil {
		return fmt.Errorf("setup restore encryption: %w", err)
	}

	// 9. Import Data
	for _, e := range snap.Entries {
		if err := s.ImportEntry(e); err != nil {
			return fmt.Errorf("import entry %d: %w", e.ID, err)
		}
	}

	for _, t := range snap.Triggers {
		if err := s.ImportTrigger(t); err != nil {
			return fmt.Errorf("import trigger %d: %w", t.ID, err)
		}
	}

	return nil
}
