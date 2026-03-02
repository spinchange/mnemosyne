package snapshot

import (
	"mnemosyne/internal/domain"
	"mnemosyne/internal/store"
	"path/filepath"
	"testing"
)

func TestSnapshotRoundtrip(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "original.db")
	restorePath := filepath.Join(tmpDir, "restored.db")
	snapFile := filepath.Join(tmpDir, "backup.msn")
	passwordStr := "master-key"

	// 1. Create original DB and add data
	s, err := store.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	
	setupKey, err := s.SetupEncryption([]byte(passwordStr))
	if err != nil {
		t.Fatalf("SetupEncryption failed: %v", err)
	}
	// SetupEncryption already called SetKey, but returns the key for us to use/zero
	defer s.SetKey(nil)

	entry := &domain.Entry{Title: "Snap Title", Body: "Snap Body Content", WordCount: 3}
	if err := s.CreateEntry(entry); err != nil {
		t.Fatalf("CreateEntry failed: %v", err)
	}

	// 2. Create Snapshot
	if err := CreateSnapshot(s, setupKey, 1, snapFile); err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}
	s.Close()

	// 3. Restore Snapshot
	if err := Restore(restorePath, snapFile, []byte(passwordStr)); err != nil {
		t.Fatalf("Restore failed: %v", err)
	}

	// 4. Verify restored data
	rs, err := store.NewSQLiteStore(restorePath)
	if err != nil {
		t.Fatalf("Failed to open restored store: %v", err)
	}
	defer rs.Close()

	dataKeyRestore, err := rs.Unlock([]byte(passwordStr))
	if err != nil {
		t.Fatalf("Failed to unlock restored store: %v", err)
	}
	rs.SetKey(dataKeyRestore)

	re, err := rs.GetEntry(entry.ID)
	if err != nil {
		t.Fatalf("Failed to get entry from restored store: %v", err)
	}

	if re.Title != entry.Title || re.Body != entry.Body {
		t.Errorf("Restored data mismatch: got title=%q, body=%q; want title=%q, body=%q", re.Title, re.Body, entry.Title, entry.Body)
	}
}
