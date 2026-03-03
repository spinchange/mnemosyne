package store

import (
	"mnemosyne/internal/crypto"
	"mnemosyne/internal/domain"
	"path/filepath"
	"testing"
)

func TestSetupAndUnlock(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "setup.db")

	s, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer s.Close()

	password := "master-pass"
	
	// Test Setup
	_, err = s.SetupEncryption([]byte(password))
	if err != nil {
		t.Fatalf("SetupEncryption failed: %v", err)
	}

	enabled, err := s.IsEncryptionEnabled()
	if err != nil || !enabled {
		t.Errorf("Encryption should be enabled")
	}

	// Test Unlock
	dataKey, err := s.Unlock([]byte(password))
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	if len(dataKey) != 32 {
		t.Errorf("Expected 32-byte data key, got %d", len(dataKey))
	}

	// Test Wrong Password
	_, err = s.Unlock([]byte("wrong-pass"))
	if err != ErrWrongPassword {
		t.Errorf("Expected ErrWrongPassword, got %v", err)
	}
}

func TestEncryptionRoundtrip(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "roundtrip.db")

	s, _ := NewSQLiteStore(dbPath)
	defer s.Close()
	password := []byte("pass")
	s.SetupEncryption(password)

	entry := &domain.Entry{
		Title: "Secret Title",
		Body:  "Secret Body Content",
	}

	err := s.CreateEntry(entry)
	if err != nil {
		t.Fatalf("CreateEntry failed: %v", err)
	}

	// Read back
	retrieved, err := s.GetEntry(entry.ID)
	if err != nil {
		t.Fatalf("GetEntry failed: %v", err)
	}

	if retrieved.Title != entry.Title {
		t.Errorf("Title mismatch: got %s, want %s", retrieved.Title, entry.Title)
	}
	if retrieved.Body != entry.Body {
		t.Errorf("Body mismatch: got %s, want %s", retrieved.Body, entry.Body)
	}
}

func TestSearch(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "search.db")

	s, _ := NewSQLiteStore(dbPath)
	defer s.Close()
	
	// 1. Test Plaintext Search
	e1 := &domain.Entry{Title: "Apple", Body: "The quick brown fox"}
	e2 := &domain.Entry{Title: "Banana", Body: "Jumped over the lazy dog"}
	s.CreateEntry(e1)
	s.CreateEntry(e2)

	results, err := s.SearchEntries("quick")
	if err != nil { t.Fatalf("Search failed: %v", err) }
	if len(results) != 1 || results[0].ID != e1.ID {
		t.Errorf("Plaintext search failed: expected e1, got %v", results)
	}

	// 2. Test Encrypted Search
	password := []byte("search-pass")
	_, err = s.SetupEncryption(password) // This migrates e1 and e2
	if err != nil { t.Fatalf("SetupEncryption failed: %v", err) }

	results, err = s.SearchEntries("lazy")
	if err != nil { t.Fatalf("Encrypted search failed: %v", err) }
	if len(results) != 1 || results[0].ID != e2.ID {
		t.Errorf("Encrypted search failed: expected e2, got %v", results)
	}

	// Test case-insensitivity
	results, err = s.SearchEntries("APPLE")
	if err != nil { t.Fatalf("Case-insensitive search failed: %v", err) }
	if len(results) != 1 || results[0].ID != e1.ID {
		t.Errorf("Case-insensitive search failed: expected e1, got %v", results)
	}
}

func TestMigrationResilience(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "resilience.db")

	s, _ := NewSQLiteStore(dbPath)
	defer s.Close()
	
	// 1. Create some plaintext data
	e1 := &domain.Entry{Title: "Title 1", Body: "Body 1"}
	s.CreateEntry(e1)
	
	// 2. Setup encryption (this runs the migration)
	password := []byte("pass123")
	dataKey, err := s.SetupEncryption(password)
	if err != nil {
		t.Fatalf("SetupEncryption failed: %v", err)
	}
	defer crypto.Zero(dataKey)

	// 3. Verify data is readable
	retrieved, err := s.GetEntry(e1.ID)
	if err != nil {
		t.Fatalf("GetEntry failed after migration: %v", err)
	}
	if retrieved.Title != "Title 1" {
		t.Errorf("Data corrupted after migration: got %q, want %q", retrieved.Title, "Title 1")
	}

	// 4. Simulate a "stale" migration flag and run migration again
	// This tests if migrateToEncrypted is idempotent and doesn't double-encrypt
	_, _ = s.db.Exec("DELETE FROM config WHERE key = 'data_migrated'")
	
	tx, err := s.db.Begin()
	if err != nil { t.Fatal(err) }
	err = s.migrateToEncrypted(tx, dataKey)
	if err != nil {
		t.Fatalf("Second migration failed: %v", err)
	}
	tx.Commit()

	// 5. Verify data is STILL readable (not double-encrypted)
	retrieved2, err := s.GetEntry(e1.ID)
	if err != nil {
		t.Fatalf("GetEntry failed after second migration: %v", err)
	}
	if retrieved2.Title != "Title 1" {
		t.Errorf("Data double-encrypted or corrupted after second migration: got %q, want %q", retrieved2.Title, "Title 1")
	}
}
