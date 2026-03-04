package store

import (
	"mnemosyne/internal/crypto"
	"mnemosyne/internal/domain"
	"path/filepath"
	"testing"
	"time"
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

func TestChangePassword(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "changepwd.db")

	s, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer s.Close()

	// 1. Setup encryption and create entry
	_, err = s.SetupEncryption([]byte("old-password"))
	if err != nil {
		t.Fatalf("SetupEncryption failed: %v", err)
	}

	entry := &domain.Entry{
		Title: "Test Title",
		Body:  "Test Body Content",
	}
	if err := s.CreateEntry(entry); err != nil {
		t.Fatalf("CreateEntry failed: %v", err)
	}

	// 2. Change password
	newKey, err := s.ChangePassword([]byte("old-password"), []byte("new-password"))
	if err != nil {
		t.Fatalf("ChangePassword failed: %v", err)
	}
	crypto.Zero(newKey)

	// 3. Simulate lock
	s.SetKey(nil)

	// 4. Unlock with new password
	dataKey, err := s.Unlock([]byte("new-password"))
	if err != nil {
		t.Fatalf("Unlock with new password failed: %v", err)
	}
	defer crypto.Zero(dataKey)
	s.SetKey(dataKey)

	// 5. Verify entry is readable and matches original
	retrieved, err := s.GetEntry(entry.ID)
	if err != nil {
		t.Fatalf("GetEntry failed after password change: %v", err)
	}
	if retrieved.Title != entry.Title {
		t.Errorf("Title mismatch after password change: got %q, want %q", retrieved.Title, entry.Title)
	}
	if retrieved.Body != entry.Body {
		t.Errorf("Body mismatch after password change: got %q, want %q", retrieved.Body, entry.Body)
	}

	// Negative case: old password no longer works
	s.SetKey(nil)
	oldKey, err := s.Unlock([]byte("old-password"))
	if oldKey != nil {
		crypto.Zero(oldKey)
	}
	if err != ErrWrongPassword {
		t.Errorf("Expected ErrWrongPassword for old password after change, got %v", err)
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

func TestGetArchiveMeta_Empty(t *testing.T) {
	s, _ := NewSQLiteStore(filepath.Join(t.TempDir(), "meta_empty.db"))
	defer s.Close()

	meta, err := s.GetArchiveMeta()
	if err != nil {
		t.Fatalf("GetArchiveMeta on empty DB: %v", err)
	}
	if meta.TotalEntries != 0 || meta.TotalWords != 0 || meta.CurrentStreak != 0 || meta.LongestStreak != 0 {
		t.Errorf("expected all zeros on empty DB, got %+v", meta)
	}
}

func TestGetArchiveMeta(t *testing.T) {
	s, err := NewSQLiteStore(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer s.Close()

	now := time.Now()
	// noon local — avoids timezone boundary issues in streak date normalization
	day := func(offset int) time.Time {
		d := now.AddDate(0, 0, offset)
		return time.Date(d.Year(), d.Month(), d.Day(), 12, 0, 0, 0, time.Local)
	}

	// Entries: days -5,-4,-3 (streak of 3), gap at -2, days -1,0 (current streak of 2)
	entries := []struct {
		date  time.Time
		words int
	}{
		{day(-5), 100},
		{day(-4), 200},
		{day(-3), 150},
		{day(-1), 250},
		{day(0), 300},
	}
	for _, e := range entries {
		if _, err := s.db.Exec(
			"INSERT INTO entries (title, body, word_count, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
			"title", "body", e.words, e.date, e.date,
		); err != nil {
			t.Fatalf("insert entry: %v", err)
		}
	}
	// entry IDs are 1-5

	// One writing session: 90 seconds active
	if _, err := s.db.Exec(
		"INSERT INTO writing_sessions (entry_id, started_at, elapsed_active_ms, words_added) VALUES (?, ?, ?, ?)",
		1, day(0), 90000, 300,
	); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	// session ID is 1

	// Triggers on entry 1: MOOD x3, ENERGY x1
	for i, prefix := range []string{"MOOD", "MOOD", "ENERGY", "MOOD"} {
		if _, err := s.db.Exec(
			"INSERT INTO entry_triggers (entry_id, session_id, line_no, prefix, payload, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			1, 1, i+1, prefix, "value", day(0),
		); err != nil {
			t.Fatalf("insert trigger: %v", err)
		}
	}

	meta, err := s.GetArchiveMeta()
	if err != nil {
		t.Fatalf("GetArchiveMeta: %v", err)
	}

	if meta.TotalEntries != 5 {
		t.Errorf("TotalEntries: got %d, want 5", meta.TotalEntries)
	}
	if meta.TotalWords != 1000 {
		t.Errorf("TotalWords: got %d, want 1000", meta.TotalWords)
	}
	if meta.AvgWordsPerEntry != 200 {
		t.Errorf("AvgWordsPerEntry: got %d, want 200", meta.AvgWordsPerEntry)
	}
	if meta.TotalActiveMs != 90000 {
		t.Errorf("TotalActiveMs: got %d, want 90000", meta.TotalActiveMs)
	}

	if len(meta.TopTriggers) != 2 {
		t.Fatalf("TopTriggers count: got %d, want 2", len(meta.TopTriggers))
	}
	if meta.TopTriggers[0].Prefix != "MOOD" || meta.TopTriggers[0].Count != 3 {
		t.Errorf("TopTriggers[0]: got %+v, want {MOOD 3}", meta.TopTriggers[0])
	}
	if meta.TopTriggers[1].Prefix != "ENERGY" || meta.TopTriggers[1].Count != 1 {
		t.Errorf("TopTriggers[1]: got %+v, want {ENERGY 1}", meta.TopTriggers[1])
	}

	// days -5,-4,-3 = longest run of 3; gap at -2; days -1,0 = current streak of 2
	if meta.LongestStreak != 3 {
		t.Errorf("LongestStreak: got %d, want 3", meta.LongestStreak)
	}
	if meta.CurrentStreak != 2 {
		t.Errorf("CurrentStreak: got %d, want 2", meta.CurrentStreak)
	}
}
