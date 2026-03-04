package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"mnemosyne/internal/crypto"
	"mnemosyne/internal/domain"
	"sort"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

var ErrEntryDeleted = errors.New("entry deleted")
var ErrEntryNotFound = errors.New("entry not found")
var ErrWrongPassword = errors.New("incorrect password")

type SQLiteStore struct {
	db      *sql.DB
	writeMu sync.Mutex
	keyMu   sync.RWMutex
	dataKey []byte // nil if encryption not enabled
}

func (s *SQLiteStore) SetKey(dataKey []byte) {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	
	// Zero existing key before replacing or nullifying
	if s.dataKey != nil {
		crypto.Zero(s.dataKey)
	}

	if dataKey == nil {
		s.dataKey = nil
		return
	}
	s.dataKey = make([]byte, len(dataKey))
	copy(s.dataKey, dataKey)
}

// getKey returns a defensive copy of the data key.
// Callers should call crypto.Zero() on the returned slice when done.
func (s *SQLiteStore) getKey() []byte {
	s.keyMu.RLock()
	defer s.keyMu.RUnlock()
	if s.dataKey == nil {
		return nil
	}
	cp := make([]byte, len(s.dataKey))
	copy(cp, s.dataKey)
	return cp
}

func (s *SQLiteStore) encryptField(table, field string, rowID int64, plaintext string) ([]byte, error) {
	key := s.getKey()
	if key == nil {
		return []byte(plaintext), nil
	}
	defer crypto.Zero(key)
	aad := crypto.FormatAAD(table, field, rowID)
	return crypto.Encrypt(key, []byte(plaintext), aad)
}

func (s *SQLiteStore) decryptField(table, field string, rowID int64, ciphertext []byte) (string, error) {
	key := s.getKey()
	if key == nil {
		return string(ciphertext), nil
	}
	defer crypto.Zero(key)
	aad := crypto.FormatAAD(table, field, rowID)
	plaintext, err := crypto.Decrypt(key, ciphertext, aad)
	if err != nil {
		return "", err
	}
	res := string(plaintext)
	crypto.Zero(plaintext)
	return res, nil
}

// decryptWithKey is a helper for snapshot/migration where we already have the key copy.
func (s *SQLiteStore) decryptWithKey(key []byte, table, field string, rowID int64, ciphertext []byte) ([]byte, error) {
	if key == nil {
		cp := make([]byte, len(ciphertext))
		copy(cp, ciphertext)
		return cp, nil
	}
	aad := crypto.FormatAAD(table, field, rowID)
	return crypto.Decrypt(key, ciphertext, aad)
}

func (s *SQLiteStore) IsEncryptionEnabled() (bool, error) {
	var val string
	err := s.db.QueryRow("SELECT value FROM config WHERE key = 'encryption_enabled'").Scan(&val)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return val == "1", nil
}

func (s *SQLiteStore) SetupEncryption(password []byte) ([]byte, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	defer crypto.Zero(password)

	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	m := uint32(65536)
	t := uint32(3)
	p := uint8(1)

	dataKey, verifyKey, err := crypto.DeriveKeys(password, salt, m, t, p)
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(verifyKey)

	// Encrypt sentinel "mnemosyne-ok"
	aad := crypto.FormatAAD("config", "sentinel", 0)
	encSentinel, err := crypto.Encrypt(verifyKey, []byte("mnemosyne-ok"), aad)
	if err != nil {
		crypto.Zero(dataKey)
		return nil, err
	}

	tx, err := s.db.Begin()
	if err != nil {
		crypto.Zero(dataKey)
		return nil, err
	}
	defer tx.Rollback()

	params := map[string]interface{}{
		"argon2_salt":        salt,
		"argon2_m":           m,
		"argon2_t":           t,
		"argon2_p":           uint32(p),
		"sentinel":           encSentinel,
		"encryption_enabled": "1",
	}

	for k, v := range params {
		var valToStore interface{} = v
		if u, ok := v.(uint32); ok {
			b := make([]byte, 4)
			binary.LittleEndian.PutUint32(b, u)
			valToStore = b
		}
		_, err = tx.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", k, valToStore)
		if err != nil {
			crypto.Zero(dataKey)
			return nil, err
		}
	}

	if _, err := tx.Exec("DELETE FROM entries_fts"); err != nil {
		crypto.Zero(dataKey)
		return nil, err
	}

	if err := s.migrateToEncrypted(tx, dataKey); err != nil {
		crypto.Zero(dataKey)
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		crypto.Zero(dataKey)
		return nil, err
	}

	s.SetKey(dataKey)
	return dataKey, nil
}

func (s *SQLiteStore) Unlock(password []byte) ([]byte, error) {
	defer crypto.Zero(password)
	var salt, encSentinel []byte
	var mBytes, tBytes, pBytes []byte

	err := s.db.QueryRow("SELECT value FROM config WHERE key = 'argon2_salt'").Scan(&salt)
	if err != nil {
		return nil, err
	}
	err = s.db.QueryRow("SELECT value FROM config WHERE key = 'argon2_m'").Scan(&mBytes)
	if err != nil {
		return nil, err
	}
	err = s.db.QueryRow("SELECT value FROM config WHERE key = 'argon2_t'").Scan(&tBytes)
	if err != nil {
		return nil, err
	}
	err = s.db.QueryRow("SELECT value FROM config WHERE key = 'argon2_p'").Scan(&pBytes)
	if err != nil {
		return nil, err
	}
	err = s.db.QueryRow("SELECT value FROM config WHERE key = 'sentinel'").Scan(&encSentinel)
	if err != nil {
		return nil, err
	}

	m := binary.LittleEndian.Uint32(mBytes)
	t := binary.LittleEndian.Uint32(tBytes)
	p := binary.LittleEndian.Uint32(pBytes)

	dataKey, verifyKey, err := crypto.DeriveKeys(password, salt, m, t, uint8(p))
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(verifyKey)

	aad := crypto.FormatAAD("config", "sentinel", 0)
	decSentinel, err := crypto.Decrypt(verifyKey, encSentinel, aad)
	if err != nil {
		crypto.Zero(dataKey)
		return nil, ErrWrongPassword
	}
	defer crypto.Zero(decSentinel)

	if string(decSentinel) != "mnemosyne-ok" {
		crypto.Zero(dataKey)
		return nil, ErrWrongPassword
	}

	return dataKey, nil
}

func (s *SQLiteStore) migrateToEncrypted(tx *sql.Tx, dataKey []byte) error {
	var migrated string
	_ = tx.QueryRow("SELECT value FROM config WHERE key = 'data_migrated'").Scan(&migrated)
	if migrated == "1" {
		return nil
	}

	rows, err := tx.Query("SELECT id, title, body FROM entries")
	if err != nil {
		return err
	}
	defer rows.Close()

	type entryUpdate struct {
		id    int64
		title []byte
		body  []byte
	}
	var entriesToUpdate []entryUpdate
	for rows.Next() {
		var id int64
		var title, body interface{}
		if err := rows.Scan(&id, &title, &body); err != nil {
			return err
		}

		var tBytes, bBytes []byte
		isTitleEnc := false
		isBodyEnc := false

		if b, ok := title.([]byte); ok && len(b) > 0 && b[0] == crypto.Version1 {
			isTitleEnc = true
		} else if str, ok := title.(string); ok {
			tBytes = []byte(str)
		}

		if b, ok := body.([]byte); ok && len(b) > 0 && b[0] == crypto.Version1 {
			isBodyEnc = true
		} else if str, ok := body.(string); ok {
			bBytes = []byte(str)
		}

		if isTitleEnc && isBodyEnc {
			continue
		}

		var encTitle, encBody []byte
		if !isTitleEnc {
			aadT := crypto.FormatAAD("entries", "title", id)
			var err error
			encTitle, err = crypto.Encrypt(dataKey, tBytes, aadT)
			if err != nil { return err }
		} else {
			encTitle = title.([]byte)
		}
		
		if !isBodyEnc {
			aadB := crypto.FormatAAD("entries", "body", id)
			var err error
			encBody, err = crypto.Encrypt(dataKey, bBytes, aadB)
			if err != nil { return err }
		} else {
			encBody = body.([]byte)
		}

		entriesToUpdate = append(entriesToUpdate, entryUpdate{id, encTitle, encBody})
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()

	for _, u := range entriesToUpdate {
		_, err = tx.Exec("UPDATE entries SET title = ?, body = ? WHERE id = ?", u.title, u.body, u.id)
		if err != nil {
			return err
		}
	}

	trows, err := tx.Query("SELECT id, payload FROM entry_triggers")
	if err != nil {
		return err
	}
	defer trows.Close()

	type triggerUpdate struct {
		id      int64
		payload []byte
	}
	var triggersToUpdate []triggerUpdate
	for trows.Next() {
		var id int64
		var payload interface{}
		if err := trows.Scan(&id, &payload); err != nil {
			return err
		}

		if b, ok := payload.([]byte); ok && len(b) > 0 && b[0] == crypto.Version1 {
			continue
		}

		var pBytes []byte
		if str, ok := payload.(string); ok { pBytes = []byte(str) }

		aadP := crypto.FormatAAD("entry_triggers", "payload", id)
		encPayload, err := crypto.Encrypt(dataKey, pBytes, aadP)
		if err != nil { return err }
		triggersToUpdate = append(triggersToUpdate, triggerUpdate{id, encPayload})
	}
	if err := trows.Err(); err != nil {
		return err
	}
	trows.Close()

	for _, u := range triggersToUpdate {
		_, err = tx.Exec("UPDATE entry_triggers SET payload = ? WHERE id = ?", u.payload, u.id)
		if err != nil {
			return err
		}
	}

	_, err = tx.Exec("INSERT OR REPLACE INTO config (key, value) VALUES ('data_migrated', '1')")
	return err
}

func (s *SQLiteStore) reEncryptData(tx *sql.Tx, oldKey, newKey []byte) error {
	rows, err := tx.Query("SELECT id, title, body FROM entries")
	if err != nil {
		return err
	}
	defer rows.Close()

	type entryUpdate struct {
		id    int64
		title []byte
		body  []byte
	}
	var entriesToUpdate []entryUpdate
	for rows.Next() {
		var id int64
		var title, body interface{}
		if err := rows.Scan(&id, &title, &body); err != nil {
			return err
		}

		var plainTitle, plainBody []byte
		if b, ok := title.([]byte); ok {
			var err error
			plainTitle, err = s.decryptWithKey(oldKey, "entries", "title", id, b)
			if err != nil {
				return fmt.Errorf("re-encrypt: decrypt title %d: %w", id, err)
			}
		} else if str, ok := title.(string); ok {
			plainTitle = []byte(str)
		}
		if b, ok := body.([]byte); ok {
			var err error
			plainBody, err = s.decryptWithKey(oldKey, "entries", "body", id, b)
			if err != nil {
				return fmt.Errorf("re-encrypt: decrypt body %d: %w", id, err)
			}
		} else if str, ok := body.(string); ok {
			plainBody = []byte(str)
		}

		aadT := crypto.FormatAAD("entries", "title", id)
		encTitle, err := crypto.Encrypt(newKey, plainTitle, aadT)
		crypto.Zero(plainTitle)
		if err != nil {
			return fmt.Errorf("re-encrypt: encrypt title %d: %w", id, err)
		}
		aadB := crypto.FormatAAD("entries", "body", id)
		encBody, err := crypto.Encrypt(newKey, plainBody, aadB)
		crypto.Zero(plainBody)
		if err != nil {
			return fmt.Errorf("re-encrypt: encrypt body %d: %w", id, err)
		}

		entriesToUpdate = append(entriesToUpdate, entryUpdate{id, encTitle, encBody})
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()

	for _, u := range entriesToUpdate {
		if _, err := tx.Exec("UPDATE entries SET title = ?, body = ? WHERE id = ?", u.title, u.body, u.id); err != nil {
			return err
		}
	}

	trows, err := tx.Query("SELECT id, payload FROM entry_triggers")
	if err != nil {
		return err
	}
	defer trows.Close()

	type triggerUpdate struct {
		id      int64
		payload []byte
	}
	var triggersToUpdate []triggerUpdate
	for trows.Next() {
		var id int64
		var payload interface{}
		if err := trows.Scan(&id, &payload); err != nil {
			return err
		}

		var plainPayload []byte
		if b, ok := payload.([]byte); ok {
			var err error
			plainPayload, err = s.decryptWithKey(oldKey, "entry_triggers", "payload", id, b)
			if err != nil {
				return fmt.Errorf("re-encrypt: decrypt payload %d: %w", id, err)
			}
		} else if str, ok := payload.(string); ok {
			plainPayload = []byte(str)
		}

		aadP := crypto.FormatAAD("entry_triggers", "payload", id)
		encPayload, err := crypto.Encrypt(newKey, plainPayload, aadP)
		crypto.Zero(plainPayload)
		if err != nil {
			return fmt.Errorf("re-encrypt: encrypt payload %d: %w", id, err)
		}
		triggersToUpdate = append(triggersToUpdate, triggerUpdate{id, encPayload})
	}
	if err := trows.Err(); err != nil {
		return err
	}
	trows.Close()

	for _, u := range triggersToUpdate {
		if _, err := tx.Exec("UPDATE entry_triggers SET payload = ? WHERE id = ?", u.payload, u.id); err != nil {
			return err
		}
	}

	return nil
}

func (s *SQLiteStore) ChangePassword(oldPassword, newPassword []byte) ([]byte, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	defer crypto.Zero(oldPassword)
	defer crypto.Zero(newPassword)

	currentDataKey, err := s.Unlock(oldPassword)
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(currentDataKey)

	newSalt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, newSalt); err != nil {
		return nil, err
	}

	m := uint32(65536)
	t := uint32(3)
	p := uint8(1)

	dataKey, verifyKey, err := crypto.DeriveKeys(newPassword, newSalt, m, t, p)
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(verifyKey)

	aad := crypto.FormatAAD("config", "sentinel", 0)
	encSentinel, err := crypto.Encrypt(verifyKey, []byte("mnemosyne-ok"), aad)
	if err != nil {
		crypto.Zero(dataKey)
		return nil, err
	}

	tx, err := s.db.Begin()
	if err != nil {
		crypto.Zero(dataKey)
		return nil, err
	}
	defer tx.Rollback()

	params := map[string]interface{}{
		"argon2_salt": newSalt,
		"argon2_m":    m,
		"argon2_t":    t,
		"argon2_p":    uint32(p),
		"sentinel":    encSentinel,
	}

	for k, v := range params {
		var valToStore interface{} = v
		if u, ok := v.(uint32); ok {
			b := make([]byte, 4)
			binary.LittleEndian.PutUint32(b, u)
			valToStore = b
		}
		_, err = tx.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", k, valToStore)
		if err != nil {
			crypto.Zero(dataKey)
			return nil, err
		}
	}

	if err := s.reEncryptData(tx, currentDataKey, dataKey); err != nil {
		crypto.Zero(dataKey)
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		crypto.Zero(dataKey)
		return nil, err
	}

	s.SetKey(dataKey)
	_ = s.Vacuum()

	return dataKey, nil
}

func (s *SQLiteStore) Vacuum() error {
	_, err := s.db.Exec("PRAGMA wal_checkpoint(FULL)")
	if err != nil {
		return err
	}
	_, err = s.db.Exec("VACUUM")
	return err
}

func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(1)

	pragmas := []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA synchronous = NORMAL",
		"PRAGMA foreign_keys = ON",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			return nil, err
		}
	}

	store := &SQLiteStore{db: db}
	if err := store.initSchema(); err != nil {
		return nil, err
	}

	var result string
	_ = db.QueryRow("PRAGMA integrity_check").Scan(&result)
	if result != "ok" {
		return nil, fmt.Errorf("database integrity check failed: %s", result)
	}

	return store, nil
}

func (s *SQLiteStore) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS entries (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		title TEXT,
		body TEXT NOT NULL,
		word_count INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);

	CREATE VIRTUAL TABLE IF NOT EXISTS entries_fts USING fts5(title, body);

	CREATE TABLE IF NOT EXISTS writing_sessions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		entry_id INTEGER NOT NULL,
		started_at DATETIME NOT NULL,
		ended_at DATETIME,
		elapsed_active_ms INTEGER NOT NULL DEFAULT 0,
		words_added INTEGER NOT NULL DEFAULT 0,
		FOREIGN KEY(entry_id) REFERENCES entries(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS entry_triggers (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		entry_id INTEGER NOT NULL,
		session_id INTEGER,
		line_no INTEGER NOT NULL,
		prefix TEXT NOT NULL,
		payload TEXT,
		created_at DATETIME NOT NULL,
		FOREIGN KEY(entry_id) REFERENCES entries(id) ON DELETE CASCADE,
		FOREIGN KEY(session_id) REFERENCES writing_sessions(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS deleted_entries (
		entry_id INTEGER PRIMARY KEY,
		deleted_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS config (
		key   TEXT PRIMARY KEY,
		value BLOB NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_entry_triggers_entry_id ON entry_triggers(entry_id);
	`
	_, err := s.db.Exec(schema)
	return err
}

func (s *SQLiteStore) CreateEntry(entry *domain.Entry) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := time.Now()
	res, err := tx.Exec("INSERT INTO entries (title, body, word_count, created_at, updated_at) VALUES (?, ?, ?, ?, ?)", entry.Title, entry.Body, entry.WordCount, now, now)
	if err != nil {
		return err
	}
	id, _ := res.LastInsertId()

	if s.getKey() != nil {
		encTitle, err := s.encryptField("entries", "title", id, entry.Title)
		if err != nil {
			return err
		}
		encBody, err := s.encryptField("entries", "body", id, entry.Body)
		if err != nil {
			return err
		}
		_, err = tx.Exec("UPDATE entries SET title = ?, body = ? WHERE id = ?", encTitle, encBody, id)
		if err != nil {
			return err
		}
	} else {
		_, err = tx.Exec("INSERT INTO entries_fts(rowid, title, body) VALUES (?, ?, ?)", id, entry.Title, entry.Body)
		if err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	entry.ID = id
	entry.CreatedAt = now
	entry.UpdatedAt = now
	return nil
}

func (s *SQLiteStore) CreateSession(sess *domain.WritingSession) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	var tombstoned int
	_ = s.db.QueryRow("SELECT 1 FROM deleted_entries WHERE entry_id = ?", sess.EntryID).Scan(&tombstoned)
	if tombstoned == 1 {
		return ErrEntryDeleted
	}
	res, err := s.db.Exec("INSERT INTO writing_sessions (entry_id, started_at, elapsed_active_ms, words_added) VALUES (?, ?, ?, ?)", sess.EntryID, sess.StartedAt, int64(sess.ElapsedActive/time.Millisecond), sess.WordsAdded)
	if err != nil {
		return err
	}
	id, _ := res.LastInsertId()
	sess.ID = id
	return nil
}

func (s *SQLiteStore) SaveAll(entry *domain.Entry, sess *domain.WritingSession, trigs []domain.Trigger) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var bodyToStore interface{} = entry.Body
	var titleToStore interface{} = entry.Title
	if s.getKey() != nil {
		encBody, err := s.encryptField("entries", "body", entry.ID, entry.Body)
		if err != nil {
			return err
		}
		bodyToStore = encBody

		encTitle, err := s.encryptField("entries", "title", entry.ID, entry.Title)
		if err != nil {
			return err
		}
		titleToStore = encTitle
	}

	res, err := tx.Exec("UPDATE entries SET title = ?, body = ?, word_count = ?, updated_at = ? WHERE id = ? AND NOT EXISTS (SELECT 1 FROM deleted_entries WHERE entry_id = ?)", titleToStore, bodyToStore, entry.WordCount, time.Now(), entry.ID, entry.ID)
	if err != nil {
		return err
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return ErrEntryDeleted
	}

	if _, err := tx.Exec("UPDATE writing_sessions SET ended_at = ?, elapsed_active_ms = ?, words_added = ? WHERE id = ?", sess.EndedAt, int64(sess.ElapsedActive/time.Millisecond), sess.WordsAdded, sess.ID); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM entry_triggers WHERE entry_id = ? AND session_id = ?", entry.ID, sess.ID); err != nil {
		return err
	}
	for _, t := range trigs {
		if s.getKey() != nil {
			res, err := tx.Exec("INSERT INTO entry_triggers (entry_id, session_id, line_no, prefix, payload, created_at) VALUES (?, ?, ?, ?, ?, ?)", entry.ID, sess.ID, t.LineNo, t.Prefix, "", t.CreatedAt)
			if err != nil {
				return err
			}
			tid, _ := res.LastInsertId()
			encPayload, err := s.encryptField("entry_triggers", "payload", tid, t.Payload)
			if err != nil {
				return err
			}
			_, err = tx.Exec("UPDATE entry_triggers SET payload = ? WHERE id = ?", encPayload, tid)
			if err != nil {
				return err
			}
		} else {
			_, err = tx.Exec("INSERT INTO entry_triggers (entry_id, session_id, line_no, prefix, payload, created_at) VALUES (?, ?, ?, ?, ?, ?)", entry.ID, sess.ID, t.LineNo, t.Prefix, t.Payload, t.CreatedAt)
			if err != nil {
				return err
			}
		}
	}

	if s.getKey() == nil {
		if _, err := tx.Exec("DELETE FROM entries_fts WHERE rowid = ?", entry.ID); err != nil {
			return err
		}
		if _, err := tx.Exec("INSERT INTO entries_fts(rowid, title, body) VALUES (?, ?, ?)", entry.ID, entry.Title, entry.Body); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *SQLiteStore) GetEntries() ([]domain.Entry, error) {
	rows, err := s.db.Query("SELECT id, title, word_count, created_at FROM entries ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []domain.Entry
	for rows.Next() {
		var e domain.Entry
		var title interface{}
		if err := rows.Scan(&e.ID, &title, &e.WordCount, &e.CreatedAt); err != nil {
			return nil, err
		}

		if s.getKey() != nil {
			if b, ok := title.([]byte); ok {
				decTitle, err := s.decryptField("entries", "title", e.ID, b)
				if err != nil {
					return nil, err
				}
				e.Title = decTitle
			} else if str, ok := title.(string); ok {
				e.Title = str
			}
		} else {
			if str, ok := title.(string); ok {
				e.Title = str
			}
		}

		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func (s *SQLiteStore) GetEntry(id int64) (*domain.Entry, error) {
	var e domain.Entry
	var title, body interface{}
	err := s.db.QueryRow("SELECT id, title, body, word_count, created_at FROM entries WHERE id = ?", id).Scan(&e.ID, &title, &body, &e.WordCount, &e.CreatedAt)
	if err != nil {
		return nil, err
	}

	if s.getKey() != nil {
		if b, ok := title.([]byte); ok {
			var decErr error
			e.Title, decErr = s.decryptField("entries", "title", e.ID, b)
			if decErr != nil {
				return nil, decErr
			}
		} else if str, ok := title.(string); ok {
			e.Title = str
		}
		if b, ok := body.([]byte); ok {
			var decErr error
			e.Body, decErr = s.decryptField("entries", "body", e.ID, b)
			if decErr != nil {
				return nil, decErr
			}
		} else if str, ok := body.(string); ok {
			e.Body = str
		}
	} else {
		if str, ok := title.(string); ok {
			e.Title = str
		}
		if str, ok := body.(string); ok {
			e.Body = str
		}
	}

	return &e, nil
}

func (s *SQLiteStore) SearchEntries(query string) ([]domain.Entry, error) {
	if s.getKey() == nil {
		rows, err := s.db.Query(`
			SELECT id, title, word_count, created_at 
			FROM entries 
			WHERE id IN (SELECT rowid FROM entries_fts WHERE entries_fts MATCH ?)
			ORDER BY (SELECT rank FROM entries_fts WHERE rowid = entries.id AND entries_fts MATCH ?)`, query+"*", query+"*")
		if err != nil {
			return nil, fmt.Errorf("search failed: %w", err)
		}
		defer rows.Close()
		var entries []domain.Entry
		for rows.Next() {
			var e domain.Entry
			var title interface{}
			if err := rows.Scan(&e.ID, &title, &e.WordCount, &e.CreatedAt); err != nil {
				return nil, err
			}
			if str, ok := title.(string); ok {
				e.Title = str
			}
			entries = append(entries, e)
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return entries, nil
	}

	rows, err := s.db.Query("SELECT id, title, body, word_count, created_at FROM entries")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []domain.Entry
	q := strings.ToLower(query)
	for rows.Next() {
		var e domain.Entry
		var title, body interface{}
		if err := rows.Scan(&e.ID, &title, &body, &e.WordCount, &e.CreatedAt); err != nil {
			return nil, err
		}

		var decTitle, decBody string
		if b, ok := title.([]byte); ok {
			plain, err := s.decryptWithKey(s.dataKey, "entries", "title", e.ID, b)
			if err != nil { return nil, err }
			decTitle = string(plain)
			crypto.Zero(plain)
		} else if str, ok := title.(string); ok {
			decTitle = str
		}

		if b, ok := body.([]byte); ok {
			plain, err := s.decryptWithKey(s.dataKey, "entries", "body", e.ID, b)
			if err != nil { return nil, err }
			decBody = string(plain)
			crypto.Zero(plain)
		} else if str, ok := body.(string); ok {
			decBody = str
		}

		if strings.Contains(strings.ToLower(decTitle), q) || strings.Contains(strings.ToLower(decBody), q) {
			e.Title = decTitle
			entries = append(entries, e)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func (s *SQLiteStore) GetLatestTriggers(entryID int64) ([]domain.Trigger, error) {
	rows, err := s.db.Query("SELECT id, prefix, payload FROM entry_triggers WHERE entry_id = ? ORDER BY created_at DESC", entryID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var triggers []domain.Trigger
	seen := make(map[string]bool)
	for rows.Next() {
		var t domain.Trigger
		var payload interface{}
		if err := rows.Scan(&t.ID, &t.Prefix, &payload); err != nil {
			return nil, err
		}
		if !seen[t.Prefix] {
			if s.getKey() != nil {
				if b, ok := payload.([]byte); ok {
					var decErr error
					t.Payload, decErr = s.decryptField("entry_triggers", "payload", t.ID, b)
					if decErr != nil {
						return nil, decErr
					}
				} else if str, ok := payload.(string); ok {
					t.Payload = str
				}
			} else {
				if str, ok := payload.(string); ok {
					t.Payload = str
				}
			}
			triggers = append(triggers, t)
			seen[t.Prefix] = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return triggers, nil
}

func (s *SQLiteStore) GetArgon2Params() (m, t uint32, p uint8, salt []byte, err error) {
	var mBytes, tBytes, pBytes []byte
	err = s.db.QueryRow("SELECT value FROM config WHERE key = 'argon2_salt'").Scan(&salt)
	if err != nil { return }
	err = s.db.QueryRow("SELECT value FROM config WHERE key = 'argon2_m'").Scan(&mBytes)
	if err != nil { return }
	err = s.db.QueryRow("SELECT value FROM config WHERE key = 'argon2_t'").Scan(&tBytes)
	if err != nil { return }
	err = s.db.QueryRow("SELECT value FROM config WHERE key = 'argon2_p'").Scan(&pBytes)
	if err != nil { return }

	m = binary.LittleEndian.Uint32(mBytes)
	t = binary.LittleEndian.Uint32(tBytes)
	p = uint8(binary.LittleEndian.Uint32(pBytes))
	return
}

func (s *SQLiteStore) ExportData(key []byte) ([]domain.Entry, []domain.Trigger, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()

	rows, err := tx.Query("SELECT id, title, body, word_count, created_at FROM entries")
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var entries []domain.Entry
	for rows.Next() {
		var e domain.Entry
		var title, body interface{}
		if err := rows.Scan(&e.ID, &title, &body, &e.WordCount, &e.CreatedAt); err != nil {
			return nil, nil, err
		}

		if key != nil {
			if b, ok := title.([]byte); ok {
				plain, err := s.decryptWithKey(key, "entries", "title", e.ID, b)
				if err != nil { return nil, nil, err }
				e.Title = string(plain)
				crypto.Zero(plain)
			} else if str, ok := title.(string); ok {
				e.Title = str
			}
			if b, ok := body.([]byte); ok {
				plain, err := s.decryptWithKey(key, "entries", "body", e.ID, b)
				if err != nil { return nil, nil, err }
				e.Body = string(plain)
				crypto.Zero(plain)
			} else if str, ok := body.(string); ok {
				e.Body = str
			}
		} else {
			if str, ok := title.(string); ok { e.Title = str }
			if str, ok := body.(string); ok { e.Body = str }
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	rows.Close()

	trows, err := tx.Query("SELECT id, entry_id, session_id, line_no, prefix, payload, created_at FROM entry_triggers")
	if err != nil {
		return nil, nil, err
	}
	defer trows.Close()

	var triggers []domain.Trigger
	for trows.Next() {
		var t domain.Trigger
		var payload interface{}
		if err := trows.Scan(&t.ID, &t.EntryID, &t.SessionID, &t.LineNo, &t.Prefix, &payload, &t.CreatedAt); err != nil {
			return nil, nil, err
		}

		if key != nil {
			if b, ok := payload.([]byte); ok {
				plain, err := s.decryptWithKey(key, "entry_triggers", "payload", t.ID, b)
				if err != nil { return nil, nil, err }
				t.Payload = string(plain)
				crypto.Zero(plain)
			} else if str, ok := payload.(string); ok {
				t.Payload = str
			}
		} else {
			if str, ok := payload.(string); ok { t.Payload = str }
		}
		triggers = append(triggers, t)
	}
	if err := trows.Err(); err != nil {
		return nil, nil, err
	}

	return entries, triggers, nil
}

func (s *SQLiteStore) GetNextSnapshotID() (uint64, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	var val []byte
	err := s.db.QueryRow("SELECT value FROM config WHERE key = 'last_snapshot_id'").Scan(&val)
	var next uint64 = 1
	if err == nil {
		next = binary.LittleEndian.Uint64(val) + 1
	} else if err != sql.ErrNoRows {
		return 0, err
	}

	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, next)
	_, err = s.db.Exec("INSERT OR REPLACE INTO config (key, value) VALUES ('last_snapshot_id', ?)", buf)
	if err != nil {
		return 0, err
	}

	return next, nil
}

func (s *SQLiteStore) ImportEntry(entry domain.Entry) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if s.getKey() != nil {
		encTitle, err := s.encryptField("entries", "title", entry.ID, entry.Title)
		if err != nil { return err }
		encBody, err := s.encryptField("entries", "body", entry.ID, entry.Body)
		if err != nil { return err }
		_, err = tx.Exec("INSERT INTO entries (id, title, body, word_count, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
			entry.ID, encTitle, encBody, entry.WordCount, entry.CreatedAt, entry.CreatedAt)
		if err != nil { return err }
	} else {
		_, err = tx.Exec("INSERT INTO entries (id, title, body, word_count, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
			entry.ID, entry.Title, entry.Body, entry.WordCount, entry.CreatedAt, entry.CreatedAt)
		if err != nil { return err }
		_, err = tx.Exec("INSERT INTO entries_fts(rowid, title, body) VALUES (?, ?, ?)", entry.ID, entry.Title, entry.Body)
		if err != nil { return err }
	}

	return tx.Commit()
}

func (s *SQLiteStore) ImportTrigger(t domain.Trigger) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if s.getKey() != nil {
		encPayload, err := s.encryptField("entry_triggers", "payload", t.ID, t.Payload)
		if err != nil { return err }
		_, err = tx.Exec("INSERT INTO entry_triggers (id, entry_id, session_id, line_no, prefix, payload, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
			t.ID, t.EntryID, t.SessionID, t.LineNo, t.Prefix, encPayload, t.CreatedAt)
		if err != nil { return err }
	} else {
		_, err = tx.Exec("INSERT INTO entry_triggers (id, entry_id, session_id, line_no, prefix, payload, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
			t.ID, t.EntryID, t.SessionID, t.LineNo, t.Prefix, t.Payload, t.CreatedAt)
		if err != nil { return err }
	}

	return tx.Commit()
}

func (s *SQLiteStore) SetupRestore(password []byte, salt []byte, m, t uint32, p uint8) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	defer crypto.Zero(password)

	dataKey, verifyKey, err := crypto.DeriveKeys(password, salt, m, t, p)
	if err != nil {
		return err
	}
	defer crypto.Zero(dataKey)
	defer crypto.Zero(verifyKey)

	aad := crypto.FormatAAD("config", "sentinel", 0)
	encSentinel, err := crypto.Encrypt(verifyKey, []byte("mnemosyne-ok"), aad)
	if err != nil {
		return err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	params := map[string]interface{}{
		"argon2_salt":        salt,
		"argon2_m":           m,
		"argon2_t":           t,
		"argon2_p":           uint32(p),
		"sentinel":           encSentinel,
		"encryption_enabled": "1",
		"data_migrated":      "1",
	}

	for k, v := range params {
		var valToStore interface{} = v
		if u, ok := v.(uint32); ok {
			b := make([]byte, 4)
			binary.LittleEndian.PutUint32(b, u)
			valToStore = b
		}
		_, err = tx.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", k, valToStore)
		if err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	s.SetKey(dataKey)
	return nil
}

func parseDriverTime(s string) (time.Time, error) {
	formats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse datetime %q", s)
}

func (s *SQLiteStore) GetArchiveMeta() (*domain.ArchiveMeta, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	meta := &domain.ArchiveMeta{}

	var firstStr, lastStr sql.NullString
	err = tx.QueryRow("SELECT COUNT(*), COALESCE(SUM(word_count), 0), MIN(created_at), MAX(created_at) FROM entries").
		Scan(&meta.TotalEntries, &meta.TotalWords, &firstStr, &lastStr)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	if firstStr.Valid && firstStr.String != "" {
		if t, parseErr := parseDriverTime(firstStr.String); parseErr == nil {
			meta.FirstEntryAt = t
		}
	}
	if lastStr.Valid && lastStr.String != "" {
		if t, parseErr := parseDriverTime(lastStr.String); parseErr == nil {
			meta.LastEntryAt = t
		}
	}

	if meta.TotalEntries > 0 {
		meta.AvgWordsPerEntry = meta.TotalWords / meta.TotalEntries
	}

	var activeMs sql.NullInt64
	_ = tx.QueryRow("SELECT SUM(elapsed_active_ms) FROM writing_sessions").Scan(&activeMs)
	meta.TotalActiveMs = activeMs.Int64

	trows, err := tx.Query("SELECT prefix, COUNT(*) as cnt FROM entry_triggers GROUP BY prefix ORDER BY cnt DESC LIMIT 5")
	if err == nil {
		defer trows.Close()
		for trows.Next() {
			var ts domain.TriggerStat
			if err := trows.Scan(&ts.Prefix, &ts.Count); err == nil {
				meta.TopTriggers = append(meta.TopTriggers, ts)
			}
		}
		if err := trows.Err(); err != nil {
			return nil, err
		}
		trows.Close()
	}

	rows, err := tx.Query("SELECT created_at FROM entries ORDER BY created_at ASC")
	if err == nil {
		defer rows.Close()
		dayCounts := make(map[time.Weekday]int)
		var dates []time.Time
		for rows.Next() {
			var t time.Time
			if err := rows.Scan(&t); err == nil {
				dayCounts[t.Weekday()]++
				y, m, d := t.Date()
				dates = append(dates, time.Date(y, m, d, 0, 0, 0, 0, time.Local))
			}
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		rows.Close()

		maxCnt := -1
		for wd, cnt := range dayCounts {
			if cnt > maxCnt {
				maxCnt = cnt
				meta.MostActiveDay = wd
			}
		}

		if len(dates) > 0 {
			uniqueDates := make(map[int64]bool)
			for _, d := range dates { uniqueDates[d.Unix()] = true }
			
			sortedDates := make([]int64, 0, len(uniqueDates))
			for d := range uniqueDates { sortedDates = append(sortedDates, d) }
			sort.Slice(sortedDates, func(i, j int) bool { return sortedDates[i] < sortedDates[j] })

			longest := 0
			ty, tm, td := time.Now().Date()
			today := time.Date(ty, tm, td, 0, 0, 0, 0, time.Local)
			yesterday := today.AddDate(0, 0, -1).Unix()
			todayUnix := today.Unix()

			tempStreak := 0
			for i := 0; i < len(sortedDates); i++ {
				if i > 0 && sortedDates[i] == time.Unix(sortedDates[i-1], 0).AddDate(0, 0, 1).Unix() {
					tempStreak++
				} else {
					tempStreak = 1
				}
				if tempStreak > longest { longest = tempStreak }
			}
			meta.LongestStreak = longest

			lastDate := sortedDates[len(sortedDates)-1]
			if lastDate == todayUnix || lastDate == yesterday {
				c := 0
				target := time.Unix(lastDate, 0)
				for i := len(sortedDates)-1; i >= 0; i-- {
					if sortedDates[i] == target.Unix() {
						c++
						target = target.AddDate(0, 0, -1)
					} else {
						break
					}
				}
				meta.CurrentStreak = c
			}
		}
	}

	return meta, nil
}

func (s *SQLiteStore) DeleteEntry(id int64) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("INSERT INTO deleted_entries (entry_id, deleted_at) VALUES (?, ?) ON CONFLICT(entry_id) DO UPDATE SET deleted_at = excluded.deleted_at", id, time.Now()); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM entries_fts WHERE rowid = ?", id); err != nil {
		return err
	}
	res, err := tx.Exec("DELETE FROM entries WHERE id = ?", id)
	if err != nil {
		return err
	}
	count, _ := res.RowsAffected()
	if count == 0 {
		return ErrEntryNotFound
	}
	return tx.Commit()
}

func (s *SQLiteStore) Close() error { return s.db.Close() }
