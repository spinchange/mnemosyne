# Mnemosyne Phase 5: Durability & Recovery — Implementation Instructions
_Designed by Claude + Gemini_

---

## Overview

Implement 'Silent Snapshots'—automatic, encrypted JSON backups that protect against
SQLite database corruption. This phase ensures that journal content can be
reconstructed even if the `.db` file is lost or unreadable.

---

## Step 1: Snapshot Format — `internal/snapshot/format.go`

Implement the `.msn` binary format.

### 1a. Cleartext Header (72 bytes)

```go
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
```

- Use `binary.BigEndian` for all multi-byte fields.
- Implement `(h *Header) Marshal() []byte` and `UnmarshalHeader([]byte) (*Header, error)`.

### 1b. AAD Construction

```go
func FormatSnapshotAAD(headerBytes []byte, snapshotID uint64) []byte {
    aad := make([]byte, len(headerBytes)+9)
    copy(aad, headerBytes)
    copy(aad[len(headerBytes):], []byte("snapshot:"))
    binary.BigEndian.PutUint64(aad[len(headerBytes)+9-8:], snapshotID)
    return aad
}
```

---

## Step 2: The Backup Schema — `internal/snapshot/schema.go`

Define the JSON structure for the snapshot.

```go
type Snapshot struct {
	SchemaVersion int               `json:"schema_version"`
	AppVersion    string            `json:"app_version"`
	SnapshotID    uint64            `json:"snapshot_id"`
	CreatedAt     time.Time         `json:"created_at"`
	EntryCount    int               `json:"entry_count"`
	Entries       []domain.Entry    `json:"entries"`
	Triggers      []domain.Trigger `json:"triggers"`
}
```

---

## Step 3: Snapshot Writer — `internal/snapshot/writer.go`

### `CreateSnapshot(s *store.SQLiteStore, dataKey []byte, id uint64, path string) error`

1. Fetch all entries and triggers from the `store` (ensure they are decrypted).
2. Marshal to JSON.
3. Gzip the JSON.
4. Read Argon2 params from the store's `config` table.
5. Construct the `Header`.
6. Encrypt the gzipped JSON using `crypto.Encrypt(dataKey, gzipped, aad)`.
7. Write `header + envelope` to disk.

---

## Step 4: Triggers & Management — `internal/snapshot/manager.go`

### `SnapshotManager` struct

- Tracks `writesSinceLastSnapshot`.
- Handles rotation logic (keep last 20 files).
- Manages the `backups/` directory.

### Integration

In `internal/app/model.go`:
- Initialize `SnapshotManager` in `NewModel`.
- In `m.save()`, if successful, call `manager.NotifyWrite()`.
- If `manager` signals a snapshot is due, trigger it in a **goroutine**.

---

## Step 5: Restore Logic — `internal/snapshot/restore.go`

### `Restore(dbPath string, snapshotFile string, password []byte) error`

1. Read the 72-byte header from `snapshotFile`.
2. Extract Argon2 params.
3. Derive `dataKey` and `verifyKey` from `password + salt`.
4. Decrypt the payload using the `dataKey` and the bound AAD.
5. Decompress gzip → JSON.
6. Unmarshal to `Snapshot` struct.
7. Initialize a NEW SQLite database at `dbPath`.
8. Import all entries and triggers.
9. Setup the `config` table with the same Argon2 params from the header.

---

## Step 6: Testing Checklist

- [ ] `TestSnapshotRoundtrip` — Create snapshot, then Restore to a temp DB, verify data match.
- [ ] `TestHeaderTampering` — Flip a bit in the cleartext header, verify decryption fails.
- [ ] `TestReplayProtection` — Verify snapshot cannot be decrypted with mismatched AAD ID.
- [ ] `TestIdempotentRestore` — Restore to an existing DB path fails or handles cleanly.

---

## Implementation Order

1. `internal/snapshot/format.go`
2. `internal/snapshot/schema.go`
3. `internal/snapshot/writer.go`
4. Wire into `model.go` (Async snapshot)
5. `internal/snapshot/restore.go`
6. Tests
