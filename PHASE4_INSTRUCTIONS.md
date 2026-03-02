# Mnemosyne Phase 4: Encryption — Implementation Instructions
_Finalized by Claude + Codex design review_

---

## Overview

Implement at-rest encryption for all sensitive journal content. The design uses
application-layer AES-256-GCM with Argon2id key derivation. This was reviewed
and agreed upon by both Claude and Codex. Follow these instructions precisely
and in order.

---

## Threat Model (Be Explicit About This)

This design protects `title`, `body`, and trigger `payload` fields at rest in
SQLite. It does NOT protect:

- Row counts, timestamps, trigger prefix names, schema structure
- SQLite WAL/journal/temp files during active writes
- Memory dumps, pagefiles, or crash reports on Windows
- Anything after the key is derived and held in memory

This is normal and acceptable for a local single-user desktop app. Document it.

---

## New Dependency

Add to `go.mod`:

```
golang.org/x/crypto
```

This provides `argon2` and `hkdf`. It is part of the official Go extended
standard library and requires no CGO.

---

## Step 1: New Package — `internal/crypto/crypto.go`

Create `internal/crypto/crypto.go` with the following responsibilities:

### 1a. Key Derivation

```
DeriveKeys(password []byte, salt []byte, m, t, p uint32) (dataKey []byte, verifyKey []byte)
```

- Run Argon2id: `argon2.IDKey(password, salt, t, m, p, 32)`
- Use HKDF (SHA-256) to derive TWO subkeys from the Argon2id output:
  - `dataKey` — used to encrypt/decrypt all field content
  - `verifyKey` — used only to encrypt/decrypt the sentinel value
- **Do not use the raw Argon2id output directly for either purpose.**
- Label the HKDF expansions explicitly, e.g. `"mnemosyne-data-v1"` and
  `"mnemosyne-verify-v1"`.

### 1b. Envelope Format

Every encrypted value stored in the database must use this binary envelope:

```
[ version: 1 byte | nonce: 12 bytes | ciphertext+tag: N bytes ]
```

- `version` is currently `0x01`. This field exists so future parameter or
  algorithm changes can be detected and handled without breaking old data.
- `nonce` is 12 bytes of cryptographically random data, generated fresh for
  every single encryption call.
- `ciphertext+tag` is the AES-256-GCM output (ciphertext with 16-byte auth
  tag appended).

### 1c. Encrypt Function

```
Encrypt(key []byte, plaintext []byte, aad []byte) ([]byte, error)
```

- Generate a fresh random 12-byte nonce.
- Encrypt with AES-256-GCM using the nonce and `aad` as additional
  authenticated data.
- Return the versioned envelope: `[0x01 | nonce | ciphertext+tag]`.

### 1d. Decrypt Function

```
Decrypt(key []byte, envelope []byte, aad []byte) ([]byte, error)
```

- Read and validate the version byte. Return an error if unrecognized.
- Extract the nonce (bytes 1–12) and ciphertext (bytes 13+).
- Decrypt with AES-256-GCM using the same `aad` that was used during
  encryption.
- An authentication failure here means either wrong key or corrupted data.
  Return a typed sentinel error (e.g. `ErrDecryptFailed`) — do not expose
  the underlying AEAD error directly.

### 1e. AAD Convention

Every `Encrypt`/`Decrypt` call must pass an AAD string that identifies the
context of the data. Use this format:

```
"mnemosyne:v1:<table>:<field>:<rowid>"
```

Examples:
- `"mnemosyne:v1:entries:title:42"`
- `"mnemosyne:v1:entries:body:42"`
- `"mnemosyne:v1:entry_triggers:payload:7"`

This prevents a valid ciphertext for one field being transplanted into a
different field or row without detection.

---

## Step 2: Database Schema Changes

### 2a. New `config` Table

Add to `initSchema()` in `internal/store/sqlite.go`:

```sql
CREATE TABLE IF NOT EXISTS config (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
```

This table stores:

| key | value |
|---|---|
| `argon2_salt` | 16 random bytes |
| `argon2_m` | uint32, memory cost in KiB (e.g. 65536 for 64 MiB) |
| `argon2_t` | uint32, iterations (e.g. 3) |
| `argon2_p` | uint32, parallelism (e.g. 1) |
| `sentinel` | encrypted envelope of known plaintext, using `verifyKey` |
| `encryption_enabled` | `"1"` or `"0"` |

### 2b. Default Argon2id Parameters

```
m = 65536   (64 MiB)
t = 3
p = 1
```

These must be stored in `config` at first-run setup — never hardcoded for
decryption. When decrypting, always read parameters back from `config`.

---

## Step 3: Store Changes — `internal/store/sqlite.go`

### 3a. Add Key Field

```go
type SQLiteStore struct {
    db      *sql.DB
    writeMu sync.Mutex
    dataKey []byte  // nil if encryption not enabled
}
```

Add a method:

```
func (s *SQLiteStore) SetKey(dataKey []byte)
```

Called after successful unlock, before any read/write operations.

### 3b. Helper Methods (internal)

```
func (s *SQLiteStore) encryptField(table, field string, rowID int64, plaintext string) ([]byte, error)
func (s *SQLiteStore) decryptField(table, field string, rowID int64, ciphertext []byte) (string, error)
```

These construct the AAD string and call `crypto.Encrypt` / `crypto.Decrypt`.
If `s.dataKey` is nil (encryption not enabled), pass the plaintext through
unchanged.

### 3c. Modify Write Methods

In `CreateEntry` and `SaveAll`, encrypt `entry.Title` and `entry.Body` before
writing to the database if `s.dataKey` is set.

In `CreateEntry` specifically: encrypt using the committed row ID. Because the
ID is only known after `tx.Commit()`, you will need to UPDATE the row
post-commit to write the encrypted values, or use a two-phase insert. The
simplest approach: insert plaintext, commit to get the ID, then immediately
UPDATE with encrypted values in a second transaction.

### 3d. Modify Read Methods

In `GetEntry`, `GetEntries`, and `SearchEntries`, decrypt `title` and `body`
after reading from the database if `s.dataKey` is set.

In `GetEntries`, only `title` is fetched (body is not). Decrypt title only.

### 3e. Modify Trigger Methods

In `SaveAll`, encrypt `t.Payload` for each trigger before insert.
In `GetLatestTriggers`, decrypt `payload` after reading.

### 3f. Replace `SearchEntries`

Drop the FTS5 query entirely when encryption is enabled. Replace with:

```
func (s *SQLiteStore) SearchEntries(query string) ([]domain.Entry, error)
```

- Fetch all entries (id, encrypted title, word_count, created_at, encrypted body).
- Decrypt each title and body.
- Filter by `strings.Contains(strings.ToLower(body+title), strings.ToLower(query))`.
- Return matches.

Keep the existing FTS5 path for when encryption is disabled (i.e. `s.dataKey == nil`).

---

## Step 4: New Store Methods for Setup and Unlock

```
func (s *SQLiteStore) IsEncryptionEnabled() (bool, error)
func (s *SQLiteStore) SetupEncryption(password []byte) error
func (s *SQLiteStore) Unlock(password []byte) (dataKey []byte, err error)
```

### `IsEncryptionEnabled`
Read `encryption_enabled` from `config`. Return `false` if the row does not
exist (fresh database).

### `SetupEncryption`
Called once, on first run with encryption:
1. Generate 16 random bytes as `salt`.
2. Use default Argon2id params (`m=65536, t=3, p=1`).
3. Call `DeriveKeys(password, salt, m, t, p)` → `dataKey`, `verifyKey`.
4. Encrypt the known sentinel string `"mnemosyne-ok"` using `verifyKey` with
   AAD `"mnemosyne:v1:config:sentinel:0"`.
5. Write `salt`, `argon2_m`, `argon2_t`, `argon2_p`, `sentinel`, and
   `encryption_enabled=1` to `config`.
6. Call the migration function (Step 5).

### `Unlock`
Called on every subsequent launch:
1. Read `salt`, `m`, `t`, `p`, `sentinel` from `config`.
2. Call `DeriveKeys(password, salt, m, t, p)` → `dataKey`, `verifyKey`.
3. Attempt to decrypt `sentinel` using `verifyKey`.
4. If decryption fails, return `ErrWrongPassword` (a typed error, not a
   generic string).
5. If successful, return `dataKey` to the caller (app layer calls
   `store.SetKey(dataKey)`).

---

## Step 5: Migration

```
func (s *SQLiteStore) MigrateToEncrypted(dataKey []byte) error
```

- Read ALL existing entries (id, title, body).
- For each entry: encrypt title and body, UPDATE the row.
- Read ALL trigger payloads (id, entry_id, payload).
- For each trigger: encrypt payload, UPDATE the row.
- Run `PRAGMA wal_checkpoint(FULL)`.
- Run `VACUUM` to eliminate plaintext from free pages.
- This function must be idempotent: if called again after a crash, it should
  detect already-encrypted rows and skip them (use the version byte in the
  envelope to detect this — `0x01` prefix = already encrypted).
- Wrap all updates in a transaction. If the transaction fails, do not write
  `encryption_enabled=1` to `config`.

---

## Step 6: New TUI Mode — `ModeUnlock`

Add `ModeUnlock` to the `Mode` iota in `internal/app/model.go`. It must be
the first mode the app enters (before `ModeWelcome`).

### Model additions

```go
passwordInput  textinput.Model
confirmInput   textinput.Model
unlockStage    int  // 0 = enter password, 1 = confirm (first run only)
isFirstRun     bool
```

### Init flow

In `NewModel`, before returning:
1. Call `store.IsEncryptionEnabled()`.
2. If `false`: set `mode = ModeWelcome` (encryption not yet set up — treat as
   plaintext session, allow user to enable via settings later, or auto-prompt
   on first run — your call).
3. If `true`: set `mode = ModeUnlock`, `isFirstRun = false`.
4. If you want to auto-prompt on first run: detect an empty database and set
   `isFirstRun = true`, `mode = ModeUnlock`.

### ModeUnlock view

Display a centered password prompt. Mask input with `EchoModePassword` on the
`textinput.Model`. First run shows a confirm field. Show a clear error message
on wrong password (but do not say "wrong key" — say "Incorrect password").

### ModeUnlock update

On `enter`:
- First run, stage 0: advance to stage 1 (confirm).
- First run, stage 1: if passwords match, call `store.SetupEncryption(password)`,
  then call `store.SetKey(dataKey)`, then transition to `ModeWelcome`.
- Returning user: call `store.Unlock(password)`. On success: `store.SetKey(dataKey)`,
  transition to `ModeWelcome`. On `ErrWrongPassword`: display error, clear
  input, stay in `ModeUnlock`.

On `ctrl+c` in `ModeUnlock`: quit without entering.

---

## Step 7: Password Change Flow

Add a key binding (e.g. `ctrl+p`) accessible from `ModeSurface` to trigger a
password change flow. The flow:

1. Prompt for current password, verify via `store.Unlock`.
2. Prompt for new password + confirm.
3. Derive new keys from new password with a freshly generated salt.
4. Re-encrypt all entries and triggers with the new `dataKey`.
5. Update `config` with new `salt`, new KDF params, new `sentinel`.
6. Run `VACUUM`.

This cannot be deferred to later — it must be designed before the unlock
screen is finalized, as they share the same password input component.

---

## Step 8: Error Handling Rules

- `ErrWrongPassword` — shown to user as "Incorrect password." Stop there.
- `ErrDecryptFailed` — may mean corruption or tampering. Log to `debug.log`,
  show user "Entry could not be read — data may be corrupted."
- Do not expose raw AEAD/GCM errors to the user. Those messages can leak
  implementation details.
- Distinguish wrong password from DB corruption internally, but present both
  cleanly to the user.

---

## Step 9: Testing Checklist

Add tests in `internal/store/sqlite_test.go` and `internal/crypto/`:

- [ ] `TestEncryptDecryptRoundtrip` — encrypt then decrypt, verify plaintext
- [ ] `TestWrongKeyFails` — decrypting with wrong key returns `ErrDecryptFailed`
- [ ] `TestWrongAADFails` — decrypting with mismatched AAD fails authentication
- [ ] `TestCiphertextTransplantFails` — ciphertext from one field rejected in another
- [ ] `TestNonceUniqueness` — two encryptions of the same plaintext produce different output
- [ ] `TestUnlockCorrectPassword` — SetupEncryption + Unlock roundtrip succeeds
- [ ] `TestUnlockWrongPassword` — returns `ErrWrongPassword`
- [ ] `TestMigrationIdempotent` — running migration twice does not corrupt data
- [ ] `TestMigrationCrashSafe` — partial migration followed by re-run completes correctly
- [ ] `TestSearchEncrypted` — in-memory search finds matches in encrypted entries
- [ ] `TestDeleteAfterEncryption` — delete still works correctly with encrypted data

---

## Implementation Order

Do these in sequence. Do not jump ahead.

1. `internal/crypto/crypto.go` — key derivation, encrypt, decrypt
2. `config` table in `initSchema`
3. Store helper methods (`encryptField`, `decryptField`, `SetKey`)
4. `SetupEncryption`, `Unlock`, `IsEncryptionEnabled` on store
5. Migration function
6. Modify `CreateEntry`, `SaveAll`, `GetEntry`, `GetEntries`, `GetLatestTriggers`
7. Replace `SearchEntries` with dual-path (FTS5 if no key, in-memory if key set)
8. `ModeUnlock` TUI mode
9. Password change flow
10. Tests

---

## What Does NOT Change

- `internal/domain/models.go` — no changes needed
- `internal/parser/scanner.go` — no changes needed
- `internal/ui/styles.go` — no changes needed (add unlock screen styling here if desired)
- `cmd/mnemosyne/main.go` — no changes needed; unlock is handled inside the TUI

---

## Final Notes

- The `debug.log` must never contain plaintext entry content. Audit all
  `log.Printf` calls before shipping.
- The `mnemosyne.exe~` backup binary in the repo root should be deleted —
  it is a stale artifact.
- Encryption is opt-in for now. A user who never sets a password continues
  using the app in plaintext mode with no behavior change.
