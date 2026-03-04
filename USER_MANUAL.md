# MNEMOSYNE — User Manual

> *Write. Remember. Endure.*

---

## Table of Contents

1. [What Is Mnemosyne?](#1-what-is-mnemosyne)
2. [Installation](#2-installation)
3. [First Launch & Encryption Setup](#3-first-launch--encryption-setup)
4. [The Interface](#4-the-interface)
5. [Keyboard Reference](#5-keyboard-reference)
6. [Writing: Dive Mode](#6-writing-dive-mode)
7. [Signals: Structured Tagging](#7-signals-structured-tagging)
8. [Archive: Surface Mode](#8-archive-surface-mode)
9. [Archive Meta Dashboard](#9-archive-meta-dashboard)
10. [Themes](#10-themes)
11. [Security & Locking](#11-security--locking)
12. [Snapshots & Recovery](#12-snapshots--recovery)
13. [Configuration](#13-configuration)
14. [Portable Mode](#14-portable-mode)
15. [Data Locations](#15-data-locations)

---

## 1. What Is Mnemosyne?

Mnemosyne is a single-binary, terminal-based personal journal. It stores everything in a local encrypted database — no cloud, no account, no network. Your archive lives on your machine and nowhere else.

Key design principles:

- **Privacy by default.** AES-256-GCM encryption protects every entry at rest. Keys are derived with Argon2id and zeroed from memory immediately after use.
- **Minimalist writing surface.** The Dive editor is distraction-free by design.
- **Structured introspection.** The Signals system lets you embed typed data (mood, energy, sleep, etc.) inline as you write, surfaced automatically in the HUD.
- **Durable.** Encrypted background snapshots run automatically so your archive is never one crash away from loss.

---

## 2. Installation

### Standard (Recommended)

1. Download the binary for your platform from the latest release:
   - `mnemosyne-windows-amd64.exe`
   - `mnemosyne-macos-amd64` / `mnemosyne-macos-arm64`
   - `mnemosyne-linux-amd64`
2. Run the binary. No installer needed.
3. Your archive will be created in `~/.mnemosyne/` on first run.

### Portable (Thumb Drive / Zero-Leak)

See [Section 14 — Portable Mode](#14-portable-mode).

---

## 3. First Launch & Encryption Setup

On first launch, Mnemosyne will prompt you to set a master password.

```
MNEMOSYNE
set a master password to encrypt your archive

[ Password field ]
```

**You have two choices:**

| Choice | How | Effect |
|--------|-----|--------|
| Set a password | Type a password → Enter, then confirm | All entries are encrypted with AES-256-GCM. You must enter this password every time you open Mnemosyne. |
| Skip encryption | Press Escape | Entries are stored in plaintext SQLite. You can enable encryption later via `Ctrl+P` from Surface mode. |

> **Recommendation:** Set a password. The performance cost is negligible and it protects your archive if your machine is ever accessed by someone else.

On subsequent launches, the Unlock screen will appear and ask for your password. Enter it and press Enter to open your archive.

---

## 4. The Interface

Mnemosyne has four primary screens:

| Screen | What It Is |
|--------|-----------|
| **Welcome** | Home screen with date, last entry summary, and navigation hints |
| **Dive** | Full-screen writing editor |
| **Surface** | Split view: editor on left, archive HUD on right |
| **Archive Meta** | Overlay dashboard with lifetime writing statistics |

Navigation flows naturally between these screens using Tab, Enter, M, and Escape.

---

## 5. Keyboard Reference

### Global (available from most screens)

| Key | Action |
|-----|--------|
| `Ctrl+C` | Save current work and quit |
| `Ctrl+L` | Lock immediately (zeros key from memory, returns to password prompt) |
| `Ctrl+T` | Cycle through available themes |

### Welcome Screen

| Key | Action |
|-----|--------|
| `Enter` or `Space` | Start a new Dive (new entry) |
| `Tab` | Open Surface (archive browser) |
| `M` | Open Archive Meta dashboard |

### Dive Mode (Writing)

| Key | Action |
|-----|--------|
| `Tab` | Save and switch to Surface mode |
| `M` | Open Archive Meta dashboard |
| `Ctrl+P` | Change or set master password |
| `Ctrl+L` | Lock the archive |
| `Ctrl+T` | Cycle themes |

All standard text editing keys work in the editor (arrows, backspace, Home/End, etc.).

### Surface Mode (Archive Browser)

| Key | Action |
|-----|--------|
| `Tab` | Return to Dive mode |
| `Up` / `Down` | Navigate the entry list |
| `Enter` | Open selected entry for editing, or create new entry (if `+ new entry` is selected) |
| `/` | Open incremental search |
| `Enter` (in search) | Commit search query |
| `Esc` (in search) | Cancel search, restore full list |
| `X` or `Backspace` | Prompt to delete selected entry |
| `Y` (after delete prompt) | Confirm deletion |
| `N` or any other key | Cancel deletion |
| `M` | Open Archive Meta dashboard |

### Archive Meta Dashboard

| Key | Action |
|-----|--------|
| `Esc` or `M` | Close and return to previous screen |

### Unlock / Password Screens

| Key | Action |
|-----|--------|
| `Enter` | Submit password (or advance to confirmation step) |
| `Esc` | Skip encryption setup (first run only) |

---

## 6. Writing: Dive Mode

Dive is a full-screen text editor. There are no formatting toolbars, no sidebars, no distractions.

**Starting a new entry:** Press `Enter` on the Welcome screen or select `+ new entry` in Surface mode. The editor opens blank.

**Opening an existing entry:** Navigate to it in Surface mode and press `Enter`.

**Saving:** Mnemosyne saves automatically every 5 seconds (configurable) whenever you have unsaved changes. You do not need to manually save. A `saved HH:MM` timestamp appears in the status bar at the bottom when a save completes.

**Entry titles:** The title of each entry is derived automatically from the first non-empty line of your text. You do not set titles manually.

**Status bar (bottom of Dive screen):**
```
42 words  ·  0m3s  ·  saved 14:22
```
- Word count for the current entry
- Active writing time for this session (pauses after 30 seconds of inactivity)
- Timestamp of last save

---

## 7. Signals: Structured Tagging

Signals are Mnemosyne's system for embedding structured data inline as you write. Any line that follows this exact format is automatically detected:

```
UPPERCASE_WORD: payload text
```

**Rules:**
- The prefix must be all uppercase Latin letters (`A`–`Z`) only.
- The colon (`:`) must immediately follow the last letter of the prefix.
- Anything after the colon is the payload (trimmed of leading/trailing whitespace).
- The line must start with the prefix — it cannot be mid-paragraph.

**Examples:**

```
MOOD: calm, slightly distracted
ENERGY: 6
SLEEP: 7h
FOCUS: writing
GRATITUDE: good coffee this morning
LOCATION: home office
INTENTION: finish the proposal draft
```

**Where signals appear:**

In Surface mode, the HUD panel shows a **METRICS** section listing all signals detected in the most recently saved entry. Signals are re-scanned on every autosave.

In the Archive Meta dashboard, the **TOP SIGNALS** section shows your most frequently used prefixes across your entire archive, with usage counts.

Signals are entirely freeform — use whatever prefixes make sense to you. Common patterns include mood tracking, habit logging, energy levels, and daily intentions.

---

## 8. Archive: Surface Mode

Surface mode is a split view. The left panel shows your current editor (so you can keep writing). The right panel is the HUD: a live sidebar showing session stats, signals, and your entry history.

**The HUD contains:**

**SESSION**
- Word count of the current entry
- Active writing time this session
- Last save timestamp

**METRICS**
- Signals detected in the current entry (visible after first autosave)

**HISTORY**
- `+ new entry` at the top (cursor position 0)
- Your 10 most recent entries, listed as `MM/DD · Title`
- If you have more than 10 entries, a `+N more...` indicator appears

**Search:** Press `/` to enter search mode. The search bar appears in the HUD. Typing filters the history list incrementally (case-insensitive, searches both titles and body text). Press `Enter` to commit or `Esc` to cancel.

**Deleting an entry:** Navigate to it and press `X` or `Backspace`. A `DELETE? (y/n)` prompt appears. Press `Y` to confirm, anything else to cancel. Deletion is permanent.

---

## 9. Archive Meta Dashboard

Press `M` from any screen (Welcome, Dive, or Surface) to open the Archive Meta dashboard. This is a full-screen overlay with three sections:

**THE WEIGHT**
- Total word count across all entries
- Total number of entries
- Total active writing time (hours and minutes)
- Archive span (first to last entry date)

**THE RHYTHM**
- Current writing streak (consecutive days with at least one entry)
- Longest streak ever
- Average words per entry
- Most active day of the week

**TOP SIGNALS**
- Your most-used signal prefixes, ranked by frequency, with occurrence counts

Press `Esc` or `M` to close the dashboard.

---

## 10. Themes

Press `Ctrl+T` from any unlocked screen to cycle through available visual themes. Themes change the color palette of the entire TUI.

The selected theme persists for the duration of your session but resets on next launch. (Theme persistence across sessions is on the roadmap.)

---

## 11. Security & Locking

### Encryption

When a master password is set, every entry is encrypted using **AES-256-GCM** before being written to the SQLite database. The encryption key is derived from your password using **Argon2id**, a memory-hard key derivation function resistant to brute-force attacks.

Additional Authenticated Data (AAD) ties the encryption to specific database records, meaning ciphertext from one entry cannot be replicated or substituted into another.

### Memory Hygiene

Sensitive data — passwords, derived keys, and plaintext JSON buffers — are explicitly zeroed in memory immediately after use. This limits forensic recovery of key material from a memory dump or swap file.

### Auto-Lock

By default, Mnemosyne will lock automatically after **10 minutes of inactivity**. When locked:
- The key is zeroed from memory.
- The screen returns to the password prompt.
- A snapshot is taken before locking.

This timeout is configurable in `config.yaml` (see [Section 13](#13-configuration)).

### Manual Lock

Press `Ctrl+L` at any time to lock immediately. Any unsaved work is saved first.

### Changing Your Password

Press `Ctrl+P` from Surface mode. You will be prompted for your current password, then your new password (twice to confirm). The database is re-encrypted with the new key.

### Setting a Password After Skipping

If you skipped encryption on first launch, press `Ctrl+P` from Surface mode. You will be prompted to set a new master password and all existing entries will be encrypted.

---

## 12. Snapshots & Recovery

Mnemosyne automatically creates encrypted backup snapshots (`.msn` files) in the background as you write. Snapshots are triggered by write activity and on lock/quit.

By default, the 20 most recent snapshots are retained; older ones are pruned automatically. This limit is configurable.

### Restoring a Snapshot

Snapshots are stored in `<data_dir>/snapshots/`. To restore from a snapshot, use the command-line restore tool:

```bash
mnemosyne restore <snapshot_file> <new_db_path>
```

**Example:**

```bash
mnemosyne restore ~/.mnemosyne/snapshots/2026-03-01T14-22-00.msn ~/.mnemosyne/mnemosyne-restored.db
```

You will be prompted for your master password. The restore creates a new database file at `<new_db_path>` — it does not overwrite your existing database.

To use the restored database, rename or replace your current `mnemosyne.db` with the restored file.

---

## 13. Configuration

Mnemosyne reads `config.yaml` from your data directory on startup. If the file does not exist, defaults are used.

**Location:**
- Standard: `~/.mnemosyne/config.yaml`
- Portable: `<exe_folder>/config.yaml`

**Options:**

```yaml
auto_lock_minutes: 10   # Minutes of inactivity before auto-lock (default: 10)
autosave_seconds: 5     # Seconds between background saves (default: 5)
snapshot_retention: 20  # Number of snapshots to keep before pruning (default: 20)
```

Changes to `config.yaml` take effect on next launch.

---

## 14. Portable Mode

Portable mode is designed for use on a thumb drive or any location where you do not want any data written to the host machine's user folder.

**Setup:**

1. Download `mnemosyne-windows-portable.zip` (or equivalent for your platform).
2. Extract the contents to your target location (e.g., a USB drive).
3. Verify that a file named `.portable` is present in the same folder as the executable.

**Behavior in Portable Mode:**

- The database (`mnemosyne.db`) and all snapshots are stored in the same folder as the executable.
- `config.yaml` is also read from and written to that folder.
- Nothing is written to `~/.mnemosyne` or any other location on the host machine.

To exit portable mode, delete the `.portable` file. Mnemosyne will revert to standard mode on next launch (using `~/.mnemosyne/`), but existing data will remain in the portable folder and will not be migrated automatically.

---

## 15. Data Locations

### Standard Mode

| File | Location |
|------|----------|
| Database | `~/.mnemosyne/mnemosyne.db` |
| Config | `~/.mnemosyne/config.yaml` |
| Snapshots | `~/.mnemosyne/snapshots/` |
| Debug log | `debug.log` (in the working directory where the binary was run) |

### Portable Mode

| File | Location |
|------|----------|
| Database | `<exe_folder>/mnemosyne.db` |
| Config | `<exe_folder>/config.yaml` |
| Snapshots | `<exe_folder>/snapshots/` |

---

## Command-Line Reference

```
mnemosyne                          Launch the TUI
mnemosyne restore <snap> <db>      Restore a snapshot to a new database file
mnemosyne help                     Show usage summary
```

---

*Mnemosyne v1.1.0 — Built by Chris Duffy (spinchange) with Gemini, Claude, and Codex.*
