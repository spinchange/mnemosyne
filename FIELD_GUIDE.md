# MNEMOSYNE
## Field Guide

*A personal memory palace. Write. Remember. Endure.*

---

## I. Getting Started

### Installation & First Launch

Mnemosyne runs as a terminal application. From the project directory:

```
./mnemosyne
```

On first launch, you are not asked to log in. You are asked to remember.

The application presents a single prompt: **Set a Master Password**. This is your only credential. There is no recovery path. The password derives the key that encrypts everything you write. Choose deliberately.

- Type a password. Press `Enter`.
- Type it again to confirm. Press `Enter`.
- The archive is initialized, encrypted, and ready.

If you prefer to run without encryption — no password, no lock screen — press `Esc` at the prompt. The archive will operate in plaintext mode. You can enable encryption later, but you cannot decrypt what you never encrypted. Decide now.

After the master password is set, you arrive at the **Welcome screen**. This is the threshold.

Press `Enter` to begin your first Dive.

---

## II. The Interface

Mnemosyne has two faces.

### The Dive

*ModeDive — the quiet room.*

The Dive is everything. A blank text area. Soft-wrapped lines. No toolbar. No formatting controls. No decorations competing with the cursor. The machine is not competing for your attention — it is simply present.

A narrow status bar anchors the bottom:

```
342 words  ·  14m32s  ·  saved 09:41
```

That's all you get: weight, time, recency. Write.

Press `Tab` to surface.

---

### The Surface

*ModeSurface — the HUD.*

The Surface is your archive made visible. The editor persists on the left. The right panel becomes a dashboard:

- **Session** — live word count and active writing time
- **Metrics** — any triggers captured from the current entry
- **History** — a scrollable list of past entries; navigate with `↑` / `↓`

From the Surface you can open old entries, start a new one, delete, or search the full archive.

Press `Tab` again to return to the Dive.

---

### The Welcome Screen

A brief landing screen between sessions. Shows the date, last entry summary, and three navigation options. This is the threshold — the moment between arrival and descent.

---

### Archive Meta

Press `M` from Welcome or Surface to open a quiet summary of everything you've written:

**The Weight**
- Total words written, total entries, total active writing time, date span

**The Rhythm**
- Current streak, longest streak, average words per entry, most active day

**Top Signals**
- Most frequently used trigger prefixes and their counts

Press `Esc` to close.

---

## III. Shortcuts & Commands

### Navigation

| Key | Context | Action |
|---|---|---|
| `Enter` | Welcome | Begin new Dive |
| `Tab` | Welcome | Open Surface |
| `M` | Welcome / Surface | Archive Meta |
| `Tab` | Dive | Switch to Surface |
| `Tab` | Surface | Switch to Dive |

### Surface — Archive

| Key | Context | Action |
|---|---|---|
| `↑` / `↓` | Surface | Navigate entry list |
| `Enter` | Surface, on entry | Open entry in editor |
| `Enter` | Surface, on "+ new" | Begin new entry |
| `/` | Surface | Enter search mode |
| `Enter` | Search mode | Confirm search |
| `Esc` | Search mode | Cancel search |
| `X` or `Backspace` | Surface, on entry | Prompt to delete |
| `Y` | Delete confirmation | Confirm deletion |

### System

| Key | Context | Action |
|---|---|---|
| `Ctrl+T` | Anywhere | Cycle through themes |
| `Ctrl+L` | Dive / Surface | Lock — zero key material, return to password prompt |
| `Ctrl+P` | Surface | Change master password |
| `Ctrl+C` | Anywhere | Save, snapshot, quit |
| `Esc` | First-run password prompt | Skip encryption setup |
| `Esc` | Change Password flow | Cancel |

### Automatic Behaviors

**Autosave** runs every 5 seconds when content has changed. You will not lose more than 5 seconds of work.

**Auto-lock** triggers after 10 minutes of inactivity. Key material is zeroed from memory. Unsaved changes are written before locking.

**Silent Snapshots** are triggered automatically after a threshold of writes. No interaction required.

---

## IV. The Trigger System

Mnemosyne parses every entry for structured signals called **triggers**. A trigger is any line matching this pattern:

```
ALLCAPS: value here
```

Examples:

```
MOOD: peaceful
ENERGY: 4/10
SLEPT: 6h
TRADED: AAPL — bought the dip, watching 185
READING: Blood Meridian, pg 122
INTENTION: stay off the phone after 9pm
```

The key must be `ALLCAPS`. The value is everything after the colon and space. There are no reserved names. Use whatever vocabulary fits your life.

### Why Triggers Matter

Triggers are stored separately, indexed by entry and writing session. Over weeks and months, the Archive Meta screen reveals your most frequently named things across all time. Search works across both body text and trigger content. Recurring patterns emerge — not because the machine tracked you, but because you named things consistently.

`MOOD: tense` costs three seconds to write. Over a year, it tells you something a mood-tracking app never could: what you were writing about when you felt that way.

### Mechanics

- Triggers are captured on every save, including autosave. Nothing special required.
- Modify a trigger line and save; the stored value updates on the next autosave.
- The HUD shows the most recently captured triggers under **METRICS**.
- When encryption is enabled, trigger **payloads** (values) are encrypted. Prefix names (e.g., `MOOD`) are stored as metadata — they reveal categories but not content. This is an acceptable scope.

---

## V. Security & Durability

### Encryption

Mnemosyne uses **AES-256-GCM** with **Argon2id** key derivation. No third-party encryption libraries — only Go's extended standard library (`golang.org/x/crypto`).

#### How the Key Is Derived

1. On setup, a 16-byte random salt is generated and stored in the database config.
2. Your password is run through Argon2id (`m=65536` KiB, `t=3` iterations, `p=1` thread) to produce a 32-byte root key.
3. HKDF (SHA-256) derives two subkeys:
   - **Data key** — encrypts all entry content
   - **Verify key** — encrypts a known sentinel used at unlock to confirm the correct password without touching data
4. The data key lives in memory for the session duration. On lock or quit, it is zeroed.

#### What Is Encrypted

| Field | Status |
|---|---|
| Entry titles | Encrypted |
| Entry bodies | Encrypted |
| Trigger payloads | Encrypted |
| Trigger prefix names | Plaintext |
| Timestamps, row counts, schema | Plaintext |

The threat model is precise: protect your written content from anyone who reads the `.db` file directly. It does NOT protect against:
- A compromised OS, keylogger, or memory dump.
- Anything after the key is derived and held in memory.
This is an acceptable and documented scope for a local single-user application.

#### Nonce Uniqueness & Field Binding

Every encryption call generates a fresh 12-byte random nonce. The same plaintext encrypted twice produces different ciphertext.

Each value is bound to its exact location via AEAD additional authenticated data:

```
mnemosyne:v1:<table>:<field>:<rowid>
```

A ciphertext transplanted from one field to another fails authentication. The database cannot be surgically tampered with.

---

### Password Change

`Ctrl+P` from the Surface opens a three-stage flow:

1. Enter current password (wrong password stops here — nothing is touched)
2. Enter new password
3. Confirm new password

On success: a fresh salt is generated, all entries and triggers are re-encrypted with the new key, the database is vacuumed to eliminate plaintext from free pages. The session continues without interruption.

---

### Silent Snapshots

Every N writes, Mnemosyne creates a snapshot — a complete encrypted export of the archive — stored in `~/.mnemosyne/snapshots/`.

#### Snapshot Format (`.msn`)

```
[ 72-byte cleartext header | encrypted payload ]
```

The header contains: magic bytes (`MSNP`), format version, Argon2 parameters, salt, snapshot ID, creation timestamp.

The payload is gzipped JSON of all entries and triggers, encrypted with the data key. The cleartext header bytes are bound as AEAD additional authenticated data — tampering with the header invalidates decryption.

Up to **20 snapshots** are retained. Older ones are rotated out automatically.

#### Restore

```
./mnemosyne restore <snapshot-file> [target-db-path]
```

Enter your password when prompted. The snapshot is decrypted, decompressed, and a new SQLite database is initialized with all entries and triggers restored. Argon2 parameters from the snapshot header are carried forward — no parameter drift between backup and restore.

**The restore command is the exit hatch. Keep your password. Keep at least one snapshot somewhere safe.**

---

## VI. Design Considerations

**Why soft-wrap?**
Hard-wrap imposes structure on thought. When you are in a Dive, you should not be thinking about line length. Soft-wrap lets prose flow naturally. The wrapping is a display concern, not a content concern. The stored text is clean.

**Why no Markdown rendering?**
Rendering interrupts the act of writing. Asterisks turn bold mid-thought. Mnemosyne stores and displays raw text. What you write is what you see. Your eye parses structure from headers and blank lines without a renderer's help.

**Why the quiet room aesthetic?**
The terminal is already a focused environment. Mnemosyne takes that further: no decorations in Dive mode, no chrome competing with text. The HUD surfaces on demand, not by default. The design philosophy is that the tool should disappear while you work and appear only when you reach for it.

Themes exist — `Ctrl+T` cycles through them — because the quiet room can be furnished differently. Some people write better in low contrast. Some need warmth. The aesthetic is intentional but not imposed.

**Why autosave instead of manual save?**
Writers should not think about saving. The only cognitive load in a Dive is the writing itself.

**Why triggers instead of tags?**
Tags require a separate UI step: write, then return and tag. Triggers are inline — written in the flow of thought. And because they are parsed from the body, they are always synchronized with the content. There is no tag that refers to deleted text.

**Why a password instead of a keyfile?**
A keyfile can be copied, forgotten, or lost with the machine. A password is in your head. For a local single-user application with Argon2id at 64 MiB memory, a strong passphrase offers excellent security without backup complexity. Wrong passwords fail fast and loudly on the sentinel — without touching any entry data.

---

## VII. About

Mnemosyne was designed in adversarial collaboration between three AI agents and one human.

---

**Gemini — The Architect**

Structured the domain model, the database schema, and the `.msn` snapshot format. Held the system together. Asked uncomfortable questions about idempotency and crash safety. Designed the binary header format with care for forward compatibility — the version byte exists because parameters will eventually change.

---

**Claude — The Aestheticist**

Wrote the TUI view logic, the styling system, and the status bar copy. Argued for soft-wrap, against Markdown rendering, for the quiet room. Introduced the Archive Meta screen and its three-section structure. Insisted the unlock screen say "Incorrect password." and nothing else. Wrote this document.

---

**Codex — The Security Nut**

Refused to let the raw Argon2id output touch anything directly. Required the HKDF label format (`mnemosyne-data-v1`, `mnemosyne-verify-v1`). Specified the AAD binding convention. Required the version byte in every ciphertext envelope as a forward-compatibility gate. Enforced strict memory hygiene through the `crypto.Zero` pattern and defensive key copying.

---

**Spinchange / Chris Duffy — The Decider**

The user, the prompt, the editor. Brought a vision: a personal memory palace with no cloud, no account, no monthly fee. Something that endures. The adversarial model worked because Chris had taste — he could evaluate competing recommendations and choose. The agents argued. He decided.

---

The name is from **Mnemosyne** — the Titan goddess of memory and mother of the Muses. In Greek mythology, the dead drank from the river Lethe to forget; initiates into the mystery cults drank instead from Mnemosyne to remember.

The application takes the name seriously.

---

*This document describes Mnemosyne as built through v1.0.*
*Future phases are unwritten.*
