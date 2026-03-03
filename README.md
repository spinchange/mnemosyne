# MNEMOSYNE

A single-binary, TUI-based journal that replaces external `.txt` files with a robust, searchable, and analytics-driven embedded database.

## Vision
Mnemosyne is designed as a personal memory palace—atmospheric, strictly local, and cryptographically hardened. It prioritizes the act of writing through its **Dive** mode while providing deep existential and behavioral insights via the **Surface** HUD.

## Key Features
- **Hardened Security**: AES-256-GCM application-layer encryption with Argon2id key derivation and strict memory hygiene (explicit zeroing of key material).
- **Durability**: Automated, encrypted background snapshots (`.msn`) with a built-in recovery CLI.
- **Atmospheric TUI**: Minimalist, high-end "quiet room" design with multiple themes and rune-safe Unicode support.
- **Archive Analytics**: A dedicated "Archive Meta" panel providing insights into your writing mass, active time, and habits.
- **Portable Mode**: Operates from a thumb drive by placing a `.portable` file in the executable directory.

## Getting Started

## Installation & Setup

### Standard Installation
1. Download the binary for your platform (`Windows`, `macOS`, or `Linux`) from the latest Release.
2. Run the binary.
3. By default, Mnemosyne stores its encrypted database and snapshots in `~/.mnemosyne`.

### Portable Edition (Zero-Leak)
The Portable Edition is designed for use on thumb drives or shared volumes where you want to ensure no data is ever written to the host machine's User folder.

1. Download the `mnemosyne-windows-portable.zip`.
2. Extract it to your preferred location.
3. Ensure the `.portable` file remains in the same folder as the executable.
4. All data, including the encrypted database and configuration, will be stored strictly within that local folder.

## Controls & Usage
- **Enter**: Start a new "Dive" (writing session).
- **Tab**: Toggle between **Dive** and **Surface** (HUD) modes.
- **M**: Open the **Archive Meta** dashboard.
- **/**: Search your archive (incremental, case-insensitive).
- **Ctrl+L**: Lock the archive immediately (zeros keys in memory).
- **Ctrl+T**: Cycle through atmospheric themes.
- **Ctrl+P**: Setup or change your master password.

## Configuration
Settings are stored in `config.yaml` within your data directory.
```yaml
auto_lock_minutes: 10   # Inactivity timeout before locking
autosave_seconds: 5     # Frequency of background saves
snapshot_retention: 20  # Number of encrypted backups to keep
```

## Security & Privacy
Mnemosyne is built on a "No Cloud" policy. Your data never leaves your machine. 
- Encryption is tied to your hardware and specific database records using AAD (Additional Authenticated Data).
- Sensitive buffers are zeroed out immediately after use to prevent forensic memory recovery.

## Collaboration
This project was built in an experimental adversarial collaboration between Chris Duffy and three specialized AI agents:

- **Spinchange / Chris Duffy** — The Decider & Visionary
- **Gemini (Google)** — The Architect (System design, snapshots, & coordination)
- **Claude (Anthropic)** — The Aestheticist (TUI view logic, UX philosophy, & documentation)
- **Codex (OpenAI)** — The Security Nut (Cryptographic auditing & forensic hardening)

## License
MIT - Created by Chris Duffy (spinchange)

---
*Write. Remember. Endure.*
