# Changelog

All notable changes to Mnemosyne will be documented in this file.

## [1.1.0] - 2026-03-02

### Added
- **Configuration System**: Settings are now externalized to `config.yaml` within the data directory. Users can now tune `auto_lock_minutes`, `autosave_seconds`, and `snapshot_retention`.
- **Idempotent Migration**: Enhanced the encryption migration logic with version-byte (0x01) checks to ensure safety and data integrity during interrupted migrations.
- **Cross-Platform Support**: Official builds now available for Windows (amd64), macOS (Intel/Silicon), and Linux (amd64).
- **Graceful Truncation**: Metrics and history items in the Surface HUD are now intelligently truncated to prevent rendering issues in small terminal windows.

### Improved
- **Forensic Hardening**: Aggressive memory hygiene pass implemented. Sensitive data, including key material, passwords, and plaintext JSON buffers, are now explicitly zeroed (`crypto.Zero`) immediately after use.
- **Scanner Performance**: Refactored the internal trigger scanner from a synchronous split approach to a memory-efficient `bufio.Scanner` with a 1MiB buffer limit for "Epic Dives."
- **Layout Robustness**: Added safety bounds to the TUI layout logic to prevent panics and rendering artifacts in extremely small windows.
- **Unified Path Logic**: Standardized data directory resolution across all systems, improving portability and consistency.

### Fixed
- Fixed a path mismatch bug where configuration was incorrectly being searched for in the snapshots directory.
- Resolved a silent failure in the trigger scanner when encountering lines exceeding the default buffer limit.

---

## [1.0.0] - 2026-02-28

### Added
- **Initial Release**: Core TUI journal with Dive/Surface modes.
- **AES-256-GCM Encryption**: Hardened at-rest encryption using Argon2id.
- **Encrypted Snapshots**: Automated background backups in `.msn` format.
- **Archive Meta**: Analytical dashboard for writing mass and streaks.
- **Theming**: Integrated style system with high-contrast and atmospheric themes.
