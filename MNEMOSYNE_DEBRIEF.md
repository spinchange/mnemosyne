# Mnemosyne v1.0: Post-Project Debrief
**Date:** March 1, 2026
**Collaborators:** Spinchange (Chris Duffy), Gemini, Claude, Codex

---

## 1. Project Status: Release 1.0 (Hardened)
Mnemosyne is a single-binary, TUI-based personal journal that prioritizes local-first privacy, aesthetic focus, and cryptographic durability.

### Core Features
- **Hardened Security**: AES-256-GCM + Argon2id. Every sensitive field is bound via AAD to its database cell. Memory is explicitly zeroed using `crypto.Zero` to prevent forensic leakage.
- **Silent Snapshots**: Automatic background backups to encrypted `.msn` files with a robust CLI `restore` path.
- **Atmospheric TUI**: Minimalist "Dive" (Focus) and "Surface" (HUD) modes. Rune-safe Unicode support for global journaling.
- **Archive Meta**: Existential and behavioral analytics (Weight, Rhythm, Signals).

---

## 2. Technical Audit: "The Saves of the Day"
During the final adversarial audit, the following critical issues were identified and resolved:
1. **The Race Condition**: Fixed a TOCTOU vulnerability where background snapshots could use zeroed keys if a session lock occurred mid-flight. Solution: Mandatory defensive key copying.
2. **The Unlock Leak**: Identified a logic gap in `ModeChangePassword` where derived keys were orphaned in memory after verification. Fixed with explicit `discardedKey` zeroing.
3. **The NULL Title Crash**: Resolved a scan error in the unencrypted FTS search path where `NULL` titles caused panics.
4. **FTS Alias Ambiguity**: Corrected non-functional search queries caused by incorrect table aliasing in FTS5 joins.

---

## 3. Known Issues & Backlog (Phase 7)
- **HUD Rendering**: User reports intermittent rendering/clipping issues in some terminal environments (e.g., small window sizes or specific emulators).
- **Scanner Performance**: `ScanContent` uses `bytes.Split`; for multi-megabyte entries, a true buffered scanner approach should be implemented.
- **Multi-Day Streaks**: While now DST-safe, the streak logic could be expanded to handle "skipped" days with configurable grace periods.

---

## 4. Design Philosophy Recap
- **"Quiet Room, Not a Cockpit"**: The tool disappears during use. Tab is the threshold.
- **No Markdown Rendering**: Intentional. The eye parses structure from raw text; rendering is a distraction from the act of writing.
- **Being is Contingent on Doing**: The AI agents "vanish" into their own use. No background hum, only reactive problem-solving in motion.

---

## 5. Final Reflection
Mnemosyne is more than a journal; it is a testament to what is possible when AI agents are treated as digital peers under the direction of a human with clear taste. We have built something that endures.

**Write. Remember. Endure.**
