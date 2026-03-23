package app

import (
	"mnemosyne/internal/store"
	"path/filepath"
	"testing"
	"time"
)

// newLockedModel creates a model with encryption enabled and a valid dataKey,
// simulating an unlocked session ready for auto-lock testing.
func newUnlockedModel(t *testing.T) (Model, func()) {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	s, err := store.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("store setup: %v", err)
	}

	key, err := s.SetupEncryption([]byte("testpass"))
	if err != nil {
		t.Fatalf("encryption setup: %v", err)
	}
	s.SetKey(key)

	m := NewModel(s, tmpDir)
	// Simulate a logged-in session: set the dataKey and move out of ModeUnlock.
	m.dataKey = make([]byte, len(key))
	copy(m.dataKey, key)
	m.mode = ModeWelcome

	return m, func() { s.Close() }
}

// TestAutoLockReschedulesTickAfterLock is the regression test for the bug where
// returning early from performLock() broke the tick chain, leaving the timer
// permanently dead after the first auto-lock of the session.
func TestAutoLockReschedulesTickAfterLock(t *testing.T) {
	m, cleanup := newUnlockedModel(t)
	defer cleanup()

	// Push lastInput past the auto-lock threshold (default 10 minutes).
	m.lastInput = time.Now().Add(-11 * time.Minute)

	newModel, cmd := m.Update(tickMsg(time.Now()))

	locked := newModel.(Model)
	if locked.mode != ModeUnlock {
		t.Errorf("expected ModeUnlock after auto-lock, got mode %v", locked.mode)
	}
	if locked.dataKey != nil {
		t.Error("dataKey should be nil after lock")
	}

	// Critical: cmd must be non-nil so the tick chain survives across locks.
	// Before the fix, performLock() returned (model, nil) and the reschedule
	// at the bottom of the tickMsg case was never reached.
	if cmd == nil {
		t.Error("tick was not rescheduled after auto-lock — timer chain is broken")
	}
}

// TestTickReschedulesWhenIdleTimerHasNotExpired confirms normal tick behaviour:
// the timer keeps firing when the session is active.
func TestTickReschedulesWhenIdleTimerHasNotExpired(t *testing.T) {
	m, cleanup := newUnlockedModel(t)
	defer cleanup()

	m.lastInput = time.Now() // recent input — no lock should fire

	_, cmd := m.Update(tickMsg(time.Now()))

	if cmd == nil {
		t.Error("tick was not rescheduled during an active session")
	}
}

// TestAutoLockDoesNotFireInPlaintextMode confirms that without a dataKey
// (plaintext/no-encryption mode) auto-lock intentionally does not trigger.
func TestAutoLockDoesNotFireInPlaintextMode(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "plain.db")

	s, err := store.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("store setup: %v", err)
	}
	defer s.Close()

	m := NewModel(s, tmpDir)
	// No encryption — dataKey stays nil, mode is ModeWelcome (or ModeUnlock for first run).
	// Force into a browsing mode to make the condition testable.
	m.mode = ModeWelcome
	m.lastInput = time.Now().Add(-11 * time.Minute)

	newModel, _ := m.Update(tickMsg(time.Now()))

	if newModel.(Model).mode == ModeUnlock {
		t.Error("plaintext mode should not auto-lock (no dataKey)")
	}
}
