package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig_Defaults(t *testing.T) {
	c := LoadConfig("/nonexistent/path/config.yaml")
	d := DefaultConfig()
	if c.AutosaveSeconds != d.AutosaveSeconds {
		t.Errorf("AutosaveSeconds: got %d, want %d", c.AutosaveSeconds, d.AutosaveSeconds)
	}
	if c.AutoLockMinutes != d.AutoLockMinutes {
		t.Errorf("AutoLockMinutes: got %d, want %d", c.AutoLockMinutes, d.AutoLockMinutes)
	}
}

func TestLoadConfig_ZeroAutosaveClamped(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.yaml")
	if err := os.WriteFile(path, []byte("autosave_seconds: 0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c := LoadConfig(path)
	if c.AutosaveSeconds < 1 {
		t.Errorf("AutosaveSeconds should be clamped to at least 1, got %d", c.AutosaveSeconds)
	}
}

func TestLoadConfig_NegativeAutolockClamped(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.yaml")
	if err := os.WriteFile(path, []byte("auto_lock_minutes: -5\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c := LoadConfig(path)
	if c.AutoLockMinutes < 0 {
		t.Errorf("AutoLockMinutes should not be negative, got %d", c.AutoLockMinutes)
	}
}

func TestLoadConfig_ZeroAutolockAllowed(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.yaml")
	if err := os.WriteFile(path, []byte("auto_lock_minutes: 0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c := LoadConfig(path)
	if c.AutoLockMinutes != 0 {
		t.Errorf("AutoLockMinutes of 0 (never lock) should be preserved, got %d", c.AutoLockMinutes)
	}
}
