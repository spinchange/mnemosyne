package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	AutoLockMinutes   int `yaml:"auto_lock_minutes"`
	AutosaveSeconds   int `yaml:"autosave_seconds"`
	SnapshotRetention int `yaml:"snapshot_retention"`
}

func DefaultConfig() Config {
	return Config{
		AutoLockMinutes:   10,
		AutosaveSeconds:   5,
		SnapshotRetention: 20,
	}
}

func LoadConfig(path string) Config {
	c := DefaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		return c
	}
	_ = yaml.Unmarshal(data, &c)
	return c
}

func GetConfigPath(dataDir string) string {
	return filepath.Join(dataDir, "config.yaml")
}
