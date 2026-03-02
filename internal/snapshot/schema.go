package snapshot

import (
	"mnemosyne/internal/domain"
	"time"
)

type Snapshot struct {
	SchemaVersion int               `json:"schema_version"`
	AppVersion    string            `json:"app_version"`
	SnapshotID    uint64            `json:"snapshot_id"`
	CreatedAt     time.Time         `json:"created_at"`
	EntryCount    int               `json:"entry_count"`
	Entries       []domain.Entry    `json:"entries"`
	Triggers      []domain.Trigger `json:"triggers"`
}
