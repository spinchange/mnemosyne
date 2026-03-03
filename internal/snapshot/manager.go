package snapshot

import (
	"fmt"
	"mnemosyne/internal/crypto"
	"mnemosyne/internal/store"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type SnapshotManager struct {
	store              *store.SQLiteStore
	snapshotDir        string
	writeCount         atomic.Int64
	lastSnapshotWrites int64
	lastSnapshotTime   time.Time
	threshold          int64
	minInterval        time.Duration
	maxSnapshots       int
	mu                 sync.Mutex
	isSnapshotting     atomic.Bool
}

func NewSnapshotManager(s *store.SQLiteStore, dir string) (*SnapshotManager, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create snapshot dir: %w", err)
	}

	return &SnapshotManager{
		store:        s,
		snapshotDir:  dir,
		threshold:    10,
		minInterval:  15 * time.Minute,
		maxSnapshots: 20,
	}, nil
}

func (m *SnapshotManager) SetMaxSnapshots(limit int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if limit > 0 {
		m.maxSnapshots = limit
	}
}

func (m *SnapshotManager) NotifyWrite(dataKey []byte) {
	n := m.writeCount.Add(1)
	
	m.mu.Lock()
	shouldSnapshot := (n-m.lastSnapshotWrites >= m.threshold) &&
		time.Since(m.lastSnapshotTime) >= m.minInterval
	m.mu.Unlock()

	if shouldSnapshot {
		// Deep-copy the key to prevent race condition if Model zeroes it while snapshotting
		keyCopy := make([]byte, len(dataKey))
		copy(keyCopy, dataKey)
		go func() {
			defer crypto.Zero(keyCopy)
			_ = m.TriggerSnapshot(keyCopy, false)
		}()
	}
}

func (m *SnapshotManager) TriggerSnapshot(dataKey []byte, isShutdown bool) error {
	if dataKey == nil {
		return fmt.Errorf("cannot snapshot without data key")
	}

	if !m.isSnapshotting.CompareAndSwap(false, true) {
		return nil // Already in progress
	}
	defer m.isSnapshotting.Store(false)

	id, err := m.store.GetNextSnapshotID()
	if err != nil {
		return fmt.Errorf("get next id: %w", err)
	}

	filename := fmt.Sprintf("snapshot-%05d.msn", id)
	if isShutdown {
		filename = "snapshot-shutdown.msn"
	}
	path := filepath.Join(m.snapshotDir, filename)

	if err := CreateSnapshot(m.store, dataKey, id, path); err != nil {
		return fmt.Errorf("create snapshot: %w", err)
	}

	m.mu.Lock()
	m.lastSnapshotWrites = m.writeCount.Load()
	m.lastSnapshotTime = time.Now()
	m.mu.Unlock()

	if !isShutdown {
		m.rotate()
	}

	return nil
}

func (m *SnapshotManager) rotate() {
	files, err := os.ReadDir(m.snapshotDir)
	if err != nil {
		return
	}

	var snapshots []string
	for _, f := range files {
		if !f.IsDir() && filepath.Ext(f.Name()) == ".msn" && f.Name() != "snapshot-shutdown.msn" {
			snapshots = append(snapshots, f.Name())
		}
	}

	if len(snapshots) <= m.maxSnapshots {
		return
	}

	sort.Strings(snapshots)
	toDelete := len(snapshots) - m.maxSnapshots
	for i := 0; i < toDelete; i++ {
		os.Remove(filepath.Join(m.snapshotDir, snapshots[i]))
	}
}
