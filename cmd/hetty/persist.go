package main

import (
	"bytes"

	"go.uber.org/zap"

	"github.com/dstotijn/hetty/pkg/db/bolt"
)

// toolStore is an in-memory tool store that can be snapshotted to and restored
// from the database, so its data survives a restart.
type toolStore interface {
	Snapshot() ([]byte, error)
	Restore([]byte) error
}

// restoreStores loads each store's last snapshot from the database at startup.
func restoreStores(db *bolt.Database, stores map[string]toolStore, logger *zap.Logger) {
	for name, st := range stores {
		data, err := db.LoadState(name)
		if err != nil {
			logger.Warn("Failed to load persisted tool state.", zap.String("store", name), zap.Error(err))
			continue
		}
		if err := st.Restore(data); err != nil {
			logger.Warn("Failed to restore tool state.", zap.String("store", name), zap.Error(err))
		}
	}
}

// flushStores writes each store's current snapshot to the database, skipping
// stores whose snapshot is unchanged since the last flush (tracked in last).
func flushStores(db *bolt.Database, stores map[string]toolStore, last map[string][]byte, logger *zap.Logger) {
	for name, st := range stores {
		data, err := st.Snapshot()
		if err != nil {
			logger.Debug("Failed to snapshot tool state.", zap.String("store", name), zap.Error(err))
			continue
		}
		if prev, ok := last[name]; ok && bytes.Equal(prev, data) {
			continue
		}
		if err := db.SaveState(name, data); err != nil {
			logger.Debug("Failed to persist tool state.", zap.String("store", name), zap.Error(err))
			continue
		}
		last[name] = data
	}
}
