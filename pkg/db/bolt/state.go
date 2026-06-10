package bolt

import (
	"fmt"

	bolt "go.etcd.io/bbolt"
)

// toolStateBucketName holds opaque per-tool state snapshots (site map, auth
// profiles, annotations, collaborator interactions, WebSocket history), keyed by
// a tool name. This lets the in-memory tool stores survive a restart without
// each one needing its own bucket schema.
var toolStateBucketName = []byte("tool_state")

// SaveState writes an opaque snapshot for the named tool.
func (db *Database) SaveState(key string, data []byte) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(toolStateBucketName)
		if err != nil {
			return fmt.Errorf("bolt: create tool_state bucket: %w", err)
		}
		return b.Put([]byte(key), data)
	})
}

// LoadState reads the snapshot for the named tool. It returns nil (no error)
// when nothing has been stored yet.
func (db *Database) LoadState(key string) ([]byte, error) {
	var out []byte
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(toolStateBucketName)
		if b == nil {
			return nil
		}
		if v := b.Get([]byte(key)); v != nil {
			out = append([]byte(nil), v...)
		}
		return nil
	})
	return out, err
}
