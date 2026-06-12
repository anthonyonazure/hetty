// Package vault saves data (reports, exports, monitoring snapshots) to a
// pluggable set of destinations: a local folder, a network share (UNC path),
// S3-compatible object storage, Azure Blob Storage, Google Drive, or Box. Every
// backend is implemented with the standard library only (raw HTTP + crypto) so
// Hetty stays a single dependency-light binary.
package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// Backend stores objects by key.
type Backend interface {
	// Kind returns the backend type ("local", "s3", "azure", "gdrive", "box").
	Kind() string
	// Put stores data under key and returns a human-readable location.
	Put(ctx context.Context, key string, data []byte, contentType string) (string, error)
}

// Config configures a destination. Only the fields relevant to Kind are used.
type Config struct {
	Kind string `json:"kind"` // local | s3 | azure | gdrive | box

	// local / network share
	Dir string `json:"dir,omitempty"`

	// s3-compatible
	Endpoint  string `json:"endpoint,omitempty"` // https://s3.amazonaws.com or a custom endpoint
	Region    string `json:"region,omitempty"`
	Bucket    string `json:"bucket,omitempty"`
	AccessKey string `json:"accessKey,omitempty"`
	SecretKey string `json:"secretKey,omitempty"`

	// azure blob
	Account    string `json:"account,omitempty"`
	Container  string `json:"container,omitempty"`
	AccountKey string `json:"accountKey,omitempty"`

	// gdrive / box (OAuth bearer token + optional parent folder id). When a
	// RefreshToken (+ClientID/Secret) is supplied, the access token is refreshed
	// before each upload so long-lived saves keep working after the token expires.
	Token        string `json:"token,omitempty"`
	FolderID     string `json:"folderId,omitempty"`
	RefreshToken string `json:"refreshToken,omitempty"`
	ClientID     string `json:"clientId,omitempty"`
	ClientSecret string `json:"clientSecret,omitempty"`
	TokenURL     string `json:"tokenUrl,omitempty"`
}

// New builds a backend from a config.
func New(cfg Config) (Backend, error) {
	switch cfg.Kind {
	case "local", "network":
		if cfg.Dir == "" {
			return nil, fmt.Errorf("vault: local/network destination needs a dir")
		}
		return &localBackend{dir: cfg.Dir}, nil
	case "s3":
		if cfg.Bucket == "" || cfg.AccessKey == "" || cfg.SecretKey == "" {
			return nil, fmt.Errorf("vault: s3 destination needs bucket, accessKey, secretKey")
		}
		return newS3(cfg), nil
	case "azure":
		if cfg.Account == "" || cfg.Container == "" || cfg.AccountKey == "" {
			return nil, fmt.Errorf("vault: azure destination needs account, container, accountKey")
		}
		return newAzure(cfg), nil
	case "gdrive":
		if cfg.Token == "" && cfg.RefreshToken == "" {
			return nil, fmt.Errorf("vault: gdrive destination needs an OAuth token or a refresh token")
		}
		return newGDrive(cfg), nil
	case "box":
		if cfg.Token == "" && cfg.RefreshToken == "" {
			return nil, fmt.Errorf("vault: box destination needs an OAuth token or a refresh token")
		}
		return newBox(cfg), nil
	default:
		return nil, fmt.Errorf("vault: unknown destination kind %q", cfg.Kind)
	}
}

// Save is a convenience that builds the backend and stores data in one call.
func Save(ctx context.Context, cfg Config, key string, data []byte, contentType string) (string, error) {
	b, err := New(cfg)
	if err != nil {
		return "", err
	}
	return b.Put(ctx, key, data, contentType)
}

// --- Local / network-share backend ----------------------------------------

type localBackend struct{ dir string }

func (b *localBackend) Kind() string { return "local" }

func (b *localBackend) Put(_ context.Context, key string, data []byte, _ string) (string, error) {
	// key may contain forward slashes — map to subdirectories under dir.
	clean := filepath.FromSlash(key)
	full := filepath.Join(b.dir, clean)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return "", fmt.Errorf("vault(local): mkdir: %w", err)
	}
	if err := os.WriteFile(full, data, 0o644); err != nil {
		return "", fmt.Errorf("vault(local): write: %w", err)
	}
	return full, nil
}

// --- Named destination store (persisted) -----------------------------------

// Destination is a saved, named destination config.
type Destination struct {
	Name   string `json:"name"`
	Config Config `json:"config"`
}

// Store holds named destinations and persists them (Snapshot/Restore).
type Store struct {
	mu    sync.RWMutex
	dests map[string]Destination
}

// NewStore returns an empty destination store.
func NewStore() *Store { return &Store{dests: map[string]Destination{}} }

// Set adds or replaces a destination.
func (s *Store) Set(d Destination) error {
	if d.Name == "" {
		return fmt.Errorf("vault: destination name is required")
	}
	if _, err := New(d.Config); err != nil {
		return err
	}
	s.mu.Lock()
	s.dests[d.Name] = d
	s.mu.Unlock()
	return nil
}

// Get returns a destination by name.
func (s *Store) Get(name string) (Destination, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.dests[name]
	return d, ok
}

// List returns destinations sorted by name, with secrets redacted.
func (s *Store) List() []Destination {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Destination, 0, len(s.dests))
	for _, d := range s.dests {
		out = append(out, redact(d))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Delete removes a destination.
func (s *Store) Delete(name string) {
	s.mu.Lock()
	delete(s.dests, name)
	s.mu.Unlock()
}

// Snapshot/Restore persist the (unredacted) destinations.
func (s *Store) Snapshot() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return json.Marshal(s.dests)
}

func (s *Store) Restore(data []byte) error {
	var m map[string]Destination
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	if m == nil {
		m = map[string]Destination{}
	}
	s.mu.Lock()
	s.dests = m
	s.mu.Unlock()
	return nil
}

func redact(d Destination) Destination {
	mask := func(s string) string {
		if s == "" {
			return ""
		}
		return "••••"
	}
	d.Config.SecretKey = mask(d.Config.SecretKey)
	d.Config.AccountKey = mask(d.Config.AccountKey)
	d.Config.Token = mask(d.Config.Token)
	d.Config.RefreshToken = mask(d.Config.RefreshToken)
	d.Config.ClientSecret = mask(d.Config.ClientSecret)
	return d
}
