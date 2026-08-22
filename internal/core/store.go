package core

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/ssyno/evidenced/evidence"
)

// Store is where sealed evidence records live. Implementations are
// append-only: records are never updated or deleted.
type Store interface {
	// Append seals r into the store's hash chain and persists it.
	Append(r *evidence.Record) error
	// All returns every record in chain order.
	All() ([]evidence.Record, error)
	// Verify checks the integrity of the full chain.
	Verify() error
	Close() error
}

// FileStore persists records as one JSON object per line. On open it
// replays the file to verify the chain and resume it at the last hash.
type FileStore struct {
	mu    sync.Mutex
	path  string
	f     *os.File
	chain *evidence.Chain
	count int
}

// OpenFileStore opens or creates the store at path. An existing file is
// fully verified before any new record can be appended, so a store that
// was tampered with while the process was down refuses to open.
func OpenFileStore(path string) (*FileStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create store directory: %w", err)
	}
	existing, err := readRecords(path)
	if err != nil {
		return nil, err
	}
	if err := evidence.Verify(existing); err != nil {
		return nil, fmt.Errorf("verify existing store %s: %w", path, err)
	}
	last := ""
	if len(existing) > 0 {
		last = existing[len(existing)-1].Hash
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- path comes from operator-supplied config
	if err != nil {
		return nil, fmt.Errorf("open store %s: %w", path, err)
	}
	return &FileStore{path: path, f: f, chain: evidence.Resume(last), count: len(existing)}, nil
}

func (s *FileStore) Append(r *evidence.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.chain.Seal(r); err != nil {
		return err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("encode record %s: %w", r.ID, err)
	}
	if _, err := s.f.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("write record %s: %w", r.ID, err)
	}
	if err := s.f.Sync(); err != nil {
		return fmt.Errorf("sync store: %w", err)
	}
	s.count++
	return nil
}

func (s *FileStore) All() ([]evidence.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return readRecords(s.path)
}

func (s *FileStore) Verify() error {
	records, err := s.All()
	if err != nil {
		return err
	}
	return evidence.Verify(records)
}

// Count returns the number of records currently in the store.
func (s *FileStore) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}

func (s *FileStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}

// ReadStoreRecords reads a store file without opening it for writing —
// for read-only inspection alongside a running writer.
func ReadStoreRecords(path string) ([]evidence.Record, error) {
	return readRecords(path)
}

func readRecords(path string) ([]evidence.Record, error) {
	f, err := os.Open(path) // #nosec G304 -- path comes from operator-supplied config
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open store %s: %w", path, err)
	}
	defer f.Close() //nolint:errcheck // read-only handle

	var records []evidence.Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		if len(sc.Bytes()) == 0 {
			continue
		}
		var r evidence.Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return nil, fmt.Errorf("store %s line %d: decode record: %w", path, line, err)
		}
		records = append(records, r)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read store %s: %w", path, err)
	}
	return records, nil
}
