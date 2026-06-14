package peanalyzer

import (
	"encoding/json"
	"fmt"
	"os"
)

// HashDB holds a set of known malicious SHA256 hashes for fast lookup.
type HashDB struct {
	hashes   map[string]bool
	sourcePath string // path to the JSON file that was loaded
}

// LoadHashDB reads a JSON file whose keys are lowercase hex-encoded SHA256 hashes.
// Values in the JSON object are ignored; only keys are stored.
//
// Example input:
//
//	{
//	    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": null,
//	    "abc123...": "SomeMalwareName"
//	}
func LoadHashDB(path string) (*HashDB, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read hash DB: %w", err)
	}
	// Parse as a generic JSON object – values may be null, string, etc.
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse hash DB JSON: %w", err)
	}
	db := &HashDB{
		hashes:     make(map[string]bool, len(raw)),
		sourcePath: path,
	}
	for k := range raw {
		// Only accept 64-character lowercase hex strings (SHA256 output)
		if len(k) == 64 {
			db.hashes[k] = true
		}
	}
	return db, nil
}

// Contains returns true if the given lowercase hex-encoded SHA256 hash is in the database.
func (db *HashDB) Contains(hash string) bool {
	return db.hashes[hash]
}

// Len returns the number of hashes stored in the database.
func (db *HashDB) Len() int {
	return len(db.hashes)
}

// SourcePath returns the file path the database was loaded from.
func (db *HashDB) SourcePath() string {
	return db.sourcePath
}
