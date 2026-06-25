package signatures

import (
	"encoding/json"
	"fmt"
	"os"
)

type HashDB struct {
	hashes		map[string]bool
	sourcePath	string
}

func LoadHashDB(path string) (*HashDB, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read hash DB: %w", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse hash DB JSON: %w", err)
	}
	db := &HashDB{
		hashes:		make(map[string]bool, len(raw)),
		sourcePath:	path,
	}
	for k := range raw {

		if len(k) == 64 {
			db.hashes[k] = true
		}
	}
	return db, nil
}

func (db *HashDB) Contains(hash string) bool {
	return db.hashes[hash]
}

func (db *HashDB) Len() int {
	return len(db.hashes)
}

func (db *HashDB) SourcePath() string {
	return db.sourcePath
}
