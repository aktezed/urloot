package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aktezed/urloot/pkg/types"
	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    root TEXT NOT NULL,
    started TEXT NOT NULL,
    finished TEXT DEFAULT '',
    opts TEXT DEFAULT '',
    raw_count INT DEFAULT 0,
    unique_count INT DEFAULT 0,
    new_count INT DEFAULT 0
);

CREATE TABLE IF NOT EXISTS endpoint_paths (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    route_hash TEXT NOT NULL UNIQUE,
    host TEXT NOT NULL,
    root TEXT NOT NULL,
    scheme TEXT NOT NULL,
    method TEXT NOT NULL DEFAULT 'GET',
    endpoint_path TEXT NOT NULL,
    sample_path TEXT NOT NULL,
    ext TEXT DEFAULT '',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    first_scan INT NOT NULL,
    last_scan INT NOT NULL,
    is_new INT NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS urls (
    url_hash TEXT PRIMARY KEY,
    route_id INT NOT NULL,
    url TEXT NOT NULL,
    host TEXT NOT NULL,
    root TEXT NOT NULL,
    endpoint_path TEXT NOT NULL,
    params TEXT DEFAULT '',
    param_sig TEXT DEFAULT '',
    source TEXT NOT NULL,
    status_code INT DEFAULT 0,
    content_type TEXT DEFAULT '',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    first_scan INT NOT NULL,
    last_scan INT NOT NULL,
    is_new INT NOT NULL DEFAULT 1,
    FOREIGN KEY (route_id) REFERENCES endpoint_paths(id)
);

CREATE TABLE IF NOT EXISTS params (
    host TEXT NOT NULL,
    root TEXT NOT NULL,
    endpoint_path TEXT NOT NULL,
    param_name TEXT NOT NULL,
    value_type TEXT NOT NULL,
    sample_value TEXT DEFAULT '',
    source TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    first_scan INT NOT NULL,
    last_scan INT NOT NULL,
    is_new INT NOT NULL DEFAULT 1,
    PRIMARY KEY (host, endpoint_path, param_name)
);

CREATE INDEX IF NOT EXISTS idx_scans_root ON scans(root);
CREATE INDEX IF NOT EXISTS idx_paths_root_new ON endpoint_paths(root, is_new);
CREATE INDEX IF NOT EXISTS idx_paths_host ON endpoint_paths(host);
CREATE INDEX IF NOT EXISTS idx_urls_root_new ON urls(root, is_new);
CREATE INDEX IF NOT EXISTS idx_urls_host ON urls(host);
CREATE INDEX IF NOT EXISTS idx_urls_endpoint_path ON urls(endpoint_path);
CREATE INDEX IF NOT EXISTS idx_urls_status ON urls(status_code);
CREATE INDEX IF NOT EXISTS idx_params_root_new ON params(root, is_new);
CREATE INDEX IF NOT EXISTS idx_params_name ON params(param_name);
CREATE INDEX IF NOT EXISTS idx_params_type ON params(value_type);
`

// Store manages embedded SQLite persistence and endpoint diffing.
type Store struct {
	path        string
	db          *sql.DB
	upsertPath  *sql.Stmt
	upsertURL   *sql.Stmt
	upsertParam *sql.Stmt
}

// New opens or initializes a SQLite database at path.
func New(path string, readOnly bool) (*Store, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=temp_store(MEMORY)&_pragma=cache_size(-20000)"
	if readOnly {
		if _, err := os.Stat(path); err != nil {
			return nil, fmt.Errorf("database %q not found: %w", path, err)
		}
		dsn = "file:" + path + "?mode=ro&_pragma=busy_timeout(5000)&_pragma=temp_store(MEMORY)&_pragma=cache_size(-20000)"
	} else if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)

	st := &Store{path: path, db: db}
	if !readOnly {
		if _, err := db.Exec(schema); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("create schema: %w", err)
		}

		st.upsertPath, err = db.Prepare(`
INSERT INTO endpoint_paths (
    route_hash, host, root, scheme, method, endpoint_path, sample_path, ext,
    first_seen, last_seen, first_scan, last_scan, is_new
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1)
ON CONFLICT(route_hash) DO UPDATE SET
    last_seen = excluded.last_seen,
    last_scan = excluded.last_scan,
    is_new = CASE WHEN endpoint_paths.first_scan = excluded.last_scan THEN 1 ELSE 0 END
RETURNING id`)
		if err != nil {
			_ = st.Close()
			return nil, fmt.Errorf("prepare upsertPath: %w", err)
		}

		st.upsertURL, err = db.Prepare(`
INSERT INTO urls (
    url_hash, route_id, url, host, root, endpoint_path, params, param_sig,
    source, status_code, content_type, first_seen, last_seen, first_scan, last_scan, is_new
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)
ON CONFLICT(url_hash) DO UPDATE SET
    last_seen = excluded.last_seen,
    last_scan = excluded.last_scan,
    status_code = CASE WHEN excluded.status_code <> 0 THEN excluded.status_code ELSE urls.status_code END,
    content_type = CASE WHEN excluded.content_type <> '' THEN excluded.content_type ELSE urls.content_type END,
    source = CASE
        WHEN instr(',' || urls.source || ',', ',' || excluded.source || ',') > 0 THEN urls.source
        ELSE urls.source || ',' || excluded.source
    END,
    is_new = CASE WHEN urls.first_scan = excluded.last_scan THEN 1 ELSE 0 END
RETURNING is_new, first_seen, source, status_code, content_type`)
		if err != nil {
			_ = st.Close()
			return nil, fmt.Errorf("prepare upsertURL: %w", err)
		}

		st.upsertParam, err = db.Prepare(`
INSERT INTO params (
    host, root, endpoint_path, param_name, value_type, sample_value,
    source, first_seen, last_seen, first_scan, last_scan, is_new
) VALUES (?,?,?,?,?,?,?,?,?,?,?,1)
ON CONFLICT(host, endpoint_path, param_name) DO UPDATE SET
    last_seen = excluded.last_seen,
    last_scan = excluded.last_scan,
    source = CASE
        WHEN instr(',' || params.source || ',', ',' || excluded.source || ',') > 0 THEN params.source
        ELSE params.source || ',' || excluded.source
    END,
    is_new = CASE WHEN params.first_scan = excluded.last_scan THEN 1 ELSE 0 END`)
		if err != nil {
			_ = st.Close()
			return nil, fmt.Errorf("prepare upsertParam: %w", err)
		}
	}

	return st, nil
}

// Close releases prepared statements and closes the database connection.
func (s *Store) Close() error {
	if s.upsertPath != nil {
		_ = s.upsertPath.Close()
	}
	if s.upsertURL != nil {
		_ = s.upsertURL.Close()
	}
	if s.upsertParam != nil {
		_ = s.upsertParam.Close()
	}
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// BeginScan records a new scan session and resets is_new=0 for prior records belonging to roots.
func (s *Store) BeginScan(roots []string, optsJSON string) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	rootLabel := strings.Join(roots, ",")
	if rootLabel == "" {
		rootLabel = "default"
	}

	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.Exec(
		`INSERT INTO scans (root, started, opts) VALUES (?, ?, ?)`,
		rootLabel, now, optsJSON,
	)
	if err != nil {
		return 0, err
	}
	scanID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}

	if len(roots) > 0 {
		for _, r := range roots {
			r = strings.ToLower(strings.TrimSpace(r))
			if r == "" {
				continue
			}
			if _, err := tx.Exec(`UPDATE endpoint_paths SET is_new = 0 WHERE root = ? OR host = ?`, r, r); err != nil {
				return 0, err
			}
			if _, err := tx.Exec(`UPDATE urls SET is_new = 0 WHERE root = ? OR host = ?`, r, r); err != nil {
				return 0, err
			}
			if _, err := tx.Exec(`UPDATE params SET is_new = 0 WHERE root = ? OR host = ?`, r, r); err != nil {
				return 0, err
			}
		}
	} else {
		if _, err := tx.Exec(`UPDATE endpoint_paths SET is_new = 0`); err != nil {
			return 0, err
		}
		if _, err := tx.Exec(`UPDATE urls SET is_new = 0`); err != nil {
			return 0, err
		}
		if _, err := tx.Exec(`UPDATE params SET is_new = 0`); err != nil {
			return 0, err
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return scanID, nil
}

// BatchUpsert persists a slice of NormalizedURLs inside a single SQLite transaction,
// updating each item's IsNew, FirstSeen, Sources, StatusCode, and ContentType in place.
func (s *Store) BatchUpsert(scanID int64, items []*types.NormalizedURL) (int, error) {
	if len(items) == 0 {
		return 0, nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	pathSt := tx.Stmt(s.upsertPath)
	urlSt := tx.Stmt(s.upsertURL)
	paramSt := tx.Stmt(s.upsertParam)

	newCount := 0
	for _, item := range items {
		if item == nil {
			continue
		}
		var routeID int64
		err := pathSt.QueryRow(
			item.RouteHash,
			item.Host,
			item.Root,
			item.Scheme,
			item.Method,
			item.EndpointPath,
			item.SamplePath,
			item.Ext,
			item.FirstSeen,
			item.LastSeen,
			scanID,
			scanID,
		).Scan(&routeID)
		if err != nil {
			return 0, fmt.Errorf("upsert endpoint_path %s: %w", item.EndpointPath, err)
		}

		var (
			isNewInt    int
			firstSeenDB string
			sourceDB    string
			statusDB    int
			ctypeDB     string
		)
		err = urlSt.QueryRow(
			item.URLHash,
			routeID,
			item.URL,
			item.Host,
			item.Root,
			item.EndpointPath,
			item.ParamsPacked,
			item.ParamSig,
			item.SourcePacked,
			item.StatusCode,
			item.ContentType,
			item.FirstSeen,
			item.LastSeen,
			scanID,
			scanID,
		).Scan(&isNewInt, &firstSeenDB, &sourceDB, &statusDB, &ctypeDB)
		if err != nil {
			return 0, fmt.Errorf("upsert url %s: %w", item.URL, err)
		}

		item.IsNew = isNewInt == 1
		item.FirstSeen = firstSeenDB
		item.SourcePacked = sourceDB
		if sourceDB != "" {
			item.Sources = strings.Split(sourceDB, ",")
		}
		item.StatusCode = statusDB
		item.ContentType = ctypeDB
		if item.IsNew {
			newCount++
		}

		for _, pName := range item.Params {
			valType := item.ParamTypes[pName]
			sampleVal := item.ParamSamples[pName]
			if _, err := paramSt.Exec(
				item.Host,
				item.Root,
				item.EndpointPath,
				pName,
				valType,
				sampleVal,
				item.SourcePacked,
				item.FirstSeen,
				item.LastSeen,
				scanID,
				scanID,
			); err != nil {
				return 0, fmt.Errorf("upsert param %s: %w", pName, err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return newCount, nil
}

// FinishScan records completion timestamp and summary counts for scanID.
func (s *Store) FinishScan(scanID int64, rawCount, uniqueCount, newCount int) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(
		`UPDATE scans SET finished = ?, raw_count = ?, unique_count = ?, new_count = ? WHERE id = ?`,
		now, rawCount, uniqueCount, newCount, scanID,
	)
	return err
}
