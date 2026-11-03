package store

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"

	"github.com/aktezed/urloot/pkg/types"
)

// QueryURLs retrieves deduplicated URLs matching the filter criteria in opts.
func (s *Store) QueryURLs(opts *types.Options) ([]types.NormalizedURL, error) {
	var (
		where []string
		args  []any
	)

	if opts.NewOnly {
		where = append(where, "u.is_new = 1")
	}
	if root := strings.ToLower(strings.TrimSpace(opts.Target)); root != "" {
		where = append(where, "(u.root = ? OR u.host = ?)")
		args = append(args, root, root)
	}
	if host := strings.ToLower(strings.TrimSpace(opts.Host)); host != "" {
		where = append(where, "u.host = ?")
		args = append(args, host)
	}
	if p := strings.TrimSpace(opts.Path); p != "" {
		where = append(where, `u.endpoint_path LIKE ? ESCAPE '\'`)
		args = append(args, "%"+escapeLike(p)+"%")
	}
	if opts.HasParams {
		where = append(where, "u.params <> ''")
	}
	if len(opts.Params) > 0 {
		var clauses []string
		for _, param := range opts.Params {
			clean := strings.ToLower(strings.TrimSpace(param))
			if clean == "" {
				continue
			}
			clauses = append(clauses, `u.params LIKE ? ESCAPE '\'`)
			args = append(args, "%,"+escapeLike(clean)+",%")
		}
		if len(clauses) > 0 {
			where = append(where, "("+strings.Join(clauses, " OR ")+")")
		}
	}
	if len(opts.ParamType) > 0 {
		var placeholders []string
		for _, pt := range opts.ParamType {
			clean := strings.ToLower(strings.TrimSpace(pt))
			if clean == "" {
				continue
			}
			placeholders = append(placeholders, "?")
			args = append(args, clean)
		}
		if len(placeholders) > 0 {
			where = append(where, fmt.Sprintf(
				"EXISTS (SELECT 1 FROM params p WHERE p.host = u.host AND p.endpoint_path = u.endpoint_path AND p.value_type IN (%s))",
				strings.Join(placeholders, ","),
			))
		}
	}
	if len(opts.Sources) > 0 {
		var clauses []string
		for _, src := range opts.Sources {
			clean := strings.ToLower(strings.TrimSpace(src))
			if clean == "" {
				continue
			}
			clauses = append(clauses, `',' || u.source || ',' LIKE ? ESCAPE '\'`)
			args = append(args, "%,"+escapeLike(clean)+",%")
		}
		if len(clauses) > 0 {
			where = append(where, "("+strings.Join(clauses, " OR ")+")")
		}
	}
	if len(opts.Ext) > 0 {
		var placeholders []string
		for _, ext := range opts.Ext {
			clean := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(ext)), ".")
			if clean == "" {
				continue
			}
			placeholders = append(placeholders, "?")
			args = append(args, clean)
		}
		if len(placeholders) > 0 {
			where = append(where, fmt.Sprintf("ep.ext IN (%s)", strings.Join(placeholders, ",")))
		}
	}
	if strings.TrimSpace(opts.Status) != "" {
		var placeholders []string
		for part := range strings.SplitSeq(opts.Status, ",") {
			if code, err := strconv.Atoi(strings.TrimSpace(part)); err == nil {
				placeholders = append(placeholders, "?")
				args = append(args, code)
			}
		}
		if len(placeholders) > 0 {
			where = append(where, fmt.Sprintf("u.status_code IN (%s)", strings.Join(placeholders, ",")))
		}
	}

	query := `
SELECT
    u.url_hash, ep.route_hash, u.url, ep.scheme, u.host, u.root, ep.method,
    u.endpoint_path, ep.sample_path, ep.ext, u.params, u.param_sig, u.source,
    u.status_code, u.content_type, u.first_seen, u.last_seen, u.is_new
FROM urls u
JOIN endpoint_paths ep ON ep.id = u.route_id`

	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY u.is_new DESC, u.host ASC, u.endpoint_path ASC, u.url ASC"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []types.NormalizedURL
	for rows.Next() {
		var item types.NormalizedURL
		if err := rows.Scan(
			&item.URLHash,
			&item.RouteHash,
			&item.URL,
			&item.Scheme,
			&item.Host,
			&item.Root,
			&item.Method,
			&item.EndpointPath,
			&item.SamplePath,
			&item.Ext,
			&item.ParamsPacked,
			&item.ParamSig,
			&item.SourcePacked,
			&item.StatusCode,
			&item.ContentType,
			&item.FirstSeen,
			&item.LastSeen,
			&item.IsNew,
		); err != nil {
			return nil, err
		}
		if trimmed := strings.Trim(item.ParamsPacked, ","); trimmed != "" {
			item.Params = strings.Split(trimmed, ",")
		}
		if item.SourcePacked != "" {
			item.Sources = strings.Split(item.SourcePacked, ",")
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// QueryParams returns cataloged parameters for a root domain (or all roots if root == "").
func (s *Store) QueryParams(root string, newOnly bool) ([]types.ParamRecord, error) {
	var (
		where []string
		args  []any
	)
	if root = strings.ToLower(strings.TrimSpace(root)); root != "" {
		where = append(where, "(root = ? OR host = ?)")
		args = append(args, root, root)
	}
	if newOnly {
		where = append(where, "is_new = 1")
	}

	q := `SELECT host, root, endpoint_path, param_name, value_type, sample_value, source, first_seen, last_seen, first_scan, last_scan, is_new FROM params`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY is_new DESC, param_name ASC"

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []types.ParamRecord
	for rows.Next() {
		var r types.ParamRecord
		if err := rows.Scan(
			&r.Host, &r.Root, &r.EndpointPath, &r.ParamName, &r.ValueType,
			&r.SampleValue, &r.Source, &r.FirstSeen, &r.LastSeen,
			&r.FirstScan, &r.LastScan, &r.IsNew,
		); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RunRawSQL executes a custom read-only SQL query using a mode=ro connection.
func RunRawSQL(dbPath, rawQuery string) ([]string, [][]string, error) {
	roDSN := "file:" + dbPath + "?mode=ro&_pragma=busy_timeout(5000)&_pragma=query_only(ON)"
	roDB, err := sql.Open("sqlite", roDSN)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = roDB.Close() }()

	rows, err := roDB.Query(rawQuery)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = rows.Close() }()

	cols, err := rows.Columns()
	if err != nil {
		return nil, nil, err
	}

	var results [][]string
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}

	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return nil, nil, err
		}
		rowStr := make([]string, len(cols))
		for i, v := range vals {
			if v == nil {
				rowStr[i] = ""
			} else {
				rowStr[i] = fmt.Sprintf("%v", v)
			}
		}
		results = append(results, rowStr)
	}
	return cols, results, rows.Err()
}

func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}
