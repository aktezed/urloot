package types

// RawURL represents an unnormalized URL discovered by a passive archive or active crawler.
type RawURL struct {
	URL         string `json:"url"`
	Method      string `json:"method,omitempty"`
	Source      string `json:"source"`
	StatusCode  int    `json:"status_code,omitempty"`
	ContentType string `json:"content_type,omitempty"`
}

// NormalizedURL represents a canonicalized, deduplicated URL with route and parameter signatures.
type NormalizedURL struct {
	URLHash      string            `json:"url_hash"`
	RouteHash    string            `json:"route_hash"`
	URL          string            `json:"url"`
	Scheme       string            `json:"scheme"`
	Host         string            `json:"host"`
	Root         string            `json:"root"`
	Method       string            `json:"method"`
	EndpointPath string            `json:"endpoint_path"`
	SamplePath   string            `json:"sample_path"`
	Ext          string            `json:"ext,omitempty"`
	Params       []string          `json:"params,omitempty"`
	ParamsPacked string            `json:"-"`
	ParamTypes   map[string]string `json:"param_types,omitempty"`
	ParamSamples map[string]string `json:"-"`
	ParamSig     string            `json:"param_sig,omitempty"`
	Sources      []string          `json:"source"`
	SourcePacked string            `json:"-"`
	StatusCode   int               `json:"status_code,omitempty"`
	ContentType  string            `json:"content_type,omitempty"`
	FirstSeen    string            `json:"first_seen"`
	LastSeen     string            `json:"last_seen"`
	FirstScan    int64             `json:"-"`
	LastScan     int64             `json:"-"`
	IsNew        bool              `json:"is_new"`
}

// ParamRecord represents a cataloged query parameter on a route in SQLite.
type ParamRecord struct {
	Host         string `json:"host"`
	Root         string `json:"root"`
	EndpointPath string `json:"endpoint_path"`
	ParamName    string `json:"param_name"`
	ValueType    string `json:"value_type"`
	SampleValue  string `json:"sample_value,omitempty"`
	Source       string `json:"source"`
	FirstSeen    string `json:"first_seen"`
	LastSeen     string `json:"last_seen"`
	FirstScan    int64  `json:"first_scan"`
	LastScan     int64  `json:"last_scan"`
	IsNew        bool   `json:"is_new"`
}
