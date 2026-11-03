package runner

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/aktezed/urloot/pkg/types"
)

// WriteOutput formats and writes NormalizedURLs to w according to format ("list", "json", or "table").
func WriteOutput(w io.Writer, format string, urls []types.NormalizedURL, params []types.ParamRecord, targetLabel string) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "list":
		for _, u := range urls {
			if _, err := fmt.Fprintln(w, u.URL); err != nil {
				return err
			}
		}
		return nil

	case "json":
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		for _, u := range urls {
			if err := enc.Encode(u); err != nil {
				return err
			}
		}
		return nil

	default:
		PrintTargetSummary(w, targetLabel, urls, params)
		return nil
	}
}

// PrintTargetSummary writes a structured terminal dossier and endpoint table for the collected URLs.
func PrintTargetSummary(w io.Writer, target string, urls []types.NormalizedURL, params []types.ParamRecord) {
	if target == "" {
		target = "ALL TARGETS"
	}
	if len(urls) == 0 {
		fmt.Fprintf(w, "No endpoints discovered for target: %s\n", target)
		return
	}

	var (
		newCount     int
		withParams   int
		uniqueRoutes = make(map[string]struct{})
		uniqueHosts  = make(map[string]struct{})
		sourceCounts = make(map[string]int)
		ssrfURLs     []types.NormalizedURL
	)

	for _, u := range urls {
		if u.IsNew {
			newCount++
		}
		if len(u.Params) > 0 {
			withParams++
		}
		uniqueRoutes[u.RouteHash] = struct{}{}
		uniqueHosts[u.Host] = struct{}{}
		for _, src := range u.Sources {
			sourceCounts[src]++
		}
		if strings.Contains(u.ParamSig, "<url_or_path>") {
			ssrfURLs = append(ssrfURLs, u)
		}
	}

	div := strings.Repeat("═", 86)
	subDiv := strings.Repeat("─", 86)

	fmt.Fprintln(w, div)
	fmt.Fprintf(w, "  ENDPOINT LOOT DOSSIER : %s\n", strings.ToUpper(target))
	fmt.Fprintln(w, div)
	fmt.Fprintf(w, "  Deduplicated URLs      : %-6d  Normalized Routes    : %d\n", len(urls), len(uniqueRoutes))
	fmt.Fprintf(w, "  Parameterized URLs     : %-6d  New In Latest Scan   : %d\n", withParams, newCount)
	fmt.Fprintf(w, "  Distinct Web Hosts     : %-6d  Cataloged Parameters : %d\n", len(uniqueHosts), len(params))
	fmt.Fprintln(w, subDiv)
	fmt.Fprintf(w, "  DISCOVERY PROVENANCE   : wayback=%d  commoncrawl=%d  otx=%d  urlscan=%d  katana=%d\n",
		sourceCounts["wayback"],
		sourceCounts["commoncrawl"],
		sourceCounts["otx"],
		sourceCounts["urlscan"],
		sourceCounts["katana"],
	)

	if len(ssrfURLs) > 0 {
		fmt.Fprintln(w, subDiv)
		fmt.Fprintln(w, "  HIGH-INTEREST PARAMETER TARGETS (URL / Path Value Class):")
		limit := min(len(ssrfURLs), 10)
		for i := range limit {
			u := ssrfURLs[i]
			fmt.Fprintf(w, "    • %-32s -> %s\n", u.EndpointPath, u.URL)
		}
	}

	fmt.Fprintln(w, subDiv)
	fmt.Fprintln(w, "  NORMALIZED ENDPOINTS:")

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  NEW\tMETHOD\tHOST\tENDPOINT PATTERN\tPARAMS\tSOURCES")
	fmt.Fprintln(tw, "  ───\t──────\t────\t────────────────\t──────\t───────")

	// Sort so parameterized and new routes appear first in the summary table
	sorted := slices.Clone(urls)
	slices.SortFunc(sorted, func(a, b types.NormalizedURL) int {
		if a.IsNew != b.IsNew {
			if a.IsNew {
				return -1
			}
			return 1
		}
		if (len(a.Params) > 0) != (len(b.Params) > 0) {
			if len(a.Params) > 0 {
				return -1
			}
			return 1
		}
		return strings.Compare(a.URL, b.URL)
	})

	maxRows := min(len(sorted), 100)
	for i := range maxRows {
		u := sorted[i]
		newMarker := "-"
		if u.IsNew {
			newMarker = "NEW"
		}
		paramStr := "-"
		if len(u.Params) > 0 {
			paramStr = strings.Join(u.Params, ",")
			if len(paramStr) > 24 {
				paramStr = paramStr[:21] + "..."
			}
		}
		pathStr := u.EndpointPath
		if len(pathStr) > 36 {
			pathStr = pathStr[:33] + "..."
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\n",
			newMarker,
			u.Method,
			u.Host,
			pathStr,
			paramStr,
			strings.Join(u.Sources, ","),
		)
	}
	_ = tw.Flush()

	if len(sorted) > maxRows {
		fmt.Fprintf(w, "\n  ... (%d more endpoints omitted from summary; use -o list or -o json for full stream)\n", len(sorted)-maxRows)
	}
	fmt.Fprintln(w, div)
}
