// Command tg-postprocess applies TigerGate's own post-scan rules to raw engine output, so a local run
// approximates what the platform stores. It is built by scripts/local-engine-scan.sh against a TigerGate
// checkout (go.mod replace directives), so the logic is the checkout's, not a copy.
//
// Secrets, in the CLI's order (tools/tigergate-cli/internal/scanner/secrets.go): sort by file, line, rule;
// scanscope.SuppressSecret; scanscope.SecretDeduper collapses a repeated (rule, value); SecretLog records
// what was stored. SAST, in the worker's order (runSemgrepEngine): exact dedupe, findingfold.Cluster, then
// the secret-copy split (scanscope.SuppressSecretCopy, scanscope.RepeatsStoredSecret).
//
// Not reproduced: the CLI's secretAllowlistReason block-comment filter and the worker's severity ranking
// inside dedupe. Values are read to match secrets and are never printed.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tigergate/pkg/findingfold"
	"github.com/tigergate/pkg/scanscope"
)

type pos struct {
	Line   int `json:"line"`
	Col    int `json:"col"`
	Offset int `json:"offset"`
}

type semgrepResult struct {
	CheckID string                 `json:"check_id"`
	Path    string                 `json:"path"`
	Start   pos                    `json:"start"`
	End     pos                    `json:"end"`
	Extra   map[string]interface{} `json:"extra"`
}

type gitleaksFinding struct {
	RuleID    string  `json:"RuleID"`
	File      string  `json:"File"`
	StartLine int     `json:"StartLine"`
	EndLine   int     `json:"EndLine"`
	Match     string  `json:"Match"`
	Secret    string  `json:"Secret"`
	Entropy   float64 `json:"Entropy"`
}

func main() {
	semgrepIn := flag.String("semgrep", "", "semgrep --json output")
	gitleaksIn := flag.String("gitleaks", "", "gitleaks JSON report")
	root := flag.String("root", ".", "scanned repository root")
	outDir := flag.String("out", ".", "directory for the processed reports")
	printScope := flag.Bool("print-scope", false, "print the shared code-scan excludes and excluded upstream rules, then exit")
	flag.Parse()
	if *printScope {
		must(json.NewEncoder(os.Stdout).Encode(map[string][]string{
			"excludes": scanscope.CodeScanExcludes(), "excluded_rules": scanscope.ExcludedUpstreamRules}))
		return
	}

	lines := scanscope.NewLineCache()
	lineOf := func(file string, n int) string { return lines.Line(filepath.Join(*root, file), n) }
	stats := map[string]int{}

	var stored []scanscope.StoredSecret
	if *gitleaksIn != "" {
		var findings []gitleaksFinding
		must(readJSON(*gitleaksIn, &findings))
		sort.SliceStable(findings, func(i, j int) bool {
			a, b := findings[i], findings[j]
			if a.File != b.File {
				return a.File < b.File
			}
			if a.StartLine != b.StartLine {
				return a.StartLine < b.StartLine
			}
			return a.RuleID < b.RuleID
		})
		deduper, log := scanscope.NewSecretDeduper(), scanscope.NewSecretLog()
		kept := []map[string]interface{}{}
		for _, f := range findings {
			line := ""
			if f.RuleID != "private-key" {
				line = lineOf(f.File, f.StartLine)
			}
			if drop, _ := scanscope.SuppressSecret(scanscope.SecretFinding{RuleID: f.RuleID, FilePath: f.File,
				StartLine: f.StartLine, EndLine: f.EndLine, Match: f.Match, Entropy: f.Entropy, Line: line}); drop {
				stats["secrets_suppressed"]++
				continue
			}
			s := scanscope.StoredSecret{File: f.File, StartLine: f.StartLine, EndLine: f.EndLine, Value: f.Secret}
			if !deduper.First(f.RuleID, f.Match) {
				log.Repeated(f.RuleID, f.Match, s)
				stats["secrets_collapsed"]++
				continue
			}
			log.Stored(f.RuleID, f.Match, s)
			// RuleID/File/lines plus the value only (verify-findings fingerprints it); Match is not written.
			kept = append(kept, map[string]interface{}{"RuleID": f.RuleID, "File": f.File, "StartLine": f.StartLine,
				"EndLine": f.EndLine, "Secret": f.Secret})
		}
		stored = log.Secrets
		stats["secrets_stored"] = len(kept)
		must(writeJSON(filepath.Join(*outDir, "secrets.processed.json"), kept))
	}

	if *semgrepIn != "" {
		var report struct {
			Results []semgrepResult          `json:"results"`
			Errors  []map[string]interface{} `json:"errors"`
		}
		must(readJSON(*semgrepIn, &report))
		// Crypto inventory detections leave the report before anything is stored (splitCryptoResults).
		var findings []semgrepResult
		for _, r := range report.Results {
			if meta, _ := r.Extra["metadata"].(map[string]interface{}); meta["cbom"] == nil {
				findings = append(findings, r)
			}
		}
		stats["sast_crypto_inventory"] = len(report.Results) - len(findings)
		results := dedupe(findings)
		stats["sast_exact_duplicates"] = len(findings) - len(results)
		before := len(results)
		results = fold(results)
		stats["sast_folded"] = before - len(results)
		files := map[string][]byte{}
		var kept []semgrepResult
		for _, r := range results {
			if !strings.HasPrefix(r.CheckID, scanscope.SecretCopyRulePrefix) {
				kept = append(kept, r)
				continue
			}
			b, ok := files[r.Path]
			if !ok {
				var err error
				if b, err = os.ReadFile(filepath.Join(*root, r.Path)); err != nil {
					b = nil // unreadable: the match cannot be proven, so the copy is kept
				}
				files[r.Path] = b
			}
			matched := func() (string, bool) {
				if r.Start.Offset < 0 || r.End.Offset > len(b) || r.Start.Offset >= r.End.Offset {
					return "", false
				}
				return string(b[r.Start.Offset:r.End.Offset]), true
			}
			if text, ok := matched(); ok {
				if drop, _ := scanscope.SuppressSecretCopy(r.CheckID, r.Path, text, lineOf(r.Path, r.Start.Line)); drop {
					stats["secret_copies_suppressed"]++
					continue
				}
			}
			if scanscope.RepeatsStoredSecret(stored, r.Path, r.Start.Line, r.End.Line, matched) {
				stats["secret_copies_held_back"]++
				continue
			}
			kept = append(kept, r)
		}
		stats["sast_stored"] = len(kept)
		must(writeJSON(filepath.Join(*outDir, "sast.processed.json"), map[string]interface{}{"results": kept, "errors": report.Errors}))
	}
	must(writeJSON(filepath.Join(*outDir, "postprocess-stats.json"), stats))
	fmt.Println(statsLine(stats))
}

func cwes(r semgrepResult) []string {
	meta, _ := r.Extra["metadata"].(map[string]interface{})
	switch v := meta["cwe"].(type) {
	case string:
		return []string{v}
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, x := range v {
			out = append(out, fmt.Sprint(x))
		}
		return out
	}
	return nil
}

func severity(r semgrepResult) string {
	meta, _ := r.Extra["metadata"].(map[string]interface{})
	if s, _ := meta["tg_severity"].(string); s != "" {
		return s
	}
	s, _ := r.Extra["severity"].(string)
	switch strings.ToUpper(s) {
	case "ERROR":
		return "high"
	case "WARNING":
		return "medium"
	}
	return "low"
}

func items(rs []semgrepResult) []findingfold.Item {
	out := make([]findingfold.Item, 0, len(rs))
	for i, r := range rs {
		msg, _ := r.Extra["message"].(string)
		_, trace := r.Extra["dataflow_trace"]
		out = append(out, findingfold.Item{Key: i, RuleID: r.CheckID, File: r.Path, Line: r.Start.Line,
			Column: r.Start.Col, Severity: severity(r), Message: msg, CWEs: cwes(r), Taint: trace})
	}
	return out
}

func dedupe(rs []semgrepResult) []semgrepResult {
	keep := map[int]bool{}
	for _, k := range findingfold.Dedupe(items(rs)) {
		keep[k] = true
	}
	var out []semgrepResult
	for i, r := range rs {
		if keep[i] {
			out = append(out, r)
		}
	}
	return out
}

func fold(rs []semgrepResult) []semgrepResult {
	drop := map[int]bool{}
	for _, f := range findingfold.Cluster(items(rs)) {
		for _, m := range f.Folded {
			drop[m.Key] = true
		}
	}
	var out []semgrepResult
	for i, r := range rs {
		if !drop[i] {
			out = append(out, r)
		}
	}
	return out
}

func statsLine(s map[string]int) string {
	keys := make([]string, 0, len(s))
	for k := range s {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, s[k]))
	}
	return strings.Join(parts, " ")
}

func readJSON(path string, v interface{}) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func writeJSON(path string, v interface{}) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "tg-postprocess:", err)
		os.Exit(1)
	}
}
