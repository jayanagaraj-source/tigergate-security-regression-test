// Command tg-loc runs a TigerGate LOC counter on a directory and prints its result as JSON: the
// CountLinesOfCode totals plus the code lines it gives each counted file.
//
// scripts/local-engine-scan.sh copies one loc.go (the worker's quality/loc.go or the CLI's scanner/loc.go)
// next to this file, renames its package to main and builds both, so the counting logic is the checkout's.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: tg-loc DIR")
		os.Exit(2)
	}
	root := os.Args[1]
	total, err := CountLinesOfCode(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tg-loc:", err)
		os.Exit(1)
	}
	// Same walk and filters as CountLinesOfCode, recording each counted file.
	files := map[string]map[string]interface{}{}
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if _, skip := locSkipDirs[filepath.Base(path)]; skip {
				return filepath.SkipDir
			}
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		spec, ok := locSpecFor(path)
		if !ok || (spec.Name == "yaml" && locYAMLIsConfig(path)) {
			return nil
		}
		fs, generated, err := countFile(path, spec)
		if err != nil || generated {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		files[filepath.ToSlash(rel)] = map[string]interface{}{"language": spec.Name, "code": fs.Code}
		return nil
	})
	out, _ := json.MarshalIndent(map[string]interface{}{"code": total.Code, "files_counted": total.Files,
		"per_language": total.PerLanguage, "files": files}, "", "  ")
	fmt.Println(string(out))
}
