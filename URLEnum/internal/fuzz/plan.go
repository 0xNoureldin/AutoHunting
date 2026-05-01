package fuzz

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type PlanOptions struct {
	Enabled   bool
	OutDir    string
	Marker    string
	Wordlist  string
	Rate      int
	MinScore  int
}

func (o PlanOptions) withDefaults() PlanOptions {
	if strings.TrimSpace(o.OutDir) == "" {
		o.OutDir = "fuzz-plan"
	}
	if strings.TrimSpace(o.Marker) == "" {
		o.Marker = "FUZZ"
	}
	if strings.TrimSpace(o.Wordlist) == "" {
		o.Wordlist = "payloads.txt"
	}
	if o.Rate <= 0 {
		o.Rate = 20
	}
	return o
}

func WritePlan(urls []string, opts PlanOptions) error {
	if !opts.Enabled {
		return nil
	}
	opts = opts.withDefaults()
	if err := os.MkdirAll(opts.OutDir, 0755); err != nil {
		return err
	}
	results := GenerateAll(urls, opts.Marker, opts.MinScore)
	if err := writeLines(filepath.Join(opts.OutDir, "fuzz.txt"), resultURLs(results)); err != nil {
		return err
	}
	if err := writeLines(filepath.Join(opts.OutDir, "params.txt"), ParamNames(results)); err != nil {
		return err
	}
	return writeLines(filepath.Join(opts.OutDir, "ffuf_commands.sh"), ffufCommands(results, opts))
}

func resultURLs(results []Result) []string {
	out := make([]string, 0, len(results))
	for _, r := range results {
		out = append(out, r.URL)
	}
	return out
}

func ffufCommands(results []Result, opts PlanOptions) []string {
	cmds := make([]string, 0, len(results)+2)
	cmds = append(cmds, "#!/usr/bin/env bash", "set -euo pipefail", "")
	for i, r := range results {
		name := fmt.Sprintf("ffuf-%04d.json", i+1)
		cmds = append(cmds, fmt.Sprintf("ffuf -u %q -w %q -rate %d -timeout 10 -mc all -of json -o %q", r.URL, opts.Wordlist, opts.Rate, filepath.Join(opts.OutDir, name)))
	}
	return cmds
}

func writeLines(path string, lines []string) error {
	sort.Strings(lines)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, line := range lines {
		if _, err := w.WriteString(line + "\n"); err != nil {
			return err
		}
	}
	return w.Flush()
}
