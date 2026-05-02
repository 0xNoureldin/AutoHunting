package nuclei

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type PlanOptions struct {
	Enabled bool
	OutDir  string
	Rate    int
	Tags    []string
}

func (o PlanOptions) withDefaults() PlanOptions {
	if strings.TrimSpace(o.OutDir) == "" {
		o.OutDir = "nuclei-plan"
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
	targets := uniqueTargets(urls)
	tags := recommendTags(urls, opts.Tags)
	if err := writeLines(filepath.Join(opts.OutDir, "nuclei_targets.txt"), targets); err != nil {
		return err
	}
	if err := writeLines(filepath.Join(opts.OutDir, "nuclei_tags.txt"), tags); err != nil {
		return err
	}
	return writeLines(filepath.Join(opts.OutDir, "nuclei_commands.sh"), commands(opts, tags))
}

func uniqueTargets(urls []string) []string {
	seen := map[string]struct{}{}
	for _, raw := range urls {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.Scheme == "" || u.Host == "" {
			continue
		}
		seen[u.Scheme+"://"+strings.ToLower(u.Host)] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func recommendTags(urls []string, extra []string) []string {
	seen := map[string]struct{}{}
	add := func(tag string) {
		tag = strings.TrimSpace(strings.ToLower(tag))
		if tag != "" {
			seen[tag] = struct{}{}
		}
	}
	for _, tag := range extra {
		add(tag)
	}
	for _, raw := range urls {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		p := strings.ToLower(u.Path)
		q := strings.ToLower(u.RawQuery)
		if strings.Contains(p, "graphql") || strings.Contains(q, "graphql") {
			add("graphql")
		}
		if strings.Contains(p, "swagger") || strings.Contains(p, "openapi") || strings.Contains(p, "api-docs") {
			add("swagger")
		}
		if strings.Contains(p, "admin") || strings.Contains(p, "login") || strings.Contains(p, "dashboard") {
			add("exposure")
		}
		if strings.Contains(q, "redirect") || strings.Contains(q, "next") || strings.Contains(q, "url=") {
			add("redirect")
		}
		if strings.Contains(q, "file") || strings.Contains(q, "path") || strings.Contains(q, "download") {
			add("lfi")
		}
	}
	add("exposure")
	add("misconfig")
	out := make([]string, 0, len(seen))
	for tag := range seen {
		out = append(out, tag)
	}
	sort.Strings(out)
	return out
}

func commands(opts PlanOptions, tags []string) []string {
	tagArg := strings.Join(tags, ",")
	targetsPath := filepath.ToSlash(filepath.Join(opts.OutDir, "nuclei_targets.txt"))
	resultsPath := filepath.ToSlash(filepath.Join(opts.OutDir, "nuclei-results.txt"))
	return []string{
		"#!/usr/bin/env bash",
		"set -euo pipefail",
		"",
		fmt.Sprintf("nuclei -l %q -tags %q -rate-limit %d -o %q", targetsPath, tagArg, opts.Rate, resultsPath),
	}
}

func writeLines(path string, lines []string) error {
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
