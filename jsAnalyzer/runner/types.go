package runner

import (
	"regexp"
	"time"
)

type AnalyzeOptions struct {
	Subdomains bool
	Cloud      bool
	Endpoints  bool
	Params     bool
	Npm        bool
	Secrets    bool
	Timeout    time.Duration
}

type ScanResult struct {
	URL           string              `json:"url"`
	Subdomains    []string            `json:"subdomains,omitempty"`
	CloudBuckets  []string            `json:"cloud_buckets,omitempty"`
	Endpoints     []string            `json:"endpoints,omitempty"`
	Parameters    []string            `json:"parameters,omitempty"`
	NpmPackages   []string            `json:"npm_packages,omitempty"`
	Secrets       map[string]struct{} `json:"secrets,omitempty"`
	SecretMatches []*SecretMatch      `json:"secret_matches,omitempty"`
}

type SecretMatch struct {
	PatternName string `json:"pattern"`
	Value       string `json:"value"`
}

// SecretGroup is one distinct secret (a pattern+value pair) found across
// one or more scanned URLs, with every URL it was found in listed together
// instead of repeating the secret once per URL.
type SecretGroup struct {
	Pattern string   `json:"pattern"`
	Value   string   `json:"value"`
	URLs    []string `json:"urls"`
}

type SecretPattern struct {
	Name string         `json:"name"`
	Re   *regexp.Regexp `json:"-"`
}
