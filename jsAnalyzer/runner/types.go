package runner

import (
	"regexp"
	"time"
)

type Options = AnalyzeOptions

type AnalyzeOptions struct {
	Subdomains bool
	Cloud      bool
	Endpoints  bool
	Params     bool
	Npm        bool
	Secrets    bool

	Timeout     time.Duration
	Retries     int
	MaxSize     int64
	StrictJS    bool
	RawSecrets  bool
	Deobfuscate bool
	MaxFindings int
}

type ScanResult struct {
	URL string `json:"url"`

	Subdomains   []string `json:"subdomains,omitempty"`
	CloudBuckets []string `json:"cloud_buckets,omitempty"`
	Endpoints    []string `json:"endpoints,omitempty"`
	Parameters   []string `json:"parameters,omitempty"`
	NpmPackages  []string `json:"npm_packages,omitempty"`

	EndpointFindings []EndpointFinding `json:"endpoint_findings,omitempty"`
	SecretFindings   []SecretFinding   `json:"secret_findings,omitempty"`
	Signals          []string          `json:"signals,omitempty"`

	Secrets       map[string]struct{} `json:"secrets,omitempty"`
	SecretMatches []*SecretMatch      `json:"secret_matches,omitempty"`
}

type EndpointFinding struct {
	URL     string `json:"url"`
	Kind    string `json:"kind"`
	Source  string `json:"source,omitempty"`
	Context string `json:"context,omitempty"`
}

type SecretFinding struct {
	Source     string `json:"source,omitempty"`
	Type       string `json:"type"`
	Value      string `json:"value,omitempty"`
	Masked     string `json:"masked"`
	Confidence string `json:"confidence"`
	Context    string `json:"context,omitempty"`
}

type AnalysisResult struct {
	Endpoints []EndpointFinding `json:"endpoints,omitempty"`
	Secrets   []SecretFinding   `json:"secrets,omitempty"`
	Signals   []string          `json:"signals,omitempty"`
}

type SecretMatch struct {
	PatternName string `json:"pattern"`
	Value       string `json:"value"`
}

type SecretPattern struct {
	Name string         `json:"name"`
	Re   *regexp.Regexp `json:"-"`
}

type FetchResult struct {
	URL         string
	Body        []byte
	ContentType string
	StatusCode  int
}
