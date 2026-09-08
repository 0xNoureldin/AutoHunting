package test

type Options struct {
	Domain             string
	Timeout            int
	Input              string
	Output             string
	ActiveEnabled      bool
	IncludeSubdomains  bool

	// NEW: split concurrency
	PassiveConcurrency int
	ActiveConcurrency  int

	// Wordlist enables path/content fuzzing against each active seed when
	// set, independently of ActiveEnabled (crawl/headless).
	Wordlist string

	queries []string
}