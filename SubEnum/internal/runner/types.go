package runner

type Options struct {
	Query            string
	queries          []string
	InputFile        string
	OutputFile       string
	Concurrency      int
	Timeout          int
	MaxMutationsSize int
	Silent           bool
	Verbose          bool
	ActiveEnabled    bool
	Enrich           bool

	// Wordlist enables DNS brute-force fuzzing (word + "." + domain, probed
	// for a live DNS record) when set, independently of ActiveEnabled.
	Wordlist string

	// Mutations enables alterx permutation-based subdomain guessing
	// (e.g. dev-api, api-dev from a known api subdomain), independently of
	// ActiveEnabled. Off by default: it's a separate opt-in technique, not
	// implied by -active.
	Mutations bool
}
