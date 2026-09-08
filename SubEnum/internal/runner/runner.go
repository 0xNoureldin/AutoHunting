package runner

import (
	"net/http"
	"strings"

	"subenum/pkg/active/alterx"
	dnsprobe "subenum/pkg/active/dnsbrobe"
	"subenum/pkg/active/zonetransfer"
	"subenum/pkg/scraper"
	"subenum/pkg/scraper/sources"
	"subenum/pkg/utils"

	"github.com/cyinnove/logify"
)

func Run(opts *Options) error {
	queries, err := loadQueries(opts)
	if err != nil {
		return err
	}

	srcs, client, err := loadSources(opts)
	if err != nil {
		return err
	}

	wordlist, err := loadWordlist(opts)
	if err != nil {
		return err
	}

	set := newDomainSet(opts.Verbose)

	for _, q := range queries {
		logify.Infof("Starting passive enumeration for: %s", q)

		queryCount := runPassive(q, srcs, client, opts, set)

		if opts.ActiveEnabled {
			queryCount += runZoneTransfer(q, opts, set)
		}

		if len(wordlist) > 0 {
			queryCount += runWordlistBruteForce(q, wordlist, opts, set)
		}

		logify.Infof("Query %s: Found %d unique subdomain(s) (Total: %d)", q, queryCount, set.Len())
	}

	uniqueSubdomains := set.Slice()
	logify.Infof("Passive enumeration completed: Found %d unique subdomain(s)", len(uniqueSubdomains))

	if opts.ActiveEnabled {
		newActiveCount, err := runActive(uniqueSubdomains, opts, set)
		if err != nil {
			return err
		}
		uniqueSubdomains = set.Slice()
		logify.Infof("Active enumeration completed: Found %d new subdomain(s) (Total: %d)", newActiveCount, set.Len())
	}

	if opts.OutputFile != "" {
		if err := utils.WriteOutputToFile(opts.OutputFile, uniqueSubdomains); err != nil {
			logify.Fatalf("Error writing output file: %s", err)
		}
	}

	return nil
}

/* ---------------- Helpers ---------------- */

func loadQueries(opts *Options) ([]string, error) {
	// read queries from direct input
	opts.queries = utils.ExtractDomainsFromString(opts.Query)

	if opts.Query == "" && opts.InputFile == "" {
		logify.Fatalf("No input or file specified")
	}

	// or from file
	if opts.InputFile != "" {
		q, err := utils.ReadInputFromFile(opts.InputFile)
		if err != nil {
			logify.Fatalf("Error reading input file %s: %s", opts.InputFile, err)
		}
		opts.queries = q
	}

	if len(opts.queries) == 0 {
		logify.Fatalf("No input or file specified")
	}

	return opts.queries, nil
}

func loadWordlist(opts *Options) ([]string, error) {
	if opts.Wordlist == "" {
		return nil, nil
	}

	words, err := utils.ReadInputFromFile(opts.Wordlist)
	if err != nil {
		return nil, err
	}

	cleaned := make([]string, 0, len(words))
	for _, w := range words {
		w = strings.TrimSpace(w)
		if w != "" && !strings.HasPrefix(w, "#") {
			cleaned = append(cleaned, w)
		}
	}

	logify.Infof("Loaded %d wordlist entries for DNS brute-force from %s", len(cleaned), opts.Wordlist)
	return cleaned, nil
}

func loadSources(opts *Options) ([]scraper.Source, *http.Client, error) {
	apiKeys, err := scraper.ExtractALLAPIKeys()
	if err != nil {
		logify.Fatalf("Error extracting API keys: %s", err)
	}

	client := scraper.NewSession(opts.Timeout)
	srcs := sources.GetAllSources(apiKeys)

	logify.Infof("Loaded %d source(s) for enumeration", len(srcs))
	return srcs, client, nil
}

func runPassive(q string, srcs []scraper.Source, client *http.Client, opts *Options, set *domainSet) int {
	count := 0

	for _, src := range srcs {
		domains, err := src.Search(q, client)
		if err != nil {
			if opts.Verbose {
				logify.Errorf("Source %s failed: %s", src.Name(), err)
			}
			continue
		}

		for _, d := range domains {
			if shouldSkip(d) {
				continue
			}
			if set.Add(d) {
				count++
			}
		}
	}

	return count
}

func runZoneTransfer(q string, opts *Options, set *domainSet) int {
	if !zonetransfer.IsVulnerable(q, opts.Timeout) {
		return 0
	}

	logify.Infof("Zone transfer vulnerability detected for %s", q)

	zoneSubs, err := zonetransfer.GetSubdomains(q, opts.Timeout)
	if err != nil {
		logify.Errorf("Zone transfer failed for %s: %s", q, err)
		return 0
	}

	added := 0
	for _, s := range zoneSubs {
		if set.Add(s) {
			added++
		}
	}

	logify.Infof("Zone transfer discovered %d subdomain(s) for %s", len(zoneSubs), q)
	return added
}

// dnsProbeTimeoutSeconds caps the per-resolver timeout used for wordlist
// brute-force DNS probes. It is intentionally decoupled from opts.Timeout,
// which is calibrated for HTTP passive-source fetches (tens of seconds to
// minutes): dnsprobe.ProbeSubdomains tries up to len(client.DefaultResolvers)
// resolvers per candidate, so reusing a long HTTP timeout there means a
// handful of unreachable/slow resolvers can multiply into a per-candidate
// worst case of minutes, and that compounds badly across a wordlist of
// thousands of candidates. DNS answers fast when it answers at all, so a
// short cap keeps a large brute-force run tractable without materially
// harming accuracy.
const dnsProbeTimeoutSeconds = 5

// runWordlistBruteForce builds a candidate subdomain for every wordlist
// entry ("word" + "." + q), concurrently DNS-probes them, and adds the
// ones with a live record to set.
func runWordlistBruteForce(q string, wordlist []string, opts *Options, set *domainSet) int {
	candidates := make([]string, 0, len(wordlist))
	for _, w := range wordlist {
		candidates = append(candidates, w+"."+q)
	}

	dnsTimeout := dnsProbeTimeoutSeconds
	if opts.Timeout > 0 && opts.Timeout < dnsTimeout {
		dnsTimeout = opts.Timeout
	}

	logify.Infof("Starting DNS brute-force for %s: %d candidate(s)", q, len(candidates))
	alive := dnsprobe.ProbeSubdomains(candidates, dnsTimeout, opts.Concurrency)

	added := 0
	for _, s := range alive {
		if set.Add(s) {
			added++
		}
	}

	logify.Infof("DNS brute-force discovered %d subdomain(s) for %s", added, q)
	return added
}

func runActive(uniqueSubdomains []string, opts *Options, set *domainSet) (int, error) {
	logify.Infof("Starting active enumeration for %d subdomain(s)", len(uniqueSubdomains))

	mutationSubs, err := alterx.RunMutator(uniqueSubdomains, opts.MaxMutationsSize, opts.Enrich)
	if err != nil {
		logify.Errorf("Mutation generation failed: %s", err)
		return 0, err
	}
	logify.Infof("Generated %d mutation(s)", len(mutationSubs))

	alive := dnsprobe.ProbeSubdomains(mutationSubs, opts.Timeout, opts.Concurrency)

	newCount := 0
	for _, s := range alive {
		if set.Add(s) {
			newCount++
		}
	}
	return newCount, nil
}

func shouldSkip(domain string) bool {
	// keep your existing filters
	if strings.Contains(domain, "playat") || strings.Contains(domain, "••") {
		return true
	}
	return false
}

/* ---------------- Set with logging ---------------- */

type domainSet struct {
	m       map[string]struct{}
	verbose bool
}

func newDomainSet(verbose bool) *domainSet {
	return &domainSet{
		m:       make(map[string]struct{}),
		verbose: verbose,
	}
}

func (s *domainSet) Add(domain string) bool {
	if _, ok := s.m[domain]; ok {
		return false
	}
	s.m[domain] = struct{}{}

	// Keep same behavior: print new domains immediately
	logify.Silentf("%s", domain)
	return true
}

func (s *domainSet) Len() int { return len(s.m) }

func (s *domainSet) Slice() []string {
	out := make([]string, 0, len(s.m))
	for d := range s.m {
		out = append(out, d)
	}
	return out
}
