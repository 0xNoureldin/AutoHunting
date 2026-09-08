package main

import (
	"flag"
	"time"

	"github.com/cyinnove/logify"

	"subenum/internal/runner"
)

var options = &runner.Options{}

func main() {
	start := time.Now()
	// Main entry point for the application
	flag.StringVar(&options.Query, "d", "", "domain to enumerate it's domains (acquisitions) sperated by comma")
	flag.IntVar(&options.Timeout, "timeout", 60, "timeout for enumeration (seconds)")
	flag.IntVar(&options.Concurrency, "c", 5, "concurrency level for enumeration")
	flag.StringVar(&options.InputFile, "i", "", "input file for enumeration")
	flag.StringVar(&options.OutputFile, "o", "", "output file for enumeration")
	flag.BoolVar(&options.ActiveEnabled, "active", false, "enable active enumeration (zone transfer)")
	flag.BoolVar(&options.Verbose, "v", false, "verbose output (shows source for each subdomain)")
	flag.BoolVar(&options.Silent, "silent", false, "silent mode (only output results)")
	flag.BoolVar(&options.Mutations, "mutations", false, "enable alterx permutation-based subdomain guessing (e.g. dev-api, api-dev from a known subdomain), independently of -active. Off by default.")
	flag.IntVar(&options.MaxMutationsSize, "max-mutations-size", 0, "max mutations size for each subdomain (only applies when -mutations is set)")
	flag.BoolVar(&options.Enrich, "e", false, "Enrich premutations and mutations process from passive list instead of builtin one (only applies when -mutations is set)")
	flag.StringVar(&options.Wordlist, "w", "", "Wordlist file for DNS brute-force fuzzing (one word per line, enabled independently of -active)")
	flag.Parse()
	if options.Silent {
		logify.MaxLevel = logify.Silent
	}

	if err := runner.Run(options); err != nil {
		logify.Errorf("Error running the tool %v", err)
	}

	elapsed := time.Since(start)
	logify.Infof("Finished in %s", elapsed.Round(time.Millisecond))

}
