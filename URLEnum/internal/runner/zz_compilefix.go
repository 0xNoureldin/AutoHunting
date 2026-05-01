package runner

import "errors"

var ErrNoInput = errors.New("no domain or input file provided")

// runnerCompat intentionally keeps legacy runner.go compiling while RunPipeline
// is the preferred execution path.
func (opts *Options) ensureQueries(q []string) {
	opts.queries = q
}
