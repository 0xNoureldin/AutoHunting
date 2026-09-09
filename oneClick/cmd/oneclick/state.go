package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// stateFileName is the name of the resume checkpoint file written into
// every run's output directory.
const stateFileName = "oneclick.state.json"

// runConfig snapshots every flag that shapes a run, so a later
// -resume <dir> can reconstruct the exact same run without the user
// retyping every flag identically -- easy to get wrong, and a mismatch
// would leave the resumed run's config out of sync with the phases
// already completed on disk.
type runConfig struct {
	Domain               string `json:"domain"`
	DomainFile           string `json:"domainFile"`
	Active               bool   `json:"active"`
	Concurrency          int    `json:"concurrency"`
	Timeout              int    `json:"timeout"`
	TimeoutSet           bool   `json:"timeoutSet"`
	FuzzSubs             bool   `json:"fuzzSubs"`
	FuzzUrls             bool   `json:"fuzzUrls"`
	Mutations            bool   `json:"mutations"`
	Vhost                bool   `json:"vhost"`
	PortScan             bool   `json:"portScan"`
	AllPorts             bool   `json:"allPorts"`
	PortsSpec            string `json:"portsSpec"`
	Live                 bool   `json:"live"`
	QuietStages          bool   `json:"quietStages"`
	SubsWordlistOverride string `json:"subsWordlistOverride"`
	UrlsWordlistOverride string `json:"urlsWordlistOverride"`
}

// completedPhases tracks which of the pipeline's independently-resumable
// phases finished successfully on a previous run, so -resume can skip
// them and pick up with whatever's left instead of redoing everything.
type completedPhases struct {
	Subdomains bool `json:"subdomains"`
	Vhost      bool `json:"vhost"`
	PortScan   bool `json:"portScan"`
	URLEnum    bool `json:"urlEnum"`
	Secrets    bool `json:"secrets"`
}

// runState is the on-disk resume checkpoint for one output directory.
// It's saved once up front (so an interruption before any phase
// completes can still be resumed with the right config restored) and
// again after every phase completes.
type runState struct {
	Version   int             `json:"version"`
	Config    runConfig       `json:"config"`
	Completed completedPhases `json:"completed"`
	path      string          // where this state lives; not persisted
}

func newRunState(outputDir string, cfg runConfig) *runState {
	return &runState{
		Version: 1,
		Config:  cfg,
		path:    filepath.Join(outputDir, stateFileName),
	}
}

// loadRunState reads a previously-saved checkpoint from outputDir.
func loadRunState(outputDir string) (*runState, error) {
	path := filepath.Join(outputDir, stateFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var st runState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("could not parse %s: %w", path, err)
	}
	st.path = path
	return &st, nil
}

// save persists the current state, overwriting any previous save.
func (s *runState) save() error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o644)
}

// markDone applies update to the completed-phases record and immediately
// persists it, so progress survives an interruption right after this
// phase finishes rather than only being saved at the very end of the run.
func (s *runState) markDone(update func(*completedPhases)) error {
	update(&s.Completed)
	return s.save()
}
