package main

import (
	"path/filepath"
	"testing"
)

func TestRunStateSaveAndLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()

	cfg := runConfig{
		Domain:        "example.com",
		Concurrency:   20,
		Timeout:       120,
		TimeoutSet:    true,
		URLTimeout:    600,
		URLTimeoutSet: true,
		FuzzSubs:      true,
		Vhost:         true,
		PortsSpec:     "80,443,8080",
	}
	st := newRunState(dir, cfg)
	if err := st.save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := loadRunState(dir)
	if err != nil {
		t.Fatalf("loadRunState: %v", err)
	}
	if loaded.Config != cfg {
		t.Errorf("loaded config = %+v, want %+v", loaded.Config, cfg)
	}
	if loaded.Completed != (completedPhases{}) {
		t.Errorf("expected no phases completed yet, got %+v", loaded.Completed)
	}
}

func TestRunStateMarkDonePersists(t *testing.T) {
	dir := t.TempDir()

	st := newRunState(dir, runConfig{Domain: "example.com"})
	if err := st.save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	if err := st.markDone(func(c *completedPhases) { c.Subdomains = true }); err != nil {
		t.Fatalf("markDone: %v", err)
	}
	if err := st.markDone(func(c *completedPhases) { c.URLEnum = true }); err != nil {
		t.Fatalf("markDone: %v", err)
	}

	loaded, err := loadRunState(dir)
	if err != nil {
		t.Fatalf("loadRunState: %v", err)
	}
	want := completedPhases{Subdomains: true, URLEnum: true}
	if loaded.Completed != want {
		t.Errorf("loaded.Completed = %+v, want %+v", loaded.Completed, want)
	}
	// Phases not explicitly marked must stay false rather than being
	// clobbered by a later markDone call overwriting the whole struct.
	if loaded.Completed.Vhost || loaded.Completed.PortScan || loaded.Completed.Secrets {
		t.Errorf("unexpected phase marked done: %+v", loaded.Completed)
	}
}

func TestLoadRunStateMissingFile(t *testing.T) {
	dir := t.TempDir()
	if _, err := loadRunState(filepath.Join(dir, "does-not-exist")); err == nil {
		t.Error("expected an error loading state from a directory with no state file")
	}
}

func TestLoadRunStateCorruptFile(t *testing.T) {
	dir := t.TempDir()
	if err := writeLines(filepath.Join(dir, stateFileName), []string{"not json"}); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRunState(dir); err == nil {
		t.Error("expected an error loading a corrupt state file")
	}
}
