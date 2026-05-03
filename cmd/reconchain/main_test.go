package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestBuildURLTargetsIncludesRootsAndSubdomains(t *testing.T) {
	dir := t.TempDir()
	subdomains := filepath.Join(dir, "subdomains.txt")
	if err := os.WriteFile(subdomains, []byte("api.example.com\nwww.example.com\napi.example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}

	got, err := buildURLTargets([]string{"example.com"}, subdomains, true)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"api.example.com", "example.com", "www.example.com"}
	if !slices.Equal(got, want) {
		t.Fatalf("unexpected targets: want %v got %v", want, got)
	}
}

func TestBuildURLTargetsErrorsWhenEmpty(t *testing.T) {
	_, err := buildURLTargets(nil, filepath.Join(t.TempDir(), "missing.txt"), false)
	if err == nil {
		t.Fatal("expected empty target error")
	}
}

func TestBuildSubEnumCommand(t *testing.T) {
	p := paths{
		SubEnumDir: "SubEnum",
		Subdomains: filepath.Join("out", "subdomains.txt"),
	}
	cmd := buildSubEnumCommand(options{
		Domain:             "example.com",
		SubTimeout:         45,
		SubConcurrency:     7,
		SubActive:          true,
		SubMaxMutationSize: 50,
		SubEnrich:          true,
	}, p)

	joined := strings.Join(append([]string{cmd.Name}, cmd.Args...), " ")
	for _, expected := range []string{
		"go run ./cmd/subenum",
		"-d example.com",
		"-o " + p.Subdomains,
		"-timeout 45",
		"-c 7",
		"-active",
		"-max-mutations-size 50",
		"-e",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("expected %q in command %q", expected, joined)
		}
	}
}

func TestBuildURLEnumCommandEnablesJSSecrets(t *testing.T) {
	p := paths{
		URLEnumDir:  "URLEnum",
		URLTargets:  filepath.Join("out", "urlenum-targets.txt"),
		URLs:        filepath.Join("out", "urls.txt"),
		WorkflowDir: filepath.Join("out", "workflow"),
		JSOutDir:    filepath.Join("out", "js-secrets"),
	}
	cmd := buildURLEnumCommand(options{
		URLTimeout:     30,
		URLConcurrency: 8,
		URLDepth:       3,
		URLMaxSeeds:    300,
		URLHeadless:    false,
		URLDedupe:      "param",
		Workflow:       true,
		WorkflowScore:  70,
		JSSecrets:      true,
		JSConcurrency:  4,
		JSTimeout:      20,
		JSRetries:      2,
		JSMaxSize:      1024,
		JSRawSecrets:   true,
	}, p)

	joined := strings.Join(append([]string{cmd.Name}, cmd.Args...), " ")
	for _, expected := range []string{
		"go run ./cmd/URLEnum",
		"-i " + p.URLTargets,
		"-o " + p.URLs,
		"-headless=false",
		"-workflow",
		"-workflow-out " + p.WorkflowDir,
		"-workflow-score 70",
		"-js-secrets",
		"-js-out " + p.JSOutDir,
		"-js-c 4",
		"-js-raw-secrets=true",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("expected %q in command %q", expected, joined)
		}
	}
}
