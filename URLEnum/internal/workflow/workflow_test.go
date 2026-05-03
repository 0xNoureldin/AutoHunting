package workflow

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noureldinSAF/AutoHunting/URLEnum/internal/fuzz"
	"github.com/noureldinSAF/AutoHunting/URLEnum/internal/nuclei"
)

func TestRunCreatesCoreFilesOnlyWhenPlansDisabled(t *testing.T) {
	outDir := t.TempDir()
	err := Run([]string{"https://example.com/admin", "https://example.com/search?q=x"}, Options{
		Enabled: true,
		OutDir:  outDir,
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"urls-prioritized.txt", "interesting.txt", "summary.md"} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Fatalf("expected %s: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(outDir, "fuzz-plan")); !os.IsNotExist(err) {
		t.Fatalf("fuzz-plan should not exist when disabled")
	}
	if _, err := os.Stat(filepath.Join(outDir, "nuclei-plan")); !os.IsNotExist(err) {
		t.Fatalf("nuclei-plan should not exist when disabled")
	}
}

func TestRunCreatesFuzzAndNucleiPlans(t *testing.T) {
	outDir := t.TempDir()
	err := Run([]string{
		"https://example.com/admin?redirect=https://target.example",
		"https://example.com/api/users?id=1",
	}, Options{
		Enabled:       true,
		OutDir:        outDir,
		FuzzEnabled:   true,
		NucleiEnabled: true,
		Fuzz: fuzz.PlanOptions{
			Marker:   "FUZZ",
			Wordlist: "payloads.txt",
			Rate:     10,
			MinScore: 1,
		},
		Nuclei: nuclei.PlanOptions{
			Rate: 10,
			Tags: []string{"custom"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	ffufCommands, err := os.ReadFile(filepath.Join(outDir, "fuzz-plan", "ffuf_commands.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(ffufCommands), "#!/usr/bin/env bash\nset -euo pipefail\n") {
		t.Fatalf("ffuf command file lost its shell header:\n%s", string(ffufCommands))
	}

	nucleiTags, err := os.ReadFile(filepath.Join(outDir, "nuclei-plan", "nuclei_tags.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(nucleiTags), "custom\n") {
		t.Fatalf("custom nuclei tag was not merged:\n%s", string(nucleiTags))
	}
}
