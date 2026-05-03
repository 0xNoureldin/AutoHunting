package workflow

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/noureldinSAF/AutoHunting/URLEnum/internal/fuzz"
	"github.com/noureldinSAF/AutoHunting/URLEnum/internal/nuclei"
	"github.com/noureldinSAF/AutoHunting/URLEnum/internal/priority"
)

type Options struct {
	Enabled          bool
	OutDir           string
	InterestingScore int
	FuzzEnabled      bool
	NucleiEnabled    bool
	Fuzz             fuzz.PlanOptions
	Nuclei           nuclei.PlanOptions
}

func (o Options) withDefaults() Options {
	if strings.TrimSpace(o.OutDir) == "" {
		o.OutDir = "urlenum-workflow"
	}
	if o.InterestingScore <= 0 {
		o.InterestingScore = 60
	}
	return o
}

func Run(urls []string, opts Options) error {
	if !opts.Enabled {
		return nil
	}
	opts = opts.withDefaults()
	if err := os.MkdirAll(opts.OutDir, 0755); err != nil {
		return err
	}

	sorted := priority.Sort(urls)
	interesting := priority.Interesting(sorted, opts.InterestingScore)
	interestingURLs := make([]string, 0, len(interesting))
	for _, r := range interesting {
		interestingURLs = append(interestingURLs, r.URL)
	}

	if err := writeLines(filepath.Join(opts.OutDir, "urls-prioritized.txt"), sorted); err != nil {
		return err
	}
	if err := writeLines(filepath.Join(opts.OutDir, "interesting.txt"), interestingURLs); err != nil {
		return err
	}
	if err := writeSummary(filepath.Join(opts.OutDir, "summary.md"), len(urls), len(interesting), opts); err != nil {
		return err
	}

	if opts.FuzzEnabled {
		fo := opts.Fuzz
		fo.Enabled = true
		if strings.TrimSpace(fo.OutDir) == "" {
			fo.OutDir = filepath.Join(opts.OutDir, "fuzz-plan")
		}
		if err := fuzz.WritePlan(sorted, fo); err != nil {
			return err
		}
	}
	if opts.NucleiEnabled {
		no := opts.Nuclei
		no.Enabled = true
		if strings.TrimSpace(no.OutDir) == "" {
			no.OutDir = filepath.Join(opts.OutDir, "nuclei-plan")
		}
		if err := nuclei.WritePlan(sorted, no); err != nil {
			return err
		}
	}
	return nil
}

func writeSummary(path string, total int, interesting int, opts Options) error {
	lines := []string{
		"# URLEnum Workflow Summary",
		"",
		fmt.Sprintf("- Total URLs: %d", total),
		fmt.Sprintf("- Interesting URLs: %d", interesting),
		fmt.Sprintf("- Interesting score threshold: %d", opts.InterestingScore),
		fmt.Sprintf("- Fuzz plan enabled: %v", opts.FuzzEnabled),
		fmt.Sprintf("- Nuclei plan enabled: %v", opts.NucleiEnabled),
		"",
		"Generated files:",
		"- urls-prioritized.txt",
		"- interesting.txt",
		"- summary.md",
	}
	if opts.FuzzEnabled {
		lines = append(lines, "- fuzz-plan/fuzz.txt", "- fuzz-plan/params.txt", "- fuzz-plan/ffuf_commands.sh")
	}
	if opts.NucleiEnabled {
		lines = append(lines, "- nuclei-plan/nuclei_targets.txt", "- nuclei-plan/nuclei_tags.txt", "- nuclei-plan/nuclei_commands.sh")
	}
	return writeLines(path, lines)
}

func writeLines(path string, lines []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, line := range lines {
		if _, err := w.WriteString(line + "\n"); err != nil {
			return err
		}
	}
	return w.Flush()
}
