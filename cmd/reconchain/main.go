package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type options struct {
	Domain string
	Input  string
	OutDir string
	DryRun bool

	SubTimeout         int
	SubConcurrency     int
	SubActive          bool
	SubMaxMutationSize int
	SubEnrich          bool

	IncludeRoots bool

	URLTimeout           int
	URLConcurrency       int
	URLActive            bool
	URLIncludeSubdomains bool
	URLDepth             int
	URLMaxSeeds          int
	URLHeadless          bool
	URLDedupe            string

	Workflow      bool
	WorkflowScore int

	JSSecrets     bool
	JSConcurrency int
	JSTimeout     int
	JSRetries     int
	JSMaxSize     int64
	JSStrict      bool
	JSRawSecrets  bool
}

type paths struct {
	Root        string
	SubEnumDir  string
	URLEnumDir  string
	OutDir      string
	Subdomains  string
	URLTargets  string
	URLs        string
	WorkflowDir string
	JSOutDir    string
}

type commandSpec struct {
	Name string
	Dir  string
	Args []string
}

func main() {
	opts := parseFlags()
	if err := run(context.Background(), opts); err != nil {
		fmt.Fprintf(os.Stderr, "reconchain: %v\n", err)
		os.Exit(1)
	}
}

func parseFlags() options {
	var opts options
	flag.StringVar(&opts.Domain, "d", "", "Domain(s) to enumerate, comma-separated")
	flag.StringVar(&opts.Input, "i", "", "Input file containing root domains")
	flag.StringVar(&opts.OutDir, "out", "recon-chain", "Output directory for the full chain")
	flag.BoolVar(&opts.DryRun, "dry-run", false, "Print commands and output paths without running")

	flag.IntVar(&opts.SubTimeout, "sub-timeout", 60, "SubEnum timeout in seconds")
	flag.IntVar(&opts.SubConcurrency, "sub-c", 5, "SubEnum concurrency")
	flag.BoolVar(&opts.SubActive, "sub-active", false, "Enable SubEnum active enumeration")
	flag.IntVar(&opts.SubMaxMutationSize, "sub-max-mutations-size", 0, "SubEnum max mutations per subdomain")
	flag.BoolVar(&opts.SubEnrich, "sub-enrich", false, "Enable SubEnum permutation enrichment")

	flag.BoolVar(&opts.IncludeRoots, "include-roots", true, "Include original root domains in URLEnum targets")

	flag.IntVar(&opts.URLTimeout, "url-timeout", 30, "URLEnum timeout in seconds")
	flag.IntVar(&opts.URLConcurrency, "url-c", 8, "URLEnum concurrency")
	flag.BoolVar(&opts.URLActive, "url-active", false, "Enable URLEnum active crawl/headless stage")
	flag.BoolVar(&opts.URLIncludeSubdomains, "url-subs", false, "Allow URLEnum active stage to include subdomains")
	flag.IntVar(&opts.URLDepth, "url-depth", 3, "URLEnum active crawl depth")
	flag.IntVar(&opts.URLMaxSeeds, "url-max-seeds", 300, "URLEnum maximum active seeds")
	flag.BoolVar(&opts.URLHeadless, "url-headless", true, "Enable URLEnum headless stage when active is enabled")
	flag.StringVar(&opts.URLDedupe, "url-dedupe", "param", "URLEnum dedupe mode: exact, param, or path")

	flag.BoolVar(&opts.Workflow, "workflow", true, "Generate URLEnum workflow output")
	flag.IntVar(&opts.WorkflowScore, "workflow-score", 60, "URLEnum workflow interesting score threshold")

	flag.BoolVar(&opts.JSSecrets, "js-secrets", true, "Run jsAnalyzer secret scan on discovered JS URLs")
	flag.IntVar(&opts.JSConcurrency, "js-c", 3, "jsAnalyzer concurrency")
	flag.IntVar(&opts.JSTimeout, "js-timeout", 30, "jsAnalyzer fetch timeout in seconds")
	flag.IntVar(&opts.JSRetries, "js-retries", 3, "jsAnalyzer fetch retries")
	flag.Int64Var(&opts.JSMaxSize, "js-max-size", 5*1024*1024, "jsAnalyzer max JS response size in bytes")
	flag.BoolVar(&opts.JSStrict, "js-strict", false, "Require JavaScript content type in jsAnalyzer fetches")
	flag.BoolVar(&opts.JSRawSecrets, "js-raw-secrets", true, "Write complete raw secret values in jsAnalyzer outputs")

	flag.Parse()
	return opts
}

func run(ctx context.Context, opts options) error {
	if strings.TrimSpace(opts.Domain) == "" && strings.TrimSpace(opts.Input) == "" {
		return errors.New("provide -d or -i")
	}

	p, err := resolvePaths(opts.OutDir)
	if err != nil {
		return err
	}
	if !opts.DryRun {
		if err := os.MkdirAll(p.OutDir, 0755); err != nil {
			return err
		}
	}

	rootDomains, err := collectRootDomains(opts)
	if err != nil {
		return err
	}

	subCmd := buildSubEnumCommand(opts, p)
	if err := runCommand(ctx, subCmd, opts.DryRun); err != nil {
		return err
	}

	targets, err := buildURLTargets(rootDomains, p.Subdomains, opts.IncludeRoots)
	if err != nil {
		return err
	}
	if opts.DryRun {
		fmt.Printf("would write %s with %d root/domain target(s) after SubEnum completes\n", p.URLTargets, len(targets))
	} else {
		if err := writeLines(p.URLTargets, targets); err != nil {
			return err
		}
	}

	urlCmd := buildURLEnumCommand(opts, p)
	if err := runCommand(ctx, urlCmd, opts.DryRun); err != nil {
		return err
	}

	fmt.Printf("reconchain complete\nsubdomains: %s\nurl targets: %s\nurls: %s\n", p.Subdomains, p.URLTargets, p.URLs)
	if opts.Workflow {
		fmt.Printf("workflow: %s\n", p.WorkflowDir)
	}
	if opts.JSSecrets {
		fmt.Printf("js secrets: %s\n", p.JSOutDir)
	}
	return nil
}

func resolvePaths(outDir string) (paths, error) {
	start, err := os.Getwd()
	if err != nil {
		return paths{}, err
	}
	root, err := findRepoRoot(start)
	if err != nil {
		return paths{}, err
	}
	outDir = strings.TrimSpace(outDir)
	if outDir == "" {
		outDir = "recon-chain"
	}
	if !filepath.IsAbs(outDir) {
		outDir = filepath.Join(root, outDir)
	}
	outDir, err = filepath.Abs(outDir)
	if err != nil {
		return paths{}, err
	}
	return paths{
		Root:        root,
		SubEnumDir:  filepath.Join(root, "SubEnum"),
		URLEnumDir:  filepath.Join(root, "URLEnum"),
		OutDir:      outDir,
		Subdomains:  filepath.Join(outDir, "subdomains.txt"),
		URLTargets:  filepath.Join(outDir, "urlenum-targets.txt"),
		URLs:        filepath.Join(outDir, "urls.txt"),
		WorkflowDir: filepath.Join(outDir, "urlenum-workflow"),
		JSOutDir:    filepath.Join(outDir, "js-secrets"),
	}, nil
}

func findRepoRoot(start string) (string, error) {
	start, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		if fileExists(filepath.Join(start, "go.mod")) &&
			fileExists(filepath.Join(start, "SubEnum", "go.mod")) &&
			fileExists(filepath.Join(start, "URLEnum", "cmd", "URLEnum", "main.go")) {
			return start, nil
		}
		parent := filepath.Dir(start)
		if parent == start {
			return "", errors.New("could not locate AutoHunting repository root")
		}
		start = parent
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func buildSubEnumCommand(opts options, p paths) commandSpec {
	args := []string{"run", "./cmd/subenum"}
	if strings.TrimSpace(opts.Domain) != "" {
		args = append(args, "-d", opts.Domain)
	}
	if strings.TrimSpace(opts.Input) != "" {
		args = append(args, "-i", absOrRaw(opts.Input))
	}
	args = append(args,
		"-o", p.Subdomains,
		"-timeout", strconv.Itoa(defaultInt(opts.SubTimeout, 60)),
		"-c", strconv.Itoa(defaultInt(opts.SubConcurrency, 5)),
	)
	if opts.SubActive {
		args = append(args, "-active")
	}
	if opts.SubMaxMutationSize > 0 {
		args = append(args, "-max-mutations-size", strconv.Itoa(opts.SubMaxMutationSize))
	}
	if opts.SubEnrich {
		args = append(args, "-e")
	}
	return commandSpec{Name: "go", Dir: p.SubEnumDir, Args: args}
}

func buildURLEnumCommand(opts options, p paths) commandSpec {
	args := []string{
		"run", "./cmd/URLEnum",
		"-i", p.URLTargets,
		"-o", p.URLs,
		"-timeout", strconv.Itoa(defaultInt(opts.URLTimeout, 30)),
		"-c", strconv.Itoa(defaultInt(opts.URLConcurrency, 8)),
		"-depth", strconv.Itoa(defaultInt(opts.URLDepth, 3)),
		"-max-seeds", strconv.Itoa(defaultInt(opts.URLMaxSeeds, 300)),
		"-headless=" + strconv.FormatBool(opts.URLHeadless),
		"-dedupe", defaultString(opts.URLDedupe, "param"),
	}
	if opts.URLActive {
		args = append(args, "-active")
	}
	if opts.URLIncludeSubdomains {
		args = append(args, "-subs")
	}
	if opts.Workflow {
		args = append(args,
			"-workflow",
			"-workflow-out", p.WorkflowDir,
			"-workflow-score", strconv.Itoa(defaultInt(opts.WorkflowScore, 60)),
		)
	}
	if opts.JSSecrets {
		args = append(args,
			"-js-secrets",
			"-js-out", p.JSOutDir,
			"-js-c", strconv.Itoa(defaultInt(opts.JSConcurrency, 3)),
			"-js-timeout", strconv.Itoa(defaultInt(opts.JSTimeout, 30)),
			"-js-retries", strconv.Itoa(maxInt(opts.JSRetries, 0)),
			"-js-max-size", strconv.FormatInt(defaultInt64(opts.JSMaxSize, 5*1024*1024), 10),
			"-js-raw-secrets="+strconv.FormatBool(opts.JSRawSecrets),
		)
		if opts.JSStrict {
			args = append(args, "-js-strict")
		}
	}
	return commandSpec{Name: "go", Dir: p.URLEnumDir, Args: args}
}

func runCommand(ctx context.Context, spec commandSpec, dryRun bool) error {
	fmt.Printf("[%s] %s\n", filepath.Base(spec.Dir), commandLine(spec))
	if dryRun {
		return nil
	}
	cmd := exec.CommandContext(ctx, spec.Name, spec.Args...)
	cmd.Dir = spec.Dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

func commandLine(spec commandSpec) string {
	parts := append([]string{spec.Name}, spec.Args...)
	for i, part := range parts {
		if strings.ContainsAny(part, " \t\"'") {
			parts[i] = strconv.Quote(part)
		}
	}
	return strings.Join(parts, " ")
}

func collectRootDomains(opts options) ([]string, error) {
	var roots []string
	for _, item := range strings.Split(opts.Domain, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			roots = append(roots, item)
		}
	}
	if strings.TrimSpace(opts.Input) != "" {
		lines, err := readLines(absOrRaw(opts.Input))
		if err != nil {
			return nil, err
		}
		roots = append(roots, lines...)
	}
	roots = uniqueSorted(roots)
	if len(roots) == 0 {
		return nil, errors.New("no root domains found")
	}
	return roots, nil
}

func buildURLTargets(rootDomains []string, subdomainsPath string, includeRoots bool) ([]string, error) {
	var targets []string
	if includeRoots {
		targets = append(targets, rootDomains...)
	}
	subdomains, err := readLines(subdomainsPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	targets = append(targets, subdomains...)
	targets = uniqueSorted(targets)
	if len(targets) == 0 {
		return nil, errors.New("SubEnum produced no subdomains and root domains were not included")
	}
	return targets, nil
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, item := range strings.Split(line, ",") {
			item = strings.TrimSpace(item)
			if item != "" {
				out = append(out, item)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
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

func uniqueSorted(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, item := range in {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func absOrRaw(path string) string {
	path = strings.TrimSpace(path)
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}

func defaultInt(v, fallback int) int {
	if v <= 0 {
		return fallback
	}
	return v
}

func defaultInt64(v, fallback int64) int64 {
	if v <= 0 {
		return fallback
	}
	return v
}

func defaultString(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func maxInt(v, min int) int {
	if v < min {
		return min
	}
	return v
}
