package main

import (
	"flag"
	"github.com/noureldinSAF/AutoHunting/URLEnum/internal/runner"
)

// This file extends flags without breaking existing main.go

func init() {
	// NOTE: these will be bound in main via type assertion
}

func bindExtendedFlags(base *runner.Options, ext *runner.PlannerOptions) {
	flag.IntVar(&ext.Depth, "depth", 3, "Crawl depth")
	flag.StringVar(&ext.DedupeMode, "dedupe", "param", "Dedupe mode (exact,param,path)")
	flag.IntVar(&ext.MaxActiveSeeds, "max-seeds", 300, "Max active seeds")
	flag.BoolVar(&ext.HeadlessEnabled, "headless", true, "Enable headless stage")

	flag.BoolVar(&ext.Workflow, "workflow", false, "Enable auto workflow")
	flag.StringVar(&ext.WorkflowOut, "workflow-out", "urlenum-workflow", "Workflow output dir")
	flag.IntVar(&ext.WorkflowScore, "workflow-score", 60, "Interesting score threshold")

	flag.BoolVar(&ext.FuzzPlan, "fuzz-plan", false, "Generate fuzz plan")
	flag.StringVar(&ext.FuzzOutDir, "fuzz-out", "", "Fuzz output dir")
	flag.StringVar(&ext.FuzzMarker, "fuzz-marker", "FUZZ", "Fuzz marker")
	flag.StringVar(&ext.FuzzWordlist, "fuzz-wordlist", "payloads.txt", "Fuzz wordlist")
	flag.IntVar(&ext.FuzzRate, "fuzz-rate", 20, "Fuzz rate")
	flag.IntVar(&ext.FuzzMinScore, "fuzz-min-score", 3, "Min fuzz score")

	flag.BoolVar(&ext.NucleiPlan, "nuclei-plan", false, "Generate nuclei plan")
	flag.StringVar(&ext.NucleiOutDir, "nuclei-out", "", "Nuclei output dir")
	flag.IntVar(&ext.NucleiRate, "nuclei-rate", 20, "Nuclei rate")
	flag.StringVar(&ext.NucleiTags, "nuclei-tags", "", "Extra nuclei tags")
}
