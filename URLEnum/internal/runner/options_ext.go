package runner

// Planner and workflow options are split into this file so older code that
// constructs Options keeps compiling while new CLI flags can opt in.
type PlannerOptions struct {
	Depth          int
	DedupeMode     string
	MaxActiveSeeds int
	HeadlessEnabled bool

	Workflow       bool
	WorkflowOut    string
	WorkflowScore  int

	FuzzPlan       bool
	FuzzOutDir     string
	FuzzMarker     string
	FuzzWordlist   string
	FuzzRate       int
	FuzzMinScore   int

	NucleiPlan     bool
	NucleiOutDir   string
	NucleiRate     int
	NucleiTags     string
}
