package runner

type Options struct {
	Domain string
	Input  string
	Output string

	Timeout     int
	Concurrency int

	ActiveEnabled     bool
	IncludeSubdomains bool
	Depth             int
	MaxActiveSeeds    int
	HeadlessEnabled   bool

	DedupeMode string

	Workflow      bool
	WorkflowOut   string
	WorkflowScore int

	FuzzPlan     bool
	FuzzOutDir   string
	FuzzMarker   string
	FuzzWordlist string
	FuzzRate     int
	FuzzMinScore int

	NucleiPlan   bool
	NucleiOutDir string
	NucleiRate   int
	NucleiTags   string

	queries []string
}
