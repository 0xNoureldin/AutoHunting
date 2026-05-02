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

	JSSecrets     bool
	JSOutDir      string
	JSConcurrency int
	JSTimeout     int
	JSRetries     int
	JSMaxSize     int64
	JSStrict      bool
	JSRawSecrets  bool

	queries []string
}
