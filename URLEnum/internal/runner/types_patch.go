package runner

// PipelineFields embeds the fields used by the new pipeline implementation.
// TODO: merge this into types.go once the legacy test runner is removed.
type PipelineFields struct {
	Depth           int
	DedupeMode      string
	MaxActiveSeeds  int
	HeadlessEnabled bool
}
