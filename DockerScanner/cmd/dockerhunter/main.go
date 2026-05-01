package main

import (
	"os"

	"github.com/cyinnove/logify"
	"github.com/spf13/cobra"

	"github.com/noureldinSAF/AutoHunting/DockerScanner/pkg/runner"
)

var (
	opts    = &runner.Options{}
	debug   bool
	verbose bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "dockerscan",
		Short: "A tool to scan Docker images for sensitive information",
		Long: `DockerScan is a command-line tool that helps you scan Docker images
for sensitive information using customizable regex patterns.`,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Set log level based on flags
			
			
			switch {
			case debug:
				logify.MaxLevel = logify.Debug
			case verbose:
				logify.MaxLevel = logify.Warning
				logify.MaxLevel = logify.Verbose
			default:
				logify.MaxLevel = logify.Info
			}
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runner.Run(opts)
		},
	}

	// Add flags
	flags := rootCmd.Flags()
	flags.StringVarP(&opts.ImageName, "image", "i", "", "Docker image name to scan")
	flags.StringVarP(&opts.OutputFile, "output", "o", "", "Output file path for scan results (default: stdout)")
	flags.StringVarP(&opts.ImagesInputFile, "input-file", "f", "", "Path to file containing list of images to scan")
	flags.BoolVar(&debug, "debug", false, "Enable debug logging")
	flags.BoolVar(&verbose, "verbose", false, "Enable verbose/info logging")
	flags.StringVarP(&opts.RegexesFile, "regexes", "r", "regexes.yaml", "Path to regexes YAML file")
	

	if err := rootCmd.Execute(); err != nil {
		logify.Errorf("Error: %v", err)
		os.Exit(1)
	}
}
