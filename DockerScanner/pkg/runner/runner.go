package runner

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/noureldinSAF/AutoHunting/DockerScanner/pkg/client"
)

func Run(opts *Options) error {
	if opts == nil {
		return fmt.Errorf("options cannot be nil")
	}

	// Validate required fields
	if opts.ImageName == "" && opts.ImagesInputFile == "" {
		return fmt.Errorf("either image name or input file must be provided")
	}

	// Process single image or multiple images from file
	if opts.ImagesInputFile != "" {
		return processImagesFromFile(opts)
	}

	return processSingleImage(opts)
}

func processSingleImage(opts *Options) error {
	imageName := opts.ImageName

	scanner, err := client.NewDockerScan(imageName)
	if err != nil {
		return fmt.Errorf("failed to create scanner: %w", err)
	}

	// Start the scan
	scanner.Scan()

	// Generate results
	res, err := scanner.GenerateJSONOutput()
	if err != nil {
		return fmt.Errorf("failed to generate results: %w", err)
	}

	// Save results
	if opts.OutputFile != "" {
		if err := saveResults(opts.OutputFile, res); err != nil {
			return fmt.Errorf("failed to save results: %w", err)
		}
		fmt.Printf("Scan completed. Results saved to %s\n", opts.OutputFile)
	} else if opts.IsFileInput{ 
	
		if err := saveResults(opts.OutputFile, res); err != nil {
			return fmt.Errorf("failed to save results: %w", err)
		}
		
		fmt.Printf("Scan completed. Results saved to %s\n", opts.OutputFile)
	
	}else {

		opts.OutputFile = fmt.Sprintf("%s_%s.json", opts.ImageName, time.Now().Format("2004-01-02_15-04-05"))

		opts.OutputFile = strings.ReplaceAll(opts.OutputFile, "/", "-")

		if err := saveResults(opts.OutputFile, res); err != nil {
			return fmt.Errorf("failed to save results: %w", err)
		}
		fmt.Printf("Scan completed. Results saved to %s\n", opts.OutputFile)
	}

	return nil
}

func processImagesFromFile(opts *Options) error {

	 opts.IsFileInput = true


	content, err := os.ReadFile(opts.ImagesInputFile)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	images := strings.Split(string(content), "\n")
	for _, image := range images {
		image = strings.TrimSpace(image)
		if image == "" {
			continue
		}

		tempOpts := *opts
		tempOpts.ImageName = image
		if err := processSingleImage(&tempOpts); err != nil {
			fmt.Printf("Error processing image %s: %v\n", image, err)
		}
	}

	return nil
}

func saveResults(filename, content string) error {
	// Ensure the filename has a .json extension
	if !strings.HasSuffix(filename, ".json") {
		filename = filename + ".json"
	}

	// Create a new file
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	// Write the content to the file
	if _, err := file.Write([]byte(content)); err != nil {
		return fmt.Errorf("failed to write to file: %w", err)
	}

	return nil
}
