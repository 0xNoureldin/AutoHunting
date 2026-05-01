package client

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/cyinnove/logify"
	"github.com/fsouza/go-dockerclient"
)

var (
	blackListDirs = []string{
		"/node_modules",
		"/vendor",
		"/.git",
		"/.idea",
		"yarn",
		"/package-lock.json",
		"/dist",
		"/locales/",
		"/locale/",
		"/components",
		"/server/data",
		"/.cache",
	}

	blackListExtensions = []string{
		".png",
		".jpg",
		".jpeg",
		".gif",
		".svg",
		".ico",
		".pak",
		".bin",
		".pdf",
		".css",
		".zip",
		".tar",
		".gz",
		".bz2",
		".rar",
		".7z",
		".wim",
		".iso",
		".dmg",
	}

	// defaultScanRoots used when image has no WORKDIR set
	defaultScanRoots = []string{"/app", "/code", "/usr/src/app", "/"}
)

// NewDockerScan creates a new DockerScan instance
func NewDockerScan(imageName string) (*DockerScan, error) {
	var version string
	var baseImageName string

	// Check if version is provided in imageName (format: name:version)
	if strings.Contains(imageName, ":") {
		parts := strings.Split(imageName, ":")
		baseImageName = parts[0]
		version = parts[1]
	} else {
		baseImageName = imageName
	}

	client, err := docker.NewClientFromEnv()
	if err != nil {
		return nil, fmt.Errorf("error creating Docker client: %v", err)
	}

	ds := &DockerScan{
		client:    client,
		imageName: baseImageName,
		version:   version,
		matches:   []*SecretMatch{},
	}

	if version != "" {
		ds.singleVersionScan = true
	}

	return ds, nil
}

// Scan performs the scanning operation on the Docker image.
func (s *DockerScan) Scan() error {
	var versions []string
	var err error

	if s.singleVersionScan {
		versions = []string{s.version}
	} else {
		versions, err = fetchTags(s.imageName)
		if err != nil {
			return fmt.Errorf("error fetching tags for image %s: %v", s.imageName, err)
		}
		if len(versions) == 0 {
			return fmt.Errorf("no tags found for image %s", s.imageName)
		}
	}

	for _, version := range versions {
		s.version = version
		logify.Infof("Starting scan for image: %s:%s\n", s.imageName, s.version)
		fullImageName := fmt.Sprintf("%s:%s", s.imageName, s.version)

		// Pull image if not available locally
		imageInfo, err := s.client.InspectImage(fullImageName)
		if err != nil {
			logify.Debugf("Image %s not found locally, pulling...", fullImageName)

			pullOpts := docker.PullImageOptions{Repository: s.imageName, Tag: s.version}
			if err := s.client.PullImage(pullOpts, docker.AuthConfiguration{}); err != nil {
				logify.Errorf("Failed to pull image %s: %v", fullImageName, err)
				continue
			}

			// Get image info after pulling
			imageInfo, err = s.client.InspectImage(fullImageName)
			if err != nil {
				logify.Errorf("Failed to inspect pulled image %s: %v", fullImageName, err)
				continue
			}
		}

		// Set working directory from image config if available
		if imageInfo != nil && imageInfo.Config != nil && imageInfo.Config.WorkingDir != "" {
			s.workDir = imageInfo.Config.WorkingDir
		}

		// Create container
		container, err := s.createContainer(fullImageName)
		if err != nil {
			logify.Errorf("Failed to create container for %s: %v", fullImageName, err)
			continue
		}
		defer s.cleanupContainer(container.ID)

		if err := s.client.StartContainer(container.ID, nil); err != nil {
			logify.Errorf("Failed to start container for %s: %v", fullImageName, err)
			continue
		}

		if err := s.scanContainerFiles(container.ID); err != nil {
			logify.Errorf("Error scanning container %s: %v", fullImageName, err)
		}
	}

	return nil
}

func (s *DockerScan) cleanupContainer(containerID string) {
	logify.Debugf("Cleaning up container %s ...", containerID)
	_ = s.client.StopContainer(containerID, 5)
	_ = s.client.RemoveContainer(docker.RemoveContainerOptions{
		ID:            containerID,
		RemoveVolumes: true,
		Force:         true,
	})
	logify.Debugf("Container %s cleanup completed.", containerID)
}

func (s *DockerScan) createContainer(imageName string) (*docker.Container, error) {
	createOpts := docker.CreateContainerOptions{
		Config: &docker.Config{
			Image: imageName,
			Cmd:   []string{"/bin/sh", "-c", "while true; do sleep 10; done"},
		},
	}
	container, err := s.client.CreateContainer(createOpts)
	if err != nil {
		return nil, fmt.Errorf("error creating container: %v", err)
	}
	logify.Infof("Container created with ID: %s\n", container.ID)
	return container, nil
}

func (s *DockerScan) scanContainerFiles(containerID string) error {
	path := s.scanRoot(containerID)
	logify.Infof("Scanning files under %s (single tar stream)\n", path)

	pipeR, pipeW := io.Pipe()
	ctx := context.Background()
	go func() {
		defer pipeW.Close()
		opts := docker.DownloadFromContainerOptions{
			Path:              path,
			OutputStream:      pipeW,
			InactivityTimeout: 0,
			Context:           ctx,
		}
		if err := s.client.DownloadFromContainer(containerID, opts); err != nil {
			logify.Errorf("DownloadFromContainer %s: %v", path, err)
		}
	}()

	tr := tar.NewReader(pipeR)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		filePath := filepath.Join("/", filepath.Clean(hdr.Name))
		if s.skipFile(filePath) {
			continue
		}
		content, err := io.ReadAll(tr)
		if err != nil {
			logify.Errorf("Reading %s from tar: %v", filePath, err)
			continue
		}
		if !utf8.Valid(content) || isBinary(content) {
			continue
		}
		s.scanContent(filePath, string(content))
	}
	return nil
}

// scanContent runs only the GeneralPattern regex on file content and appends matches.
func (s *DockerScan) scanContent(filePath, content string) {
	for _, pattern := range GeneralPatterns {
		if pattern.Regex == nil {
			continue
		}

		for _, match := range pattern.Regex.FindAllString(content, -1) {
			match = strings.TrimSpace(match)
			if match == "" || len(match) < 20 {
				continue
			}

			s.matches = append(s.matches, &SecretMatch{
				Secret:   match,
				FilePath: filePath,
			})
		}
	}
}

// secretsOutput is the top-level JSON structure returned by GenerateJSONOutput.
type secretsOutput struct {
	Secrets []*SecretMatch `json:"secrets"`
}

// GenerateJSONOutput generates JSON output for all matched secrets.
func (s *DockerScan) GenerateJSONOutput() (string, error) {

	s.RemoveDuplicateMatches()

	out := secretsOutput{Secrets: s.matches}

	jsonData, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return "", fmt.Errorf("error generating JSON output: %v", err)
	}
	return string(jsonData), nil
}

func (s *DockerScan) GetOutput() []*SecretMatch {
	return s.matches
}

func (s *DockerScan) RemoveDuplicateMatches() {
	unique := make(map[string]*SecretMatch)
	for _, match := range s.matches {
		key := fmt.Sprintf("%s|%s", match.FilePath, match.Secret)
		if _, exists := unique[key]; !exists {
			unique[key] = match
		}
	}
	s.matches = make([]*SecretMatch, 0, len(unique))
	for _, match := range unique {
		s.matches = append(s.matches, match)
	}
}
