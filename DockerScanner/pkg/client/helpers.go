package client

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	

	"github.com/cyinnove/logify"
	docker "github.com/fsouza/go-dockerclient"
)



// scanRoot returns the path to scan: workDir if set, else first existing root from defaultScanRoots.
func (s *DockerScan) scanRoot(containerID string) string {
	if s.workDir != "" {
		return s.workDir
	}

	// Probe which default root exists via one exec
	roots := strings.Join(defaultScanRoots, " ")
	execOpts := docker.CreateExecOptions{
		Container:    containerID,
		Cmd:          []string{"/bin/sh", "-c", fmt.Sprintf("for d in %s; do [ -d \"$d\" ] && echo \"$d\" && break; done", roots)},
		AttachStdout: true,
		AttachStderr: true,
	}

	execInstance, err := s.client.CreateExec(execOpts)
	if err != nil {
		return defaultScanRoots[0]
	}

	var out bytes.Buffer
	_ = s.client.StartExec(execInstance.ID, docker.StartExecOptions{OutputStream: &out, ErrorStream: io.Discard})
	line := strings.TrimSpace(strings.Split(out.String(), "\n")[0])
	if line != "" {
		return line
	}

	return defaultScanRoots[0]
}

// skipFile determines whether a file path should be skipped based on blacklists.
func (s *DockerScan) skipFile(filePath string) bool {
	for _, bl := range blackListDirs {
		if strings.Contains(filePath, bl) {
			logify.Verbosef("Skipping blacklisted file: %s\n", "V", filePath)
			return true
		}
	}

	for _, ext := range blackListExtensions {
		if strings.HasSuffix(filePath, ext) {
			logify.Verbosef("Skipping blacklisted extension: %s\n", "V", filePath)
			return true
		}
	}

	return false
}

// isBinary performs a simple heuristic to detect binary content.
func isBinary(content []byte) bool {
	const max = 8 * 1024
	n := len(content)
	if n > max {
		n = max
	}
	for i := 0; i < n; i++ {
		if content[i] == 0 {
			return true
		}
	}
	return false
}

