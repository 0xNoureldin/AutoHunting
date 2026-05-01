package client

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	docker "github.com/fsouza/go-dockerclient"
	"github.com/cyinnove/logify"
	"gopkg.in/yaml.v3"
)

var GeneralPatterns []Pattern

func init() {
	var err error
	GeneralPatterns, err = LoadRegexes("regexes.yaml")
	if err != nil {
		logify.Errorf("load regexes: %v", err)
		os.Exit(1)
	}
}

type regexSignaturesFile struct {
	Signatures []regexSignature `yaml:"signatures"`
}

type regexSignature struct {
	Pattern regexPattern `yaml:"pattern"`
}

type regexPattern struct {
	Name      string `yaml:"name"`
	Value     string `yaml:"value"`
	Sensitive bool   `yaml:"sensitive"`
}

type Pattern struct {
	Name      string         `yaml:"name"`
	Value     string         `yaml:"value"`
	Sensitive bool           `yaml:"sensitive"`
	Regex     *regexp.Regexp `yaml:"-"`
}

func LoadRegexes(path string) ([]Pattern, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read regexes file: %w", err)
	}

	var file regexSignaturesFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parse regexes yaml: %w", err)
	}

	patterns := make([]Pattern, 0, len(file.Signatures))
	for _, sig := range file.Signatures {
		value := strings.TrimSpace(sig.Pattern.Value)
		if value == "" {
			continue
		}

		re, err := regexp.Compile(value)
		if err != nil {
			logify.Warningf("skip invalid regex %q: %v", sig.Pattern.Name, err)
			continue
		}

		patterns = append(patterns, Pattern{
			Name:      sig.Pattern.Name,
			Value:     value,
			Sensitive: sig.Pattern.Sensitive,
			Regex:     re,
		})
	}

	return patterns, nil
}

type DockerScan struct {
	client            *docker.Client
	singleVersionScan bool
	imageName         string
	version           string
	workDir           string
	matches           []*SecretMatch
}

// SecretMatch represents a secret match with the secret value and file path.
type SecretMatch struct {
	Secret   string `json:"secret"`
	FilePath string `json:"file_path"`
}

type TagsList struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

