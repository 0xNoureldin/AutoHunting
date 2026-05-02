package runner

import (
	"bufio"
	"encoding/json"
	"os"
)

func WriteEndpoints(path string, results []ScanResult) error {
	set := map[string]struct{}{}
	for _, res := range results {
		for _, finding := range res.EndpointFindings {
			if finding.URL != "" {
				set[finding.URL] = struct{}{}
			}
		}
	}
	return WriteOutputToFile(path, setToSlice(set))
}

func WriteSecretsJSONL(path string, results []ScanResult, raw bool) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	for _, res := range results {
		for _, finding := range res.SecretFindings {
			finding.Source = res.URL
			if !raw {
				finding = redactSecretFinding(finding)
				finding.Value = ""
			}
			if err := enc.Encode(finding); err != nil {
				return err
			}
		}
	}
	return w.Flush()
}
