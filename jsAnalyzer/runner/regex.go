package runner

import (
	"fmt"
	"strings"

	"github.com/cyinnove/logify"
)

func AnalyzeJSContent(content string, opts AnalyzeOptions) (ScanResult, error) {
	return AnalyzeJSContentForURL("", []byte(content), opts)
}

func AnalyzeJSContentForURL(sourceURL string, body []byte, opts AnalyzeOptions) (ScanResult, error) {
	opts = defaultOptions(opts)
	analysis := AnalyzeJavaScript(sourceURL, body, opts)
	text := string(body)
	if opts.Deobfuscate {
		deob := DeobfuscateStatic(text, opts)
		text = deob.Expanded
	}

	subdomains := make(map[string]struct{})
	clouds := make(map[string]struct{})
	params := make(map[string]struct{})
	npm := make(map[string]struct{})

	if opts.Subdomains {
		for _, s := range SubdomainRegex.FindAllString(text, -1) {
			subdomains[s] = struct{}{}
		}
	}
	if opts.Cloud {
		for _, c := range CloudBucketRegex.FindAllString(text, -1) {
			clouds[c] = struct{}{}
		}
	}
	if opts.Params {
		for _, p := range ParameterRegex.FindAllString(text, -1) {
			p = strings.TrimSpace(p)
			if p != "" {
				params[p] = struct{}{}
			}
		}
	}
	if opts.Npm {
		for _, pkg := range NodeModulesRegex.FindAllStringSubmatch(text, -1) {
			if len(pkg) > 0 && strings.TrimSpace(pkg[0]) != "" {
				npm[strings.TrimSpace(pkg[0])] = struct{}{}
			}
		}
	}

	endpointSet := map[string]struct{}{}
	if opts.Endpoints {
		for _, e := range analysis.Endpoints {
			endpointSet[e.URL] = struct{}{}
		}
	}

	legacySecretSet := map[string]struct{}{}
	legacySecretMatches := make([]*SecretMatch, 0, len(analysis.Secrets))
	secretFindings := analysis.Secrets
	if !opts.Secrets {
		secretFindings = nil
	} else {
		for i := range secretFindings {
			if !opts.RawSecrets {
				secretFindings[i] = redactSecretFinding(secretFindings[i])
				secretFindings[i].Value = ""
			}
			legacyValue := secretFindings[i].Masked
			if opts.RawSecrets && secretFindings[i].Value != "" {
				legacyValue = secretFindings[i].Value
			}
			legacySecretSet[fmt.Sprintf("%s::%s", secretFindings[i].Type, legacyValue)] = struct{}{}
			legacySecretMatches = append(legacySecretMatches, &SecretMatch{
				PatternName: secretFindings[i].Type,
				Value:       legacyValue,
			})
		}
	}

	results := ScanResult{
		URL:              sourceURL,
		Subdomains:       setToSlice(subdomains),
		CloudBuckets:     setToSlice(clouds),
		Endpoints:        setToSlice(endpointSet),
		Parameters:       setToSlice(params),
		NpmPackages:      setToSlice(npm),
		EndpointFindings: analysis.Endpoints,
		SecretFindings:   secretFindings,
		Signals:          analysis.Signals,
		Secrets:          legacySecretSet,
		SecretMatches:    legacySecretMatches,
	}

	logify.Infof(
		"Scan complete: subdomains=%d cloud=%d endpoints=%d params=%d npm=%d secrets=%d signals=%d",
		len(results.Subdomains), len(results.CloudBuckets), len(results.EndpointFindings),
		len(results.Parameters), len(results.NpmPackages), len(results.SecretFindings), len(results.Signals),
	)

	return results, nil
}

func AnalyzeJavaScript(baseURL string, body []byte, opts Options) AnalysisResult {
	opts = defaultOptions(opts)
	raw := string(body)
	texts := []string{raw}
	signals := []string{}

	if opts.Deobfuscate {
		deob := DeobfuscateStatic(raw, opts)
		texts = append(texts, deob.Expanded)
		signals = append(signals, deob.Signals...)
	}

	var endpoints []EndpointFinding
	var secrets []SecretFinding
	for _, text := range texts {
		if opts.Endpoints {
			endpoints = append(endpoints, ExtractEndpoints(baseURL, text, opts)...)
		}
		if opts.Secrets {
			for _, finding := range ExtractSecrets(text) {
				finding.Source = baseURL
				secrets = append(secrets, finding)
			}
		}
	}

	return AnalysisResult{
		Endpoints: limitEndpointFindings(dedupeEndpointFindings(endpoints), opts.MaxFindings),
		Secrets:   limitSecretFindings(dedupeSecretFindings(secrets), opts.MaxFindings),
		Signals:   uniqueStrings(signals),
	}
}
