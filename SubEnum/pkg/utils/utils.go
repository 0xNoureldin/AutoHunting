package utils

import (
	"bufio"
	"os"
	"regexp"
	"strings"
)

// ReadInputFromFile reads one entry per line, trimming whitespace and
// dropping blank lines and "#"-prefixed comments. A trailing newline --
// the normal case for any file written by a text editor or by this
// codebase's own writeLines-style helpers -- would otherwise produce a
// spurious empty final entry (strings.Split on "a\n" returns ["a", ""]),
// which callers that don't do their own filtering (like the domain list
// in loadQueries) would silently enumerate as a real query.
func ReadInputFromFile(file string) ([]string, error) {
	fileData, err := os.ReadFile(file)
	if err != nil {
		return []string{}, err
	}

	lines := strings.Split(string(fileData), "\n")
	cleaned := make([]string, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		cleaned = append(cleaned, l)
	}
	return cleaned, nil
}

func WriteOutputToFile(file string, data []string) error {
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer f.Close()

	writer := bufio.NewWriter(f)
	for _, line := range data {
		if _, err := writer.WriteString(line + "\n"); err != nil {
			return err
		}
	}

	return writer.Flush()
}

func ExtractDomainsFromString(input string) []string {
	return strings.Split(input, ",")
}

// RegexSubdomainExtractor extracts subdomains from text using regex
type RegexSubdomainExtractor struct {
	extractor *regexp.Regexp
}

// NewSubdomainExtractor creates a new subdomain extractor for a specific domain
func NewSubdomainExtractor(domain string) (*RegexSubdomainExtractor, error) {
	// Escape special regex characters in the domain
	escapedDomain := regexp.QuoteMeta(domain)
	// Pattern: [alphanumeric, asterisk, underscore, dot, hyphen]+.domain
	// This matches subdomains like: api.example.com, sub.example.com, etc.
	pattern := `(?i)[a-zA-Z0-9\*_.-]+\.` + escapedDomain
	extractor, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return &RegexSubdomainExtractor{extractor: extractor}, nil
}

// Extract finds all subdomains matching the domain pattern in the given text
func (r *RegexSubdomainExtractor) Extract(text string) []string {
	var results []string
	seen := make(map[string]bool)

	matches := r.extractor.FindAllStringSubmatch(text, -1)
	for _, match := range matches {
		if len(match) > 1 {
			subdomain := strings.ToLower(strings.TrimSpace(match[1]))

			// Clean up common HTML entities
			subdomain = strings.ReplaceAll(subdomain, "&#39;", "'")
			subdomain = strings.ReplaceAll(subdomain, "&quot;", "\"")
			subdomain = strings.ReplaceAll(subdomain, "&amp;", "&")

			// Remove HTML tags
			subdomain = regexp.MustCompile(`<[^>]+>`).ReplaceAllString(subdomain, "")

			// Trim punctuation and whitespace
			subdomain = strings.Trim(subdomain, ".,;:!?\"'()[]{}<> \t\n\r")

			// Remove trailing dots
			subdomain = strings.TrimSuffix(subdomain, ".")

			// Validate and deduplicate
			if isValidSubdomain(subdomain) && !seen[subdomain] {
				seen[subdomain] = true
				results = append(results, subdomain)
			}
		}
	}

	return results
}

// isValidSubdomain validates that a string is a proper subdomain format
func isValidSubdomain(domain string) bool {
	if domain == "" {
		return false
	}
	// Must contain at least one dot
	if !strings.Contains(domain, ".") {
		return false
	}
	// Must not start or end with dot or hyphen
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}
	if strings.HasPrefix(domain, "-") || strings.HasSuffix(domain, "-") {
		return false
	}
	// Check each label (part between dots)
	parts := strings.Split(domain, ".")
	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 {
			return false
		}
		// Each part must be alphanumeric, asterisk, underscore, or hyphen, but not start/end with hyphen
		if !regexp.MustCompile(`^[a-zA-Z0-9\*_]([a-zA-Z0-9\*_\-]*[a-zA-Z0-9\*_])?$`).MatchString(part) {
			return false
		}
	}
	return true
}
