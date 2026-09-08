package runner

import "testing"

// fixture values below are built from concatenated fragments rather than a
// single literal string. They are synthetic and never valid credentials,
// but GitHub's push protection (and other secret scanners) match on shape
// alone, so a contiguous literal would still get flagged as a real secret.
// Splitting the literal avoids that while producing the exact same string
// at runtime for the regexes under test to match against.

// TestFindSecretsDetectsKnownFormats is a regression test for the secret
// pattern set: every sample below must be detected by FindSecrets. It
// exists because past versions of these patterns silently failed to match
// due to capturing-group and case-sensitivity mistakes that made
// pickBestSecretGroup pick a fragment of the match (e.g. "live" instead of
// the key) instead of the actual secret, which then failed the minimum
// length check in isPlausibleSecret.
func TestFindSecretsDetectsKnownFormats(t *testing.T) {
	samples := []struct {
		name    string
		content string
	}{
		{"AWS Access Key ID", `var k = "` + "AKIA" + `ABCDEFGHIJKLMNOP";`},
		{"AWS Secret Key", `aws_secret_access_key = "` + "PtYgjmUhBel31iEl2hpChYgC" + `frL1spNxnyVmihA/"`},
		{"Google API Key", `const apiKey = "` + "AIza" + `SyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY";`},
		{"Slack Token", `token: "` + "xoxb-1234567890-1234567890-" + `abcdefghijklmnopqrstuvwx"`},
		{"GitHub Personal Access Token", "ghp_" + "16C7e42F292c6912E7710c838347Ae178B4a"},
		{"GitHub Fine-Grained PAT", "github_pat_" + "11AAAAAAA0aaaaaaaaaaaa_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{"GitLab Personal Access Token", `export const GITLAB_TOKEN = "` + "glpat-a1B2c3D4e5F6" + `g7H8i9J0";`},
		{"Stripe Secret Key", "sk_live_" + "51NzXyzAbCdEfGhIjKlMnOpQrStUvWx"},
		{"npm Access Token", "npm_" + "1234567890abcdefghijklmnopqrstuvwxyz"},
		{"SendGrid API Key", "SG." + "aBcDeFgHiJkLmNoPqRsT12." + "aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcdefgh"},
		{"Mailgun API Key", "key-" + "1234567890abcdef1234567890abcdef"},
		{"DigitalOcean Personal Access Token", "dop_v1_" + "a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4"},
		{"JWT", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0." + "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"},
		{"Private Key Block", "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234567890abcdefgh\n-----END RSA PRIVATE KEY-----"},
		{"Credentials in URL", `const dbUrl = "mongodb://admin:` + "SuperSecretPass123" + `@cluster0.internal-acme.io:27017/db";`},
		{"Generic API Key/Secret", `const config = { apiKey: "` + "sk_abcdefghijklmnopqr" + `stuvwxyz123456" };`},
		{"Azure Storage Account Key", "AccountKey=" + "odJFCrnl2edlBDdz1C5Jau2RJtBRnlWmTSHf6pWkLUyifDLkDmWJ6UuVTAIjvFu7WICPh" + "DeOZIiBOB/Y6sHrFH=="},
		{"PascalCase identifier (case-insensitive keyword match)", `var SecretKey = "` + "AKIA" + `ABCDEFGHIJKLMNOP";`},
	}

	for _, s := range samples {
		matches, _ := FindSecrets(s.content)
		if len(matches) == 0 {
			t.Errorf("%s: expected at least one match, got none (content: %s)", s.name, s.content)
			continue
		}
		for _, m := range matches {
			if m.Value == "" {
				t.Errorf("%s: matched pattern %q with an empty value", s.name, m.PatternName)
			}
		}
	}
}

// TestFindSecretsSkipsPublicValues ensures values that vendors explicitly
// design to be public (e.g. Stripe publishable keys) are never reported as
// secrets, since flagging them would be a false positive.
func TestFindSecretsSkipsPublicValues(t *testing.T) {
	content := `const stripe = Stripe("` + "pk_live_" + `51NzXyzAbCdEfGhIjKlMnOpQrStUvWx");`
	matches, _ := FindSecrets(content)
	for _, m := range matches {
		t.Errorf("public/non-secret value flagged as a secret: %+v", m)
	}
}

// TestGroupSecretsByValue covers the shape secrets.json is expected to
// have: the same (pattern, value) found in several files collapses into
// one entry listing every URL, distinct secrets stay separate, and URLs
// with no secret contribute nothing (not even an empty entry).
func TestGroupSecretsByValue(t *testing.T) {
	shared := &SecretMatch{PatternName: "AWS Access Key ID", Value: "AKIASHARED000000TEST"}
	onlyInB := &SecretMatch{PatternName: "GitHub Personal Access Token", Value: "ghp_onlyinbTEST0000000000000000"}

	results := []ScanResult{
		{URL: "https://a.example.com/app.js", SecretMatches: []*SecretMatch{shared}},
		{URL: "https://b.example.com/vendor.js", SecretMatches: []*SecretMatch{shared, onlyInB}},
		{URL: "https://c.example.com/no-secrets.js"}, // no matches: must not appear in output
	}

	groups := GroupSecretsByValue(results)
	if len(groups) != 2 {
		t.Fatalf("expected 2 distinct secret groups, got %d: %+v", len(groups), groups)
	}

	byValue := make(map[string]SecretGroup, len(groups))
	for _, g := range groups {
		byValue[g.Value] = g
	}

	sharedGroup, ok := byValue[shared.Value]
	if !ok {
		t.Fatalf("missing group for shared secret %q: %+v", shared.Value, groups)
	}
	wantURLs := []string{"https://a.example.com/app.js", "https://b.example.com/vendor.js"}
	if len(sharedGroup.URLs) != len(wantURLs) {
		t.Fatalf("shared secret: got URLs %v, want %v", sharedGroup.URLs, wantURLs)
	}
	for i, want := range wantURLs {
		if sharedGroup.URLs[i] != want {
			t.Errorf("shared secret: URLs[%d] = %q, want %q (full: %v)", i, sharedGroup.URLs[i], want, sharedGroup.URLs)
		}
	}

	onlyInBGroup, ok := byValue[onlyInB.Value]
	if !ok {
		t.Fatalf("missing group for %q: %+v", onlyInB.Value, groups)
	}
	if len(onlyInBGroup.URLs) != 1 || onlyInBGroup.URLs[0] != "https://b.example.com/vendor.js" {
		t.Errorf("got URLs %v, want exactly [https://b.example.com/vendor.js]", onlyInBGroup.URLs)
	}

	for _, g := range groups {
		for _, u := range g.URLs {
			if u == "https://c.example.com/no-secrets.js" {
				t.Errorf("URL with no secrets leaked into group %+v", g)
			}
		}
	}
}

// TestGroupSecretsByValueEmpty ensures an all-clean scan produces a valid
// empty JSON array ("[]"), not "null", so consumers can always range over it.
func TestGroupSecretsByValueEmpty(t *testing.T) {
	groups := GroupSecretsByValue([]ScanResult{{URL: "https://example.com/clean.js"}})
	if groups == nil {
		t.Fatal("GroupSecretsByValue returned nil, want a non-nil empty slice")
	}
	if len(groups) != 0 {
		t.Errorf("expected no groups, got %+v", groups)
	}

	data, err := EncodeSecretGroups(groups)
	if err != nil {
		t.Fatalf("EncodeSecretGroups: %v", err)
	}
	if got := string(data); got != "[]" {
		t.Errorf("EncodeSecretGroups(empty) = %q, want \"[]\"", got)
	}
}
