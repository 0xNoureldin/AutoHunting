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
