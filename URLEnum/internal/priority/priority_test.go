package priority

import "testing"

func TestSortPrioritizesInterestingURLsDeterministically(t *testing.T) {
	urls := []string{
		"https://example.com/about",
		"https://example.com/admin?redirect=https://evil.example",
		"https://example.com/api/users?id=1",
	}

	got := Sort(urls)
	if got[0] != "https://example.com/admin?redirect=https://evil.example" {
		t.Fatalf("unexpected first URL: %v", got)
	}

	gotAgain := Sort(urls)
	for i := range got {
		if got[i] != gotAgain[i] {
			t.Fatalf("sort is not deterministic: %v vs %v", got, gotAgain)
		}
	}
}

func TestSortKeepsParameterURLsAheadOfGenericJavaScript(t *testing.T) {
	urls := []string{
		"https://example.com/_next/static/chunks/02b763e81740e9bc.js",
		"https://example.com/products?id=123",
		"https://example.com/",
	}

	got := Sort(urls)
	if got[0] != "https://example.com/products?id=123" {
		t.Fatalf("expected id parameter URL first, got %v", got)
	}
}

func TestRankMatchesImportantTermsByPathSegment(t *testing.T) {
	admin := Rank("https://example.com/assets/admin.js")
	administrator := Rank("https://example.com/administrator")
	apiary := Rank("https://example.com/apiary")

	if admin.Score <= Rank("https://example.com/_next/static/chunks/app.js").Score {
		t.Fatalf("admin JavaScript should outrank generic JavaScript: admin=%#v", admin)
	}
	if administrator.Score <= 0 {
		t.Fatalf("administrator path should be interesting: %#v", administrator)
	}
	if apiary.Score != 0 {
		t.Fatalf("apiary should not be treated as an API path: %#v", apiary)
	}
}

func TestRankScoresAPIHosts(t *testing.T) {
	r := Rank("https://api.example.com/v1/users")
	if r.Score == 0 {
		t.Fatalf("expected API host to be scored: %#v", r)
	}
}

func TestRequestedTermsScoreInPathHostAndParameter(t *testing.T) {
	tests := []string{
		"https://example.com/signup",
		"https://example.com/api/users",
		"https://example.com/auth/callback",
		"https://example.com/dev/tools",
		"https://example.com/admin",
		"https://signup.example.com/",
		"https://api.example.com/",
		"https://auth.example.com/",
		"https://dev.example.com/",
		"https://admin.example.com/",
		"https://example.com/?signup=true",
		"https://example.com/?api_key=abc",
		"https://example.com/?auth_token=abc",
		"https://example.com/?dev=true",
		"https://example.com/?admin=true",
	}

	for _, raw := range tests {
		r := Rank(raw)
		if r.Score == 0 {
			t.Fatalf("expected %s to receive priority score, got %#v", raw, r)
		}
	}
}

func TestShortPriorityTermsAvoidCommonFalsePositives(t *testing.T) {
	for _, raw := range []string{
		"https://example.com/apiary",
		"https://device.example.com/",
		"https://example.com/?device=ios",
	} {
		if r := Rank(raw); r.Score != 0 {
			t.Fatalf("expected %s to avoid short-term false positive, got %#v", raw, r)
		}
	}
}
