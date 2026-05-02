package runner

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"
)

func TestActiveSeedsKeepsRootsAndHighValuePaths(t *testing.T) {
	seeds := activeSeeds(
		[]string{"example.com"},
		[]string{
			"https://example.com/static/app.css",
			"https://example.com/admin/users?id=1",
			"https://example.com/api/v1/users",
			"https://example.com/download/manual.pdf",
		},
		10,
	)

	want := []string{
		"https://example.com/",
		"https://example.com/admin/users",
		"https://example.com/api/v1/users",
	}
	for _, expected := range want {
		if !slices.Contains(seeds, expected) {
			t.Fatalf("expected seed %q in %v", expected, seeds)
		}
	}
	if slices.Contains(seeds, "https://example.com/static/app.css") {
		t.Fatalf("static asset was used as active seed: %v", seeds)
	}
	if slices.Contains(seeds, "https://example.com/download/manual.pdf") {
		t.Fatalf("static document was used as active seed: %v", seeds)
	}
}

func TestActiveSeedsEnforcesLimit(t *testing.T) {
	seeds := activeSeeds(
		[]string{"a.example.com", "b.example.com", "c.example.com"},
		[]string{"https://a.example.com/admin", "https://b.example.com/login"},
		2,
	)
	if len(seeds) != 2 {
		t.Fatalf("expected two seeds, got %d: %v", len(seeds), seeds)
	}
}

func TestRunPassiveSourceWithRetryRecovers(t *testing.T) {
	src := &flakySource{failFor: 1}
	urls, err := runPassiveSourceWithRetry(context.Background(), &Options{Timeout: 1}, passiveJob{
		query:  "example.com",
		source: src,
	}, newLimiter(0))
	if err != nil {
		t.Fatal(err)
	}
	if src.calls != 2 {
		t.Fatalf("expected source to be retried once, got %d calls", src.calls)
	}
	if len(urls) != 1 || urls[0] != "https://example.com/admin" {
		t.Fatalf("unexpected urls: %v", urls)
	}
}

type flakySource struct {
	calls   int
	failFor int
}

func (s *flakySource) Name() string        { return "flaky" }
func (s *flakySource) RequireAPIKey() bool { return false }

func (s *flakySource) Search(_ context.Context, _ string, _ *http.Client) ([]string, error) {
	s.calls++
	if s.calls <= s.failFor {
		return nil, errors.New("i/o timeout")
	}
	return []string{"https://example.com/admin"}, nil
}
