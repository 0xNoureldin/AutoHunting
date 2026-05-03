package runner

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"

	"github.com/noureldinSAF/AutoHunting/URLEnum/pkg/scraper"
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

func TestArchiveSourcesUseTheirOwnRetryBudget(t *testing.T) {
	for _, sourceName := range []string{"commoncrawl", "webarchive"} {
		if got := passiveRetryAttempts(sourceName); got != 1 {
			t.Fatalf("expected %s to be retried inside the source only, got runner attempts=%d", sourceName, got)
		}
	}
}

func TestPassiveRequestTimeoutRespectsConfiguredTimeout(t *testing.T) {
	opts := &Options{Timeout: 30}
	for _, sourceName := range []string{"commoncrawl", "webarchive", "urlscan"} {
		if got := passiveRequestTimeout(opts, sourceName); got.Seconds() != 30 {
			t.Fatalf("expected %s timeout to respect -timeout=30, got %s", sourceName, got)
		}
	}
}

func TestCommonCrawlDisabledAfterTenConsecutiveFailures(t *testing.T) {
	src := &namedFlakySource{name: "commoncrawl", failFor: 20}
	queries := []string{
		"one.example.com",
		"two.example.com",
		"three.example.com",
		"four.example.com",
		"five.example.com",
		"six.example.com",
		"seven.example.com",
		"eight.example.com",
		"nine.example.com",
		"ten.example.com",
		"eleven.example.com",
		"twelve.example.com",
	}

	runPassiveStage(
		context.Background(),
		&Options{Timeout: 1, Concurrency: 1},
		queries,
		[]scraper.Source{src},
		map[string]*limiter{"commoncrawl": newLimiter(0)},
		newResultStore(parseDedupeMode("exact")),
	)

	if src.calls != commonCrawlFailureThreshold {
		t.Fatalf("expected commoncrawl to stop after %d failures, got %d calls", commonCrawlFailureThreshold, src.calls)
	}
}

func TestCommonCrawlCircuitResetsAfterSuccess(t *testing.T) {
	breaker := newSourceCircuitBreaker(2)
	if disabled := breaker.RecordFailure(); disabled {
		t.Fatal("breaker disabled too early")
	}
	breaker.RecordSuccess()
	if disabled := breaker.RecordFailure(); disabled {
		t.Fatal("breaker did not reset after success")
	}
	if disabled := breaker.RecordFailure(); !disabled {
		t.Fatal("breaker did not disable after two fresh failures")
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

type namedFlakySource struct {
	name    string
	calls   int
	failFor int
}

func (s *namedFlakySource) Name() string        { return s.name }
func (s *namedFlakySource) RequireAPIKey() bool { return false }

func (s *namedFlakySource) Search(_ context.Context, _ string, _ *http.Client) ([]string, error) {
	s.calls++
	if s.calls <= s.failFor {
		return nil, errors.New("i/o timeout")
	}
	return []string{"https://example.com/admin"}, nil
}
