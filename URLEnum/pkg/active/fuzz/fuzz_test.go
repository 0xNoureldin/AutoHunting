package fuzz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"
)

// TestEnumerateFindsOnlyRealPaths spins up a local server with a handful of
// "real" paths (distinct status/body from the 404 default) and confirms
// Enumerate reports exactly those, not the wordlist entries that 404 like
// the baseline.
func TestEnumerateFindsOnlyRealPaths(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("admin panel"))
	})
	mux.HandleFunc("/secret.txt", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("a much longer response body than the 404 page has"))
	})
	mux.HandleFunc("/redirect-me", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	wordlist := []string{
		"admin",
		"secret.txt",
		"redirect-me",
		"doesnotexist1",
		"doesnotexist2",
		"", // blank lines in a real wordlist file must be skipped, not 404 as "/"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	found, err := Enumerate(ctx, srv.URL, wordlist, Options{Concurrency: 4, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}

	want := []string{srv.URL + "/admin", srv.URL + "/redirect-me", srv.URL + "/secret.txt"}
	sort.Strings(found)
	sort.Strings(want)

	if len(found) != len(want) {
		t.Fatalf("found %v, want %v", found, want)
	}
	for i := range want {
		if found[i] != want[i] {
			t.Errorf("found[%d] = %q, want %q (full: found=%v want=%v)", i, found[i], want[i], found, want)
		}
	}
}

// TestEnumerateSkipsEverythingLikeBaseline covers a target that returns the
// same response for literally everything (a common "soft 404" pattern, or
// a minimal static site) -- Enumerate must report zero findings, not flag
// every wordlist entry as interesting.
func TestEnumerateSkipsEverythingLikeBaseline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("same page regardless of path"))
	}))
	defer srv.Close()

	wordlist := []string{"admin", "login", "api", "backup.zip"}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	found, err := Enumerate(ctx, srv.URL, wordlist, Options{Concurrency: 4, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("expected no findings against a uniform-response server, got %v", found)
	}
}

func TestEnumerateEmptyWordlist(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	found, err := Enumerate(ctx, "https://example.invalid", nil, Options{})
	if err != nil {
		t.Fatalf("Enumerate with empty wordlist should not error, got: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("expected no findings for an empty wordlist, got %v", found)
	}
}
