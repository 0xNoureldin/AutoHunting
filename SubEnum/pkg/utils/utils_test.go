package utils

import (
	"os"
	"path/filepath"
	"testing"
)

// TestReadInputFromFileDropsTrailingEmptyLine is a regression test for a
// false-positive/empty-domain bug: a domain-list file written with a
// trailing newline (the normal case for any text editor or this
// codebase's own writeLines-style helpers) produced a spurious empty
// string as the final entry, since strings.Split("a\n", "\n") returns
// ["a", ""]. loadQueries in the SubEnum runner uses this result directly
// with no filtering of its own, so that empty entry got enumerated as a
// real query: passive sources failed on it, and DNS brute-force turned
// every wordlist word into "word." (word + "." + "") -- a bare
// root-zone query that spuriously "resolves" against ccTLDs known for
// wildcarding everything (.cm, .tk, .bd, ...), producing hundreds of
// fake "subdomains" that were really just wordlist entries.
func TestReadInputFromFileDropsTrailingEmptyLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "domains.txt")
	if err := os.WriteFile(path, []byte("tuwaiq.edu.sa\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := ReadInputFromFile(path)
	if err != nil {
		t.Fatalf("ReadInputFromFile: %v", err)
	}
	want := []string{"tuwaiq.edu.sa"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v (a trailing newline must not produce an extra empty entry)", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestReadInputFromFileTrimsBlanksCommentsAndCRLF(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "domains.txt")
	content := "example.com\r\n\n  \n# a comment\nfoo.example.com\r\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := ReadInputFromFile(path)
	if err != nil {
		t.Fatalf("ReadInputFromFile: %v", err)
	}
	want := []string{"example.com", "foo.example.com"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q (full: got=%v want=%v)", i, got[i], want[i], got, want)
		}
	}
}

func TestReadInputFromFileMissingFile(t *testing.T) {
	if _, err := ReadInputFromFile("/does/not/exist"); err == nil {
		t.Error("expected an error reading a missing file")
	}
}
