package utils

import (
	"os"
	"path/filepath"
	"testing"
)

// TestReadInputFromFileDropsTrailingEmptyLine is a regression test: a
// subdomain/URL list file written with a trailing newline (the normal
// case for a text editor or this codebase's own writeLines-style
// helpers -- including oneClick's, which feeds this exact file to
// URLEnum's -i) used to produce a spurious empty final entry, since
// strings.Split("a\n", "\n") returns ["a", ""]. Callers use the result
// directly with no filtering of their own, so that empty entry got
// enumerated as a real seed.
func TestReadInputFromFileDropsTrailingEmptyLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subs.txt")
	if err := os.WriteFile(path, []byte("example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := ReadInputFromFile(path)
	if err != nil {
		t.Fatalf("ReadInputFromFile: %v", err)
	}
	want := []string{"example.com"}
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
	path := filepath.Join(dir, "subs.txt")
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
