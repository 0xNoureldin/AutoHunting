package runner

import (
	"os"
	"path/filepath"
	"testing"
)

// TestReadInputFromFileDropsTrailingEmptyLine is a regression test: a JS
// URL list file written with a trailing newline (the normal case for a
// text editor or this codebase's own writeLines-style helpers --
// including oneClick's, which feeds this exact file to jsAnalyzer's -i)
// used to produce a spurious empty final entry, since
// strings.Split("a\n", "\n") returns ["a", ""]. The caller scans the
// result directly with no filtering of its own, so that empty entry got
// scanned as an extra, invalid URL.
func TestReadInputFromFileDropsTrailingEmptyLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "js.txt")
	if err := os.WriteFile(path, []byte("https://example.com/app.js\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := ReadInputFromFile(path)
	if err != nil {
		t.Fatalf("ReadInputFromFile: %v", err)
	}
	want := []string{"https://example.com/app.js"}
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
	path := filepath.Join(dir, "js.txt")
	content := "https://example.com/a.js\r\n\n  \n# a comment\nhttps://example.com/b.js\r\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := ReadInputFromFile(path)
	if err != nil {
		t.Fatalf("ReadInputFromFile: %v", err)
	}
	want := []string{"https://example.com/a.js", "https://example.com/b.js"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q (full: got=%v want=%v)", i, got[i], want[i], got, want)
		}
	}
}
