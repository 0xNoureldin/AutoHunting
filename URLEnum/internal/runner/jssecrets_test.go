package runner

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestExtractJSURLsFiltersAndCanonicalizes(t *testing.T) {
	got := extractJSURLs([]string{
		"https://Example.com/static/app.js#frag",
		"https://example.com/static/app.js",
		"https://example.com/static/app.js?v=1",
		"https://example.com/static/app.js.map",
		"https://example.com/_next/data/app.js.json",
		"https://example.com/assets/module.mjs",
		"https://example.com/assets/common.cjs?x=1",
		"https://example.com/assets/style.css",
		"javascript:alert(1)",
	})

	want := []string{
		"https://example.com/assets/common.cjs?x=1",
		"https://example.com/assets/module.mjs",
		"https://example.com/static/app.js",
		"https://example.com/static/app.js?v=1",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("unexpected JS URLs:\nwant: %v\ngot:  %v", want, got)
	}
}

func TestRunJSSecretStageWritesMaskedSecretArtifacts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(`const token = "ghp_abcdefghijklmnopqrstuvwxyz123456";`))
	}))
	defer srv.Close()

	outDir := t.TempDir()
	opts := &Options{
		JSOutDir:      outDir,
		JSConcurrency: 1,
		JSTimeout:     2,
		JSRetries:     0,
		JSMaxSize:     1024 * 1024,
	}

	if err := runJSSecretStage([]string{srv.URL + "/static/app.js", srv.URL + "/image.png"}, opts); err != nil {
		t.Fatal(err)
	}

	jsURLs, err := os.ReadFile(filepath.Join(outDir, jsURLsFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(jsURLs)) != srv.URL+"/static/app.js" {
		t.Fatalf("unexpected JS URL list: %q", string(jsURLs))
	}

	secrets, err := os.ReadFile(filepath.Join(outDir, jsSecretsFile))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(secrets), `"type":"github_token"`) {
		t.Fatalf("expected github token finding, got: %s", secrets)
	}
	if strings.Contains(string(secrets), "abcdefghijklmnopqrstuvwxyz123456") {
		t.Fatalf("raw secret leaked in masked output: %s", secrets)
	}
	if !strings.Contains(string(secrets), "ghp_********3456") {
		t.Fatalf("expected masked token in output, got: %s", secrets)
	}
}

func TestRunJSSecretStageCanWriteRawSecretArtifacts(t *testing.T) {
	raw := "ghp_abcdefghijklmnopqrstuvwxyz123456"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(`const token = "` + raw + `";`))
	}))
	defer srv.Close()

	outDir := t.TempDir()
	opts := &Options{
		JSOutDir:      outDir,
		JSConcurrency: 1,
		JSTimeout:     2,
		JSRetries:     0,
		JSMaxSize:     1024 * 1024,
		JSRawSecrets:  true,
	}

	if err := runJSSecretStage([]string{srv.URL + "/static/app.js"}, opts); err != nil {
		t.Fatal(err)
	}

	secrets, err := os.ReadFile(filepath.Join(outDir, jsSecretsFile))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(secrets), `"value":"`+raw+`"`) {
		t.Fatalf("expected raw secret value in output, got: %s", secrets)
	}
}

func TestRunJSSecretStageHandlesNoJSURLs(t *testing.T) {
	outDir := t.TempDir()
	opts := &Options{JSOutDir: outDir, JSConcurrency: 1, JSTimeout: 1, JSMaxSize: 1024}

	if err := runJSSecretStage([]string{"https://example.com/index.html"}, opts); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{jsURLsFile, jsResultsFile, jsSecretsFile, jsSummaryFile} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Fatalf("expected %s to be created: %v", name, err)
		}
	}
}
