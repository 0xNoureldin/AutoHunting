package runner

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEndpointExtractionKinds(t *testing.T) {
	body := `
		const full = "https://api.example.com/v1/users";
		fetch("/api/user");
		axios.post("/v1/login");
		xhr.open("GET", "/internal/data");
		$.ajax({url:"/api/jquery"});
		$.get("/api/get");
		import("/chunks/admin.js");
		const routes = [{path:"/dashboard"}, {to:"/profile"}];
		//# sourceMappingURL=app.js.map
		const gql = "/api/graphql";
	`

	got := ExtractEndpoints("https://example.com/app.js", body, AnalyzeOptions{MaxFindings: 100})
	want := map[string]string{
		"literal_url:https://api.example.com/v1/users": "",
		"fetch:/api/user":         "",
		"axios:/v1/login":         "",
		"xhr:/internal/data":      "",
		"jquery:/api/jquery":      "",
		"jquery:/api/get":         "",
		"import:/chunks/admin.js": "",
		"route:/dashboard":        "",
		"sourcemap:app.js.map":    "",
		"graphql:/api/graphql":    "",
	}
	for _, f := range got {
		delete(want, f.Kind+":"+f.URL)
	}
	if len(want) != 0 {
		t.Fatalf("missing endpoint findings: %#v\ngot: %#v", want, got)
	}
}

func TestExtractSecretsAndMasking(t *testing.T) {
	body := `
		const key = "AKIA1234567890ABCDEF";
		const token = "ghp_abcdefghijklmnopqrstuvwxyz123456";
		const slack = "xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx";
		const stripe = "sk_live_abcdefghijklmnopqrstuvwxyz";
		const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature";
		const client_secret = "realisticSecretValue12345";
	`
	findings := ExtractSecrets(body)
	types := map[string]bool{}
	for _, f := range findings {
		types[f.Type] = true
		if f.Masked == "" || strings.Contains(f.Masked, f.Value) {
			t.Fatalf("secret was not masked correctly: %#v", f)
		}
	}
	for _, typ := range []string{"aws_access_key_id", "github_token", "slack_token", "stripe_key", "jwt", "assignment_client_secret"} {
		if !types[typ] {
			t.Fatalf("missing secret type %s in %#v", typ, findings)
		}
	}
}

func TestSecretFalsePositiveFiltering(t *testing.T) {
	body := `
		const key = "YOUR_API_KEY";
		const secret = "changeme";
		const token = "test-token";
	`
	if got := ExtractSecrets(body); len(got) != 0 {
		t.Fatalf("expected false positives to be filtered, got %#v", got)
	}
}

func TestMaskedSecretOutputRedactsContext(t *testing.T) {
	raw := "ghp_abcdefghijklmnopqrstuvwxyz123456"
	res, err := AnalyzeJSContentForURL("https://example.com/app.js", []byte(`const token = "`+raw+`";`), AnalyzeOptions{
		Secrets:     true,
		Deobfuscate: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.SecretFindings) != 1 {
		t.Fatalf("expected one finding, got %#v", res.SecretFindings)
	}
	finding := res.SecretFindings[0]
	if finding.Value != "" {
		t.Fatalf("expected raw value to be blank by default, got %#v", finding)
	}
	if strings.Contains(finding.Context, raw) {
		t.Fatalf("raw secret leaked in context: %#v", finding)
	}
	if !strings.Contains(finding.Context, "ghp_********3456") {
		t.Fatalf("expected masked secret in context, got %#v", finding)
	}
}

func TestRawSecretOutputKeepsCompleteValue(t *testing.T) {
	raw := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature"
	res, err := AnalyzeJSContentForURL("https://example.com/app.js", []byte(`const token = "`+raw+`";`), AnalyzeOptions{
		Secrets:     true,
		RawSecrets:  true,
		Deobfuscate: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.SecretFindings) != 1 {
		t.Fatalf("expected one finding, got %#v", res.SecretFindings)
	}
	finding := res.SecretFindings[0]
	if finding.Value != raw {
		t.Fatalf("expected complete secret value %q, got %#v", raw, finding)
	}
	if !strings.Contains(finding.Context, raw) {
		t.Fatalf("expected raw context when raw secrets are enabled, got %#v", finding)
	}
}

func TestAnalyzeJavaScriptDeobfuscatesStaticStrings(t *testing.T) {
	body := []byte(
		"const escaped = \"\\x2f\\x61\\x70\\x69\\x2f\\x65\\x73\\x63\";\n" +
			"const b64 = atob(\"L2FwaS91c2Vy\");\n" +
			"const concat = \"/api\" + \"/concat\";\n" +
			"const tmpl = `/api/users/${id}`;\n" +
			"const a = \"/api\";\n" +
			"const b = \"/reconstructed\";\n" +
			"fetch(a + b);\n" +
			"eval(\"fetch('/api/eval')\");\n",
	)
	res := AnalyzeJavaScript("https://example.com/app.js", body, AnalyzeOptions{
		Endpoints:   true,
		Secrets:     true,
		Deobfuscate: true,
		MaxSize:     5 * 1024 * 1024,
	})
	endpoints := map[string]bool{}
	for _, f := range res.Endpoints {
		endpoints[f.URL] = true
	}
	for _, expected := range []string{"/api/esc", "/api/user", "/api/concat", "/api/users/", "/api/reconstructed", "/api/eval"} {
		if !endpoints[expected] {
			t.Fatalf("missing deobfuscated endpoint %q in %#v", expected, res.Endpoints)
		}
	}
}

func TestPackerSignalAndMalformedJSDontPanic(t *testing.T) {
	body := []byte(`eval(function(p,a,c,k,e,d){return p}('x',1,1,'/api/packed'.split('|'),0,{})); function bad( }`)
	res := AnalyzeJavaScript("https://example.com/app.js", body, AnalyzeOptions{
		Endpoints:   true,
		Secrets:     true,
		Deobfuscate: true,
	})
	found := false
	for _, signal := range res.Signals {
		if signal == "packer_detected" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected packer_detected signal, got %#v", res.Signals)
	}
}

func TestDeanEdwardsPackerStaticUnpack(t *testing.T) {
	body := []byte(`eval(function(p,a,c,k,e,d){return p}('0("/1/2")',3,3,'fetch|api|packed'.split('|'),0,{}));`)
	res := AnalyzeJavaScript("https://example.com/app.js", body, AnalyzeOptions{
		Endpoints:   true,
		Secrets:     true,
		Deobfuscate: true,
	})
	endpoints := map[string]bool{}
	for _, f := range res.Endpoints {
		endpoints[f.URL] = true
	}
	if !endpoints["/api/packed"] {
		t.Fatalf("expected packed endpoint, got %#v", res.Endpoints)
	}
	signals := map[string]bool{}
	for _, signal := range res.Signals {
		signals[signal] = true
	}
	if !signals["packer_detected"] || !signals["packer_unpacked"] {
		t.Fatalf("expected packer signals, got %#v", res.Signals)
	}
}

func TestLongEvalPayloadExtractionIsScannerBased(t *testing.T) {
	body := []byte(`eval("` + strings.Repeat("x", 1500) + `fetch('/api/long-eval')");`)
	res := AnalyzeJavaScript("https://example.com/app.js", body, AnalyzeOptions{
		Endpoints:   true,
		Deobfuscate: true,
		MaxSize:     5 * 1024 * 1024,
	})
	for _, f := range res.Endpoints {
		if f.URL == "/api/long-eval" {
			return
		}
	}
	t.Fatalf("expected long eval endpoint, got %#v", res.Endpoints)
}

func TestReadLimitedRejectsLargeInput(t *testing.T) {
	_, err := readLimited(strings.NewReader("abcdef"), 5)
	if err == nil {
		t.Fatal("expected max-size error")
	}
}

func TestFetcherRetriesTransientStatusAndSucceeds(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls == 1 {
			http.Error(w, "temporary", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, `fetch("/api/retry-ok")`)
	}))
	defer server.Close()

	fetcher := NewFetcher(AnalyzeOptions{Timeout: 2 * time.Second, Retries: 1, MaxSize: 1024})
	res, err := fetcher.Fetch(server.URL + "/app.js")
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("expected retry, got %d calls", calls)
	}
	if !strings.Contains(string(res.Body), "/api/retry-ok") {
		t.Fatalf("unexpected body: %s", string(res.Body))
	}
}

func TestFetcherStrictJSRejectsNonJavaScript(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		fmt.Fprint(w, "not really js")
	}))
	defer server.Close()

	fetcher := NewFetcher(AnalyzeOptions{Timeout: 2 * time.Second, StrictJS: true, Retries: 0, MaxSize: 1024})
	if _, err := fetcher.Fetch(server.URL + "/app.js"); err == nil {
		t.Fatal("expected strict-js content type error")
	}
}
