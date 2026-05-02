package normalize

import "testing"

func TestParamAwareKeyWithoutQueryHasNoQuestionMark(t *testing.T) {
	key := Key("HTTPS://Example.COM/admin#frag", ParamAware)
	if key != "https://example.com/admin" {
		t.Fatalf("unexpected key: %q", key)
	}
}

func TestParamAwareKeyKeepsSortedParameterNames(t *testing.T) {
	key := Key("https://example.com/path?b=2&a=1&B=3#frag", ParamAware)
	if key != "https://example.com/path?a&b" {
		t.Fatalf("unexpected key: %q", key)
	}
}
