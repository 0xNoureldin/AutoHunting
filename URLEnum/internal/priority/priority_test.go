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
