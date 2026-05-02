package runner

import (
	"strings"
	"sync"

	"github.com/noureldinSAF/AutoHunting/URLEnum/pkg/scraper"
)

const commonCrawlFailureThreshold = 10

type sourceCircuitBreaker struct {
	mu        sync.Mutex
	threshold int
	failures  int
	disabled  bool
}

func sourceCircuitBreakers(srcs []scraper.Source) map[string]*sourceCircuitBreaker {
	breakers := make(map[string]*sourceCircuitBreaker, len(srcs))
	for _, src := range srcs {
		name := strings.ToLower(strings.TrimSpace(src.Name()))
		if name == "commoncrawl" {
			breakers[src.Name()] = newSourceCircuitBreaker(commonCrawlFailureThreshold)
		}
	}
	return breakers
}

func newSourceCircuitBreaker(threshold int) *sourceCircuitBreaker {
	if threshold <= 0 {
		threshold = 1
	}
	return &sourceCircuitBreaker{threshold: threshold}
}

func (b *sourceCircuitBreaker) Disabled() bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.disabled
}

func (b *sourceCircuitBreaker) Threshold() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.threshold
}

func (b *sourceCircuitBreaker) RecordFailure() bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.disabled {
		return false
	}
	b.failures++
	if b.failures < b.threshold {
		return false
	}
	b.disabled = true
	return true
}

func (b *sourceCircuitBreaker) RecordSuccess() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures = 0
}
