package runner

import (
	"context"
	"time"
	"github.com/noureldinSAF/AutoHunting/URLEnum/pkg/scraper"
)

// wrapper around source execution with rate limiting
func runSource(ctx context.Context, src scraper.Source, q string, client *http.Client) ([]string, error) {
	lim := limiterForSource(src.Name())
	if err := lim.Wait(ctx); err != nil {
		return nil, err
	}
	return src.Search(ctx, q, client)
}
