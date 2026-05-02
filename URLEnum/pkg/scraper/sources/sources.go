package sources

import (
	"github.com/noureldinSAF/AutoHunting/URLEnum/pkg/scraper"
	"github.com/noureldinSAF/AutoHunting/URLEnum/pkg/scraper/sources/commoncrawl"
	"github.com/noureldinSAF/AutoHunting/URLEnum/pkg/scraper/sources/urlscan"
	"github.com/noureldinSAF/AutoHunting/URLEnum/pkg/scraper/sources/webarchive"
)

var AllSources = [...]scraper.Source{
	&commoncrawl.Source{},
	&urlscan.Source{},
	&webarchive.Source{},
}

func GetAllSources(apiKeys map[string][]string) []scraper.Source {
	var sources []scraper.Source

	for _, source := range AllSources {
		if source.RequireAPIKey() {
			keys := apiKeys[source.Name()]
			if len(keys) == 0 {
				continue
			}
			switch source.Name() {
			case "urlscan":
				sources = append(sources, urlscan.New(keys))
			default:
				sources = append(sources, source)
			}
			continue
		}
		sources = append(sources, source)
	}

	return sources
}
