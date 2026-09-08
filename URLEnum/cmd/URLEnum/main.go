// this is the script of url enumeration tool
package main
import (
	"flag"
	"time"
	"github.com/cyinnove/logify"
	//"github.com/noureldinSAF/AutoHunting/URLEnum/internal/runner"
	"github.com/noureldinSAF/AutoHunting/URLEnum/test"
)

func main() {
	//logify.MaxLevel = logify.Error
	startTime := time.Now()
	options := &test.Options{}
	flag.StringVar(&options.Domain, "d", "", "Domain to enumerate URLs for")
	flag.IntVar(&options.Timeout, "timeout", 60, "Timeout for each request in seconds")
	flag.IntVar(&options.PassiveConcurrency, "pc", 5, "Number of concurrent passive requests")
	flag.IntVar(&options.ActiveConcurrency, "ac", 10, "Number of concurrent active requests")
	flag.StringVar(&options.Input, "i", "", "Input file with list of URLs")
	flag.StringVar(&options.Output, "o", "results.txt", "Output file for results")
	flag.BoolVar(&options.ActiveEnabled, "active", false, "Enable active scanning mode (crawl + headless)")
	flag.BoolVar(&options.IncludeSubdomains, "subs", false, "Include subdomains in active scanning")
	flag.StringVar(&options.Wordlist, "w", "", "Wordlist file for path/content fuzzing (one path per line, enabled independently of -active)")
	flag.Parse()

	if err := test.Run(options); err != nil {
		logify.Errorf("Error running URL enumeration: %v", err)
		return
	}
	elapsed := time.Since(startTime)
	logify.Infof("URL enumeration completed in %s", elapsed)
}
	
