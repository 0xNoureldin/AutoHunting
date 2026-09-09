# 🚀 AutoHunting

**AutoHunting** is a collection of automation tools designed to streamline and enhance the bug bounty hunting workflow.  
This repository brings together multiple recon, scanning, and analysis utilities to help identify vulnerabilities efficiently.

---

## 🎯 Purpose

The goal of this project is to:
- Automate repetitive bug bounty tasks
- Improve recon efficiency
- Reduce manual effort
- Provide a modular toolkit for security researchers

---

## 🧰 Tools Overview

Below is a description of each tool included in this repository:

---

### 🔍 AI_Validator
Validates discovered info and filters out non-relevant or inactive targets to improve the quality of recon results using AI.

---

### 🐳 DockerScanner
Scans Docker images and containers for:
- Secrets (API keys, tokens)
- Misconfigurations
- Sensitive files  
Useful for supply chain and DevOps security testing.

---

### 🌐 DomEnum
Performs domain enumeration to discover:
- Subdomains
- Related domains  
Helps expand the attack surface during reconnaissance.

---

### 🔗 URLenum
Extracts and enumerates URLs from various sources to identify:
- Hidden endpoints
- API routes
- Interesting parameters

---

### 🧠 SubEnum
Subdomain enumeration tool designed to:
- Discover subdomains from multiple sources
- Aggregate and clean results

---

### 📡 asn2cidr
Converts ASN (Autonomous System Number) into CIDR ranges.  
Useful for identifying IP ranges owned by a target organization.

---

### 🌍 cidr2ips
Expands CIDR ranges into individual IP addresses for scanning and analysis.

---

### 🧪 dnsenum
Performs DNS enumeration to gather:
- Records (A, MX, TXT, etc.)
- Subdomains
- DNS misconfigurations

---

### 🧵 fuzzing
Automates fuzzing of:
- Endpoints
- Parameters
- Inputs  
Helps discover hidden functionality and vulnerabilities.

---

### 🧠 jsAnalyzer
Analyzes JavaScript files to extract:
- Endpoints
- Secrets
- Hidden functionality

---

### 🔐 jwt
Handles JWT (JSON Web Token) analysis:
- Decoding tokens
- Checking weaknesses
- Testing for common misconfigurations

---

### 📦 npm
Scans npm packages for:
- Exposed secrets
- Malicious patterns
- Supply chain risks

---

### ⚡ nuclei
Integration or wrapper for **Nuclei** to automate vulnerability scanning using templates.

---

### 🔎 portScanner
Performs port scanning to identify:
- Open ports
- Running services  
Scans the top 100 most common ports by default; `-all-ports` scans all 65535, or `-ports` scans
a specific comma-separated list/range. Useful for network-level recon.

---

### 🧬 regex
Custom regex-based engine used to:
- Detect secrets
- Extract patterns from files and responses

---

### ☁️ s3
Scans for exposed AWS S3 buckets and misconfigurations:
- Public access
- Sensitive file exposure

---

### 🌍 vhosts
Discovers virtual hosts associated with a target, two ways:
- Given a list of hosts, groups them by the IP(s) they resolve to
- Given a list of candidate hosts **and** a target IP/host, fuzzes the HTTP `Host` header
  against that one target to find vhosts with no DNS record of their own -- hidden domains
  and internal services a server routes to but that DNS never reveals

---

### 🧾 whois
Performs WHOIS lookups to gather:
- Ownership details
- Registration data
- Related infrastructure

---

### ⚡ oneClick
One command recon pipeline. Give it a domain (or a file of domains) and it chains together
**SubEnum → URLEnum → jsAnalyzer**: subdomain enumeration, then URL enumeration on the
discovered hosts, then secret scanning on the discovered `.js` files. Optional add-on stages
(off by default): virtual-host discovery (`-vhost`) and port scanning (`-port-scan`) across
every discovered subdomain. See [Module Usage Details](#-module-usage-details) below for usage.

---

## ⚙️ Installation

```bash
git clone https://github.com/noureldinSAF/AutoHunting.git
cd AutoHunting
```

## 🤖 Notes

This tool is built using patterns described in my [Go Syntax & Notes](https://github.com/noureldinSAF/GoLearning) repository. It demonstrates concurrency with goroutines, HTTP requests, and parsing logic tailored for recon tasks. Feel free to explore the code to learn how these patterns are applied in a real-world reconnaissance tool.

## 📘 Module Usage Details

### asn2cidr
Converts autonomous system numbers (ASNs) into CIDR ranges. Navigate to the `asn2cidr` directory and run:
```bash
./asnmap -asn AS32934   # ASN for Facebook
```

### cidr2ips
Transforms a list of CIDR blocks into individual IP addresses. Place your CIDRs in a `list.txt` file and run:
```bash
cat list.txt | go run .
```

### asn2cidr + cidr2ips
Combine both modules by piping output from `asn2cidr` into `cidr2ips`:
```bash
./asn2cidr/asnmap -asn AS32934 | go run .
```
Use `wc -l` to count the resulting IPs.

### Domain Enumeration (DomEnum)
Enumerate all domains related to a company by name (passive or active). From `DomEnum/cmd/DomEnum`:
```bash
go run . -h
go run . -q Swisscom -o swisscomDomains.txt                # passive
go run . -q Swisscom -o swisscomDomains.txt -active       # passive + active
go run . -q Swisscom -o swisscomDomains.txt -active -t 60 # set timeout in seconds
```
Passive enumeration uses three sources:
1. `crtsh` – no API key required.
2. `whoisfreaks` – free with API key; results are paginated (50 domains per page). To fetch all pages automatically, modify `ro.CurrentPage >= 1` to `ro.TotalPages >= ro.TotalPages` in `whoisfreaks.go`. A paid plan removes rate limits.
3. `whoisxmlapi` – paid.

APIs for all modules are configured in [`DomEnum/internal/config/config.yaml`](https://github.com/noureldinSAF/AutoHunting/tree/main/DomEnum/cmd/DomEnum/internal/config/config.yaml). Provide keys for `whoisfreaks` or `whoisxmlapi` to enable those sources.

### DnsEnum
Checks DNS records (A, AAAA, CNAME, etc.) for a target:
```bash
go run .
# or display help
go run ./main.go -h
```

### SubEnum
Enumerates subdomains. In `SubEnum/cmd/subenum`:
```bash
go run . -h
go run . -active -c 10 -i domains.txt -o subs.txt                        # zone transfer
go run . -mutations -c 20 -i domains.txt -o subs.txt -e -max-mutations-size 50 # permutation guessing
go run . -w wordlist.txt -i domains.txt -o subs.txt                      # DNS brute-force fuzzing
```
`-active` (zone transfer), `-mutations` (alterx permutation-based guessing, e.g. `dev-api`
from a known `api`), and `-w <wordlist>` (DNS brute-force: each candidate is
`word + "." + domain`, concurrently DNS-probed for a live record) are three independent
techniques — each off by default, combine any of them freely.

### vhost (virtual host enumeration)
In `vhosts/cmd/vhoster`, two modes depending on whether `-ips` is given:
```bash
# Mode 1: group known hosts by the IP(s) they resolve to
go run . -hosts subs.txt -output vhostedSubs

# Mode 2: vhost fuzzing -- find hosts with NO DNS record at all, by sending each
# candidate as the Host header to a fixed target and diffing the response against
# a baseline (the same effect as pinning the domain to an IP in /etc/hosts and
# fuzzing the Host header, e.g. `gobuster vhost`, without touching system DNS config)
go run . -hosts candidates.txt -ips targets.txt -output vhostResults -concurrency 10
```
`-ips` accepts a domain name as well as a literal IP -- either way, every candidate in
`-hosts` is requested against that same connection target with only the `Host` header
changed. `candidates.txt` needs full hostnames (e.g. `admin.example.com`), not bare words;
oneClick's `-vhost` (below) builds this file for you from a subdomain wordlist. In fuzzing
mode, a candidate that comes back 403 Forbidden is recorded separately -- alongside
`-output`'s normal results, as `<output>_403.json` (e.g. `vhostResults_403.json`) -- when its
403 is genuinely distinct from what an unrecognized host gets right now (confirmed the same
way a hit is: against a live control probe), since a 403 usually means the host exists and is
just being gated rather than that it doesn't exist at all. A target whose default response is
itself a generic 403 for every unrecognized `Host` (or one hit by a WAF/rate limit mid-scan)
would otherwise turn the entire wordlist into "403s", which carries no signal.

### portScanner
Performs TCP (or UDP) port scanning:
```bash
go run . -host-file subs.txt -host-threads 52 -threads 86 -output-file ports.txt -timeout 3       # top 100 ports (default)
go run . -host example.com -all-ports -output-file ports.txt                                       # all 65535 ports
go run . -host example.com -ports 80,443,8000-8100 -output-file ports.txt                           # specific ports/ranges
```
`-ports` (comma-separated ports and/or ranges, e.g. `80,443,1000-2000`) takes precedence over
`-all-ports` if both are given; with neither, it scans `Top100Ports`, the built-in list of the
100 most commonly open ports.

### URLEnum (passive and active)
Enumerates URLs from subdomains:
```bash
go run . -i subs.txt -o urls1.txt -pc 20 -ac 50 -timeout 400 -subs -active
go run . -i subs.txt -o urls1.txt -subs -w wordlist.txt   # path/content fuzzing
```
Notes:
1. The `commoncrawl` source does not work in Codespaces; to use outside Codespaces remove the API key requirement in `commoncrawl.go` (`RequireAPIKey` should return `false`).
2. Specify a reasonable timeout for headless browser enumeration.
3. Increasing concurrency can reduce accuracy.
4. Passive enumeration takes ~2–3 minutes; active enumeration may take up to an hour.
5. Non‑script files (e.g., SVG, JPEG) are ignored automatically.
6. The tool returns unique URLs by default.
7. `-w <wordlist>` fuzzes each active seed with the wordlist as paths (one request per path,
   concurrently), reporting the ones whose response differs from a captured baseline. It
   runs independently of `-active` and can be combined with it.

### JSAnalyzer
Analyzes JavaScript files and extracts secrets:
```bash
go run . -i js.txt -o output.json -timeout 600 -c 10 -only secrets
```
With `-only secrets` (secrets and nothing else), the output is grouped by secret instead of
by URL: each distinct `(pattern, value)` appears once, with a `urls` array listing every file
it was found in, and files with no secret are left out entirely — so a key repeated across
many bundled/minified files shows up as one entry, not one per file. Any other combination of
`-subdomains`/`-cloud`/`-endpoints`/`-params`/`-npm`/`-secrets` keeps the original one-entry-
per-URL shape (`secret_matches` included per URL, alongside whatever else was found there).
### oneClick (one command recon pipeline)
Runs subdomain enumeration, URL enumeration, and JS secret scanning back to back with a
single command — no need to juggle each tool's flags or pipe files between them by hand.
From `oneClick/cmd/oneclick`:
```bash
go run . -d example.com                    # passive, fast (default)
go run . -f domains.txt                    # same, for a list of domains
go run . -d example.com -active            # deeper: zone transfer, crawling, headless browsing
go run . -d example.com -fuzz-subs         # wordlist-based subdomain DNS brute-force
go run . -d example.com -fuzz-urls         # wordlist-based URL path/content fuzzing
go run . -d example.com -mutations         # alterx permutation-based subdomain guessing
go run . -d example.com -vhost             # Host-header vhost discovery (no DNS record needed)
go run . -d example.com -port-scan         # TCP port scan every discovered subdomain (top 100 ports)
go run . -d example.com -port-scan -all-ports        # scan all 65535 ports instead
go run . -d example.com -port-scan -ports 1-1000,8080,8443  # scan specific ports/ranges instead
go run . -d example.com -live              # stream each stage's live output to the terminal
go run . -d example.com -fuzz-subs -vhost -live -quiet-stages  # live, but banners/summaries only
go run . -d example.com -o results/acme -c 20 -t 120
go run . -resume oneClick/results/example.com_20260909_030405  # pick up an interrupted run
go run . -h                                # full option list
```
Results (subdomains, vhost-discovered subdomains on their own when `-vhost` is used
(`vhost_subdomains.txt`), every subdomain that returns 403 Forbidden from any source --
passive, brute-force, or vhost discovery (`403.txt`, always checked, also merged back into
`subdomains.txt`) -- URLs, the filtered list of JS files, `secrets.json`, every notable open
port (`ports.txt`, also merged back into `subdomains.txt`) when `-port-scan` is used, a
`SUMMARY.txt`, and a combined log) are written to
`oneClick/results/<target>_<timestamp>/` unless `-o` is given. Active mode is off by default
since it can take from several minutes up to an hour (see the URLEnum notes above); pass
`-active` when you want deeper coverage.

`-fuzz-subs` and `-fuzz-urls` each enable wordlist-based fuzzing independently — DNS
brute-force for subdomain enumeration, and path/content discovery (baseline-diffing) for URL
enumeration — and independently of `-active`/`-mutations`, so any combination works. On first
use each downloads and caches its own SecLists wordlist (`subdomains-top1million-5000.txt`,
`common.txt`) into `oneClick/wordlists/`; pass `-sw <path>`/`-uw <path>` to use your own
instead (which also implies the matching `-fuzz-subs`/`-fuzz-urls`, so you don't need both).
Like `-active`, they're thorough but slow (thousands of candidates per target), so either one
also bumps the default timeout to 300s unless `-t` is set explicitly.

`-mutations` enables alterx permutation-based subdomain guessing (e.g. trying `dev-api` and
`api-dev` once `api` is known). It's off by default and independent of `-active`, `-fuzz-subs`,
and `-fuzz-urls` — combine it with any of them.

`-vhost` finds virtual hosts that don't exist in DNS at all — only in the target server's own
routing config — which every DNS-based technique above (passive sources, `-fuzz-subs`,
`-mutations`) is blind to by nature. It probes each target directly over HTTP(S) with the
`Host` header swapped to `word.domain` for every entry in the subdomain wordlist (the same one
`-fuzz-subs` downloads/uses, or `-sw`), keeping the connection target fixed, and reports a
candidate only once it's confirmed, against a *live* control probe taken at that same moment
(not just a baseline captured once at the start), to be genuinely different from what an
unrecognized host gets right now. The control probe itself is also built as `random.domain` --
a subdomain of the same target zone, not an unrelated/foreign host -- since a CDN or WAF
commonly treats an unrecognized name that's still inside its own zone (falling through to the
origin's generic catch-all vhost) differently from a Host header for a totally unrelated
domain (often blocked at the edge before ever reaching the origin); comparing against the
latter would never match the former, making every real candidate look "distinct" regardless of
whether it's an actual hit. That live-recheck is what keeps a WAF or rate limit triggered
mid-scan (or a target that simply 403s every unconfigured name in its zone) from turning the
entire wordlist into "hits" -- once that happens every remaining response starts looking
different from the stale starting baseline, which a one-time baseline comparison alone can't
tell apart from a real discovery. This is the
`vhosts` tool's fuzzing mode (see above) wired in automatically; discovered vhosts are merged
into the subdomain list before URL enumeration runs, so they get the same downstream
treatment as anything DNS found -- and are also written on their own to
`vhost_subdomains.txt`, so you can tell which entries in `subdomains.txt` came from DNS versus
from vhost fuzzing alone. A candidate whose 403 Forbidden is, by that same live-control check,
genuinely distinct from what an unrecognized host gets right now is written to
`vhost_403.txt`. Off by default, independent of
`-active`/`-mutations`/`-fuzz-subs`/`-fuzz-urls`, and combinable with any of them; also bumps
the default timeout to 300s unless `-t` is set explicitly.

Once every subdomain is known -- from passive sources, `-fuzz-subs`, and `-vhost` alike --
every one of them is probed directly, on its own hostname, for a 403 Forbidden response.
Unlike `-vhost`'s own check (which tests wordlist *guesses* against an unknown routing target
and needs the live-control comparison to rule out "none of these hosts are real"), this runs
on subdomains already confirmed real, so a 403 on any of them is meaningful on its own -- no
baseline needed. This step always runs, regardless of which flags above were used (even a
bare `go run . -d example.com` with no flags at all). Combined with `-vhost`'s own
`vhost_403.txt` findings and deduped, the result becomes `403.txt`, which is then merged into
`subdomains.txt`: a 403 usually means the host exists and is worth a closer look, not that it
doesn't exist, so it gets the same downstream treatment (URL enumeration, port scanning) as
anything else discovered. One caveat: a `-vhost`-only host has no DNS record of its own (that
was the whole point of finding it that way), so once merged into `subdomains.txt` it can still
only actually be reached the same way `-vhost` reached it -- later stages that resolve DNS
directly (URL enumeration, `-port-scan`) won't be able to connect to it under its bare name.

`-port-scan` TCP-connect scans every discovered subdomain (including any found via `-vhost`)
with `portScanner`, the top 100 most commonly open ports by default. Pass `-all-ports` to scan
all 65535 instead, or `-ports <spec>` (e.g. `80,443,8000-8100`, same comma/range syntax as
`portScanner`'s own `-ports`) for a specific list -- either flag implies `-port-scan`, and
`-ports` wins if both are given. Only "notable" open ports -- not 80, 443, 8080, or 8443, the
common web ports already covered by every other web-facing stage here -- are kept: written to
`ports.txt`, and merged into `subdomains.txt` as `host:port` (URLEnum's seed-building
understands a port in its input, so this makes URL enumeration target that exact port
directly, not just the default web ones). Off by default, independent of every other stage,
and combinable with any of
them.

By default, each stage's own output only goes into `oneclick.log`, keeping the terminal to
oneClick's own progress lines. Pass `-live` to also stream it to the terminal as it happens --
each stage (subdomain/URL/vhost fuzzing especially) logs a line for every discovery and every
network error as it runs, which is a lot of output on a large wordlist. Add `-quiet-stages`
alongside `-live` to suppress that raw per-item stream from the terminal while still printing
oneClick's own stage banners and the summary line after each stage finishes; the full raw
output is unaffected in `oneclick.log` either way. `-quiet-stages` has no effect without
`-live`, since nothing streams to the terminal in the first place.

Every run checkpoints its progress to `oneclick.state.json` in the output directory,
updated as soon as each phase (subdomain enumeration, vhost discovery, port scanning, URL
enumeration, secret scanning) finishes -- so if the run is interrupted (Ctrl+C, a crash, a
closed terminal), nothing already completed is lost. Resume it with
`-resume <output-dir>` (the directory printed as `output:` at the start of the run, and
again in the message a Ctrl+C prints): it restores the original target and every flag
automatically -- don't pass anything else alongside `-resume` -- skips whatever phases the
state file marks done, and picks up with whatever's left. Resuming an already-fully-completed
run is a harmless no-op that just regenerates `SUMMARY.txt`. `oneclick.log` is appended to
across resumes rather than overwritten, so the full history of a multi-attempt run stays in
one file.

## 🤝 Contributing

Contributions are welcome! If you'd like to add new enumeration modules, improve performance, or fix bugs, please open an issue or submit a pull request. Be sure to follow Go best practices (`go fmt`) and include tests where appropriate.

## Disclaimer

This project is intended for educational and authorized security testing only.
Do not use these tools against systems without proper permission.
