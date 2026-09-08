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
Useful for network-level recon.

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
Discovers virtual hosts associated with a target:
- Hidden domains
- Internal services

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
discovered hosts, then secret scanning on the discovered `.js` files. See
[Module Usage Details](#-module-usage-details) below for usage.

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
Determines which subdomains resolve to which IP addresses:
```bash
go run . -hosts subs.txt -output vhostedSubs
```

### portScanner
Performs TCP port scanning:
```bash
go run . -host-file subs.txt -host-threads 52 -threads 86 -output-file ports.txt -timeout 3
```

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
go run . -d example.com -live              # stream each stage's live output to the terminal
go run . -d example.com -o results/acme -c 20 -t 120
go run . -h                                # full option list
```
Results (subdomains, URLs, the filtered list of JS files, `secrets.json`, a `SUMMARY.txt`,
and a combined log) are written to `oneClick/results/<target>_<timestamp>/` unless `-o` is
given. Active mode is off by default since it can take from several minutes up to an hour
(see the URLEnum notes above); pass `-active` when you want deeper coverage.

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

By default, each stage's own output only goes into `oneclick.log`, keeping the terminal to
oneClick's own progress lines. Pass `-live` to also stream it to the terminal as it happens.

## 🤝 Contributing

Contributions are welcome! If you'd like to add new enumeration modules, improve performance, or fix bugs, please open an issue or submit a pull request. Be sure to follow Go best practices (`go fmt`) and include tests where appropriate.

## Disclaimer

This project is intended for educational and authorized security testing only.
Do not use these tools against systems without proper permission.
