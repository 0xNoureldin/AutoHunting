#!/usr/bin/env bash
#
# oneClick - one command recon pipeline for AutoHunting
#
# Give it a domain (or a file of domains) and it chains together:
#   1) SubEnum   -> subdomain enumeration
#   2) URLEnum   -> URL enumeration on the discovered subdomains
#   3) jsAnalyzer -> secret scanning on the discovered .js files
#
# Usage:
#   ./oneclick.sh -d example.com
#   ./oneclick.sh -f domains.txt
#   ./oneclick.sh -d example.com --active -o /tmp/out
#
set -uo pipefail

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

DOMAIN=""
DOMAIN_FILE=""
OUTPUT_DIR=""
CONCURRENCY=10
TIMEOUT=60
TIMEOUT_SET=0
ACTIVE=0

BOLD="$(tput bold 2>/dev/null || true)"
DIM="$(tput dim 2>/dev/null || true)"
GREEN="$(tput setaf 2 2>/dev/null || true)"
YELLOW="$(tput setaf 3 2>/dev/null || true)"
RED="$(tput setaf 1 2>/dev/null || true)"
CYAN="$(tput setaf 6 2>/dev/null || true)"
RESET="$(tput sgr0 2>/dev/null || true)"

usage() {
    cat <<EOF
${BOLD}oneClick${RESET} - one command recon pipeline (subdomains -> URLs -> JS secrets)

Usage:
  $(basename "$0") -d <domain>       Run the pipeline against a single domain
  $(basename "$0") -f <file>         Run the pipeline against a file of domains (one per line)

Options:
  -d, --domain <domain>      Target domain, or comma separated domains
  -f, --file <path>          File with a list of domains, one per line
  -o, --output <dir>         Output directory (default: oneClick/results/<target>_<timestamp>)
  -a, --active                Enable active enumeration (slower, deeper: brute forcing, crawling,
                              headless browsing). Off by default for a fast passive-only run.
  -c, --concurrency <n>       Concurrency used across stages (default: 10)
  -t, --timeout <seconds>     Per-request timeout used across stages (default: 60, 300 with --active)
  -h, --help                  Show this help

Examples:
  $(basename "$0") -d example.com
  $(basename "$0") -f domains.txt -o results/acme
  $(basename "$0") -d example.com --active -c 20
EOF
}

log()   { echo "${DIM}[$(date +%H:%M:%S)]${RESET} $*"; }
step()  { echo; echo "${BOLD}${CYAN}==> $*${RESET}"; }
ok()    { echo "${GREEN}[ok]${RESET} $*"; }
warn()  { echo "${YELLOW}[!]${RESET} $*"; }
fail()  { echo "${RED}[x]${RESET} $*"; }

count_lines() {
    # counts non-empty lines in a file, 0 if the file doesn't exist.
    # grep -c exits 1 (with a valid "0" printed) when there are no matches,
    # so the count is captured explicitly rather than relying on its exit code.
    local file="$1" n=0
    if [ -f "$file" ]; then
        n="$(grep -c . "$file" 2>/dev/null)"
    fi
    echo "${n:-0}"
}

sanitize_hosts() {
    # keeps only lines that look like a valid hostname, dropping garbage
    # (error messages, blank lines, etc.) that a flaky/blocked source can
    # otherwise inject into results and pass on to later stages.
    # Reads from stdin so it can be used as a pipe filter.
    grep -Eo '^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$' 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        -d|--domain)
            DOMAIN="${2:-}"; shift 2 ;;
        -f|--file)
            DOMAIN_FILE="${2:-}"; shift 2 ;;
        -o|--output)
            OUTPUT_DIR="${2:-}"; shift 2 ;;
        -a|--active)
            ACTIVE=1; shift ;;
        -c|--concurrency)
            CONCURRENCY="${2:-}"; shift 2 ;;
        -t|--timeout)
            TIMEOUT="${2:-}"; TIMEOUT_SET=1; shift 2 ;;
        -h|--help)
            usage; exit 0 ;;
        *)
            fail "Unknown option: $1"; usage; exit 1 ;;
    esac
done

if [ -z "$DOMAIN" ] && [ -z "$DOMAIN_FILE" ]; then
    fail "You must provide either -d <domain> or -f <file>"
    usage
    exit 1
fi

if [ -n "$DOMAIN" ] && [ -n "$DOMAIN_FILE" ]; then
    fail "Use either -d or -f, not both"
    exit 1
fi

if [ -n "$DOMAIN_FILE" ] && [ ! -s "$DOMAIN_FILE" ]; then
    fail "Domain file not found or empty: $DOMAIN_FILE"
    exit 1
fi

if ! command -v go >/dev/null 2>&1; then
    fail "Go is required but was not found in PATH"
    exit 1
fi

if [ "$ACTIVE" -eq 1 ] && [ "$TIMEOUT_SET" -eq 0 ]; then
    TIMEOUT=300
fi

# ---------------------------------------------------------------------------
# Output directory + input normalization
# ---------------------------------------------------------------------------
if [ -n "$DOMAIN" ]; then
    TARGET_NAME="$(echo "$DOMAIN" | tr -c 'A-Za-z0-9._-' '_' | cut -c1-60)"
else
    TARGET_NAME="$(basename "$DOMAIN_FILE" | tr -c 'A-Za-z0-9._-' '_' | cut -c1-60)"
fi

if [ -z "$OUTPUT_DIR" ]; then
    OUTPUT_DIR="$REPO_ROOT/oneClick/results/${TARGET_NAME}_$(date +%Y%m%d_%H%M%S)"
fi
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

LOG_FILE="$OUTPUT_DIR/oneclick.log"
: > "$LOG_FILE"

INPUT_DOMAINS="$OUTPUT_DIR/input_domains.txt"
if [ -n "$DOMAIN" ]; then
    echo "$DOMAIN" | tr ',' '\n' | sed '/^[[:space:]]*$/d' > "$INPUT_DOMAINS"
else
    sed '/^[[:space:]]*$/d' "$DOMAIN_FILE" > "$INPUT_DOMAINS"
fi

if [ ! -s "$INPUT_DOMAINS" ]; then
    fail "No valid domains found in input"
    exit 1
fi

TARGET_COUNT="$(count_lines "$INPUT_DOMAINS")"

echo "${BOLD}oneClick recon pipeline${RESET}"
echo "  targets:     ${TARGET_COUNT} domain(s)"
echo "  mode:        $([ "$ACTIVE" -eq 1 ] && echo 'active (deep, slower)' || echo 'passive (fast)')"
echo "  concurrency: $CONCURRENCY"
echo "  timeout:     ${TIMEOUT}s"
echo "  output:      $OUTPUT_DIR"

ACTIVE_FLAG=()
[ "$ACTIVE" -eq 1 ] && ACTIVE_FLAG=(-active)

SUBS_FILE="$OUTPUT_DIR/subdomains.txt"
URLS_FILE="$OUTPUT_DIR/urls.txt"
JS_FILE="$OUTPUT_DIR/js_urls.txt"
SECRETS_FILE="$OUTPUT_DIR/secrets.json"

# ---------------------------------------------------------------------------
# Stage 1: Subdomain enumeration (SubEnum)
# ---------------------------------------------------------------------------
step "Stage 1/3: Subdomain enumeration"
(
    cd "$REPO_ROOT/SubEnum/cmd/subenum" && \
    go run . -i "$INPUT_DOMAINS" -o "$SUBS_FILE" -c "$CONCURRENCY" -timeout "$TIMEOUT" "${ACTIVE_FLAG[@]}"
) >>"$LOG_FILE" 2>&1
SUBENUM_RC=$?

# Always seed the discovered subdomains with the original target(s) so later
# stages still have something to work with even if enumeration finds nothing,
# and drop any garbage lines a flaky source may have injected.
touch "$SUBS_FILE"
cat "$INPUT_DOMAINS" "$SUBS_FILE" | sanitize_hosts | sort -u > "$SUBS_FILE.tmp" && mv "$SUBS_FILE.tmp" "$SUBS_FILE"

SUBS_COUNT="$(count_lines "$SUBS_FILE")"
if [ "$SUBENUM_RC" -ne 0 ]; then
    warn "SubEnum exited with an error (see $LOG_FILE), continuing with $SUBS_COUNT known host(s)"
else
    ok "Found $SUBS_COUNT unique subdomain(s) -> $SUBS_FILE"
fi

# ---------------------------------------------------------------------------
# Stage 2: URL enumeration (URLEnum)
# ---------------------------------------------------------------------------
step "Stage 2/3: URL enumeration"
(
    cd "$REPO_ROOT/URLEnum/cmd/URLEnum" && \
    go run . -i "$SUBS_FILE" -subs -o "$URLS_FILE" \
        -pc "$CONCURRENCY" -ac "$((CONCURRENCY * 2))" -timeout "$TIMEOUT" "${ACTIVE_FLAG[@]}"
) >>"$LOG_FILE" 2>&1
URLENUM_RC=$?

touch "$URLS_FILE"
URLS_COUNT="$(count_lines "$URLS_FILE")"
if [ "$URLENUM_RC" -ne 0 ]; then
    warn "URLEnum exited with an error (see $LOG_FILE), continuing with $URLS_COUNT known URL(s)"
else
    ok "Found $URLS_COUNT unique URL(s) -> $URLS_FILE"
fi

# ---------------------------------------------------------------------------
# Stage 3: JS secret scanning (jsAnalyzer)
# ---------------------------------------------------------------------------
step "Stage 3/3: JS secret scanning"
grep -Ei '\.js([?#].*)?$' "$URLS_FILE" 2>/dev/null \
    | grep -Eiv '\.map([?#]|$)|\.json\.js' \
    | sort -u > "$JS_FILE" || true

JS_COUNT="$(count_lines "$JS_FILE")"
if [ "$JS_COUNT" -eq 0 ]; then
    warn "No JS files found in URLEnum output, skipping secret scan"
    echo "[]" > "$SECRETS_FILE"
    JSANALYZER_RC=0
else
    log "Scanning $JS_COUNT JS file(s) for secrets"
    (
        cd "$REPO_ROOT/jsAnalyzer/cmd" && \
        go run . -i "$JS_FILE" -o "$SECRETS_FILE" -only secrets -c "$CONCURRENCY" -timeout "$TIMEOUT"
    ) >>"$LOG_FILE" 2>&1
    JSANALYZER_RC=$?
    if [ "$JSANALYZER_RC" -ne 0 ]; then
        warn "jsAnalyzer exited with an error (see $LOG_FILE)"
    else
        ok "Secret scan results -> $SECRETS_FILE"
    fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
SUMMARY_FILE="$OUTPUT_DIR/SUMMARY.txt"
{
    echo "oneClick recon summary"
    echo "target(s):        $(tr '\n' ',' < "$INPUT_DOMAINS" | sed 's/,$//')"
    echo "mode:              $([ "$ACTIVE" -eq 1 ] && echo active || echo passive)"
    echo "generated:         $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "subdomains found:  $SUBS_COUNT   ($SUBS_FILE)"
    echo "urls found:        $URLS_COUNT   ($URLS_FILE)"
    echo "js files found:    $JS_COUNT   ($JS_FILE)"
    echo "secrets output:    $SECRETS_FILE"
    echo "full log:          $LOG_FILE"
} | tee "$SUMMARY_FILE"

step "Done"
echo "Results saved in: ${BOLD}$OUTPUT_DIR${RESET}"

if [ "$SUBENUM_RC" -ne 0 ] || [ "$URLENUM_RC" -ne 0 ] || [ "${JSANALYZER_RC:-0}" -ne 0 ]; then
    warn "One or more stages reported errors, check $LOG_FILE for details"
    exit 2
fi

exit 0
