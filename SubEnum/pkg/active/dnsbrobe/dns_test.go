package dnsprobe

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"subenum/pkg/client"
)

// startFakeDNSServer runs a minimal authoritative-style DNS server on an
// OS-assigned local UDP port and returns its address ("host:port"), ready
// to drop into a "udp:<addr>" resolver string. The server is shut down
// automatically at the end of the test.
func startFakeDNSServer(t *testing.T, handler func(w dns.ResponseWriter, r *dns.Msg)) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind a fake DNS server: %v", err)
	}
	server := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(handler)}
	go func() {
		_ = server.ActivateAndServe()
	}()
	t.Cleanup(func() {
		_ = server.Shutdown()
	})
	return pc.LocalAddr().String()
}

// matchesWildcard reports whether name (a fully-qualified query name) is
// matched by a "*.zone" wildcard record, per RFC 4592: exactly one extra
// label in front of zone, no more and no less.
func matchesWildcard(name, zone string) bool {
	suffix := "." + zone
	if !strings.HasSuffix(name, suffix) {
		return false
	}
	prefix := strings.TrimSuffix(name, suffix)
	return prefix != "" && !strings.Contains(prefix, ".")
}

// TestProbeSubdomainsFiltersWildcardDNS is a regression test for the root
// cause behind subdomain enumeration reporting thousands of "alive"
// subdomains for a single brute-force wordlist run (which then floods
// every downstream stage, including the 403 check, with noise): the
// wildcard-DNS probe in detectWildcard built its "guaranteed absent"
// candidate as "<token>.<domain>.<tld>" using time.Now().String() as the
// token -- a string containing spaces, colons, and its own "."
// characters, which DNS packs as several *extra* labels rather than one.
// A wildcard record ("*.domain.tld") only matches a query name with
// exactly one extra label in front of it, so that malformed probe could
// never match a real wildcard regardless of whether the target's zone
// actually had one -- wildcard detection always reported "no wildcard",
// so every brute-force candidate that happened to resolve (which, behind
// a wildcarded zone, is *all* of them) was reported "alive" verbatim.
//
// This test stands up a local DNS server that answers with a fixed
// "wildcard" IP for every name except one specific real one -- exactly
// what a wildcarded zone looks like -- and verifies ProbeSubdomains
// (through runDnsProbe and detectWildcard) reports only the genuinely
// distinct name as alive, filtering out every candidate that merely
// matches the wildcard's answer.
func TestProbeSubdomainsFiltersWildcardDNS(t *testing.T) {
	const realName = "specific-real.test.local."
	realIP := net.ParseIP("1.2.3.4")
	wildcardIP := net.ParseIP("5.6.7.8")

	addr := startFakeDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) != 1 || r.Question[0].Qtype != dns.TypeA {
			_ = w.WriteMsg(m)
			return
		}
		q := r.Question[0]
		switch {
		case strings.EqualFold(q.Name, realName):
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   realIP,
			})
		case matchesWildcard(q.Name, "test.local."):
			// Real authoritative DNS wildcard matching (RFC 4592): a
			// "*.test.local." record matches a query name with exactly
			// one extra label in front of "test.local.", not two or
			// more. A probe token containing its own "." (like the old,
			// buggy time.Now().String() token) turns into several extra
			// labels and would fall through to the NXDOMAIN case below,
			// exactly as it would against a real wildcarded zone.
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   wildcardIP,
			})
		default:
			m.Rcode = dns.RcodeNameError // NXDOMAIN
		}
		_ = w.WriteMsg(m)
	})

	origResolvers := client.DefaultResolvers
	client.DefaultResolvers = []string{"udp:" + addr}
	defer func() { client.DefaultResolvers = origResolvers }()

	hosts := []string{
		"specific-real.test.local",
		"fake1.test.local",
		"fake2.test.local",
		"fake3.test.local",
		"fake4.test.local",
	}
	alive := ProbeSubdomains(hosts, 5, 5)

	if len(alive) != 1 || alive[0] != "specific-real.test.local" {
		t.Fatalf("expected only specific-real.test.local to be reported alive (wildcard DNS should filter the rest), got %v", alive)
	}
}

// TestDetectWildcardUsesASingleValidLabel is a narrower regression test
// directly on the probe label detectWildcard builds: it must be exactly
// one syntactically valid DNS label (no embedded "." splitting it into
// several), or it can never correctly test for a wildcard one level below
// the target domain regardless of what the fake DNS server answers.
func TestDetectWildcardUsesASingleValidLabel(t *testing.T) {
	var gotName string
	addr := startFakeDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) == 1 {
			gotName = r.Question[0].Name
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("5.6.7.8"),
			})
		}
		_ = w.WriteMsg(m)
	})

	origResolvers := client.DefaultResolvers
	client.DefaultResolvers = []string{"udp:" + addr}
	defer func() { client.DefaultResolvers = origResolvers }()

	_, ok := detectWildcard("fake1.test.local")
	if !ok {
		t.Fatalf("expected detectWildcard to succeed against a server that answers every query, got ok=false (queried name: %q)", gotName)
	}

	// Exactly one extra label ("<token>.") in front of "test.local." --
	// i.e. exactly 3 labels total (token, test, local) plus the root.
	labels := dns.SplitDomainName(gotName)
	if len(labels) != 3 {
		t.Fatalf("detectWildcard queried %q, which splits into %d labels %v -- want exactly 3 (a single random label plus test.local), matching what a real *.test.local wildcard record would require", gotName, len(labels), labels)
	}
}
