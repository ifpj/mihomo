package main

import (
	"flag"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/metacubex/mihomo/component/geodata/router"
	C "github.com/metacubex/mihomo/constant"

	"google.golang.org/protobuf/proto"
)

// ── ANSI color helpers ────────────────────────────────────────────────────────

var colorEnabled bool

// ansi returns an ANSI escape sequence combining the given attribute codes,
// or an empty string when color is disabled.
func ansi(codes ...string) string {
	if !colorEnabled {
		return ""
	}
	return "\033[" + strings.Join(codes, ";") + "m"
}

func r() string { return ansi("0") }

// style codes
const (
	bold = "1"
	dim  = "2"
	// foreground colors
	yellow = "33"
	cyan   = "36"
)

// ── Entry point ───────────────────────────────────────────────────────────────

func main() {
	dirFlag     := flag.String("dir", "", "data directory containing GeoSite.dat and GeoIP.dat\n\t(default: ~/.config/mihomo/)")
	noColorFlag := flag.Bool("no-color", false, "disable colored output")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: geo-lookup [flags] <domain|IP>\n\nFlags:\n")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\nExamples:")
		fmt.Fprintln(os.Stderr, "  geo-lookup google.com")
		fmt.Fprintln(os.Stderr, "  geo-lookup 8.8.8.8")
		fmt.Fprintln(os.Stderr, "  geo-lookup -dir /etc/mihomo google.com")
		fmt.Fprintln(os.Stderr, "  geo-lookup 2001:4860:4860::8888")
	}
	flag.Parse()

	if !*noColorFlag && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb" {
		if stat, err := os.Stdout.Stat(); err == nil {
			colorEnabled = (stat.Mode() & os.ModeCharDevice) != 0
		}
	}

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	if *dirFlag != "" {
		C.SetHomeDir(*dirFlag)
	}

	input := flag.Arg(0)
	host := extractHost(input) // extract bare host from any input format

	if ip, err := netip.ParseAddr(host); err == nil {
		lookupIP(ip.Unmap(), input)
	} else {
		domain := strings.ToLower(strings.TrimSuffix(host, "."))
		lookupDomain(domain, input)
	}
}

// ── Input parsing ─────────────────────────────────────────────────────────────

// extractHost accepts a URL, host:port, or bare domain/IP and returns the host only.
//
//	https://www.google.com/path  →  www.google.com
//	//www.google.com/path        →  www.google.com
//	www.google.com:443           →  www.google.com
//	[2001:db8::1]:443            →  2001:db8::1
//	8.8.8.8                      →  8.8.8.8 (unchanged)
//	google.com                   →  google.com (unchanged)
func extractHost(input string) string {
	// URL with explicit scheme
	if strings.Contains(input, "://") {
		if u, err := url.Parse(input); err == nil && u.Hostname() != "" {
			return u.Hostname()
		}
	}

	// Protocol-relative URL: //host/path
	if strings.HasPrefix(input, "//") {
		if u, err := url.Parse(input); err == nil && u.Hostname() != "" {
			return u.Hostname()
		}
	}

	// host:port or [IPv6]:port — only when ":" present to avoid splitting plain IPv6
	if strings.Contains(input, ":") {
		// If it can be parsed as a bare IPv6 address, leave it alone
		if _, err := netip.ParseAddr(input); err != nil {
			if host, _, err := net.SplitHostPort(input); err == nil {
				return host
			}
		}
	}

	// URL without scheme that has a path: example.com/path → example.com
	if idx := strings.IndexByte(input, '/'); idx != -1 {
		return input[:idx]
	}

	return input
}

// ── Domain helpers ────────────────────────────────────────────────────────────

// matchedDomainEntries returns each Domain entry whose rule matches the given domain.
func matchedDomainEntries(domain string, domains []*router.Domain) []*router.Domain {
	var entries []*router.Domain
	for _, d := range domains {
		value := strings.ToLower(d.Value)
		var hit bool
		switch d.Type {
		case router.Domain_Full:
			hit = domain == value
		case router.Domain_Domain:
			hit = domain == value || strings.HasSuffix(domain, "."+value)
		case router.Domain_Plain:
			hit = strings.Contains(domain, value)
		case router.Domain_Regex:
			if re, err := regexp.Compile(value); err == nil {
				hit = re.MatchString(domain)
			}
		}
		if hit {
			entries = append(entries, d)
		}
	}
	return entries
}

// attrKeys returns the lowercase key of each attribute.
func attrKeys(attrs []*router.Domain_Attribute) []string {
	keys := make([]string, len(attrs))
	for i, a := range attrs {
		keys[i] = strings.ToLower(a.GetKey())
	}
	return keys
}

// attrSig returns a stable map key for a set of attributes (sorted).
func attrSig(attrs []*router.Domain_Attribute) string {
	keys := attrKeys(attrs)
	sort.Strings(keys)
	return strings.Join(keys, "@")
}

// attrDisplay returns "@key1@key2" for the category code (original order).
func attrDisplay(attrs []*router.Domain_Attribute) string {
	if len(attrs) == 0 {
		return ""
	}
	return "@" + strings.Join(attrKeys(attrs), "@")
}

// coloredDomainRule formats "type:value" — attributes are shown in the category code, not here.
func coloredDomainRule(d *router.Domain) string {
	var prefix string
	switch d.Type {
	case router.Domain_Full:
		prefix = "full:"
	case router.Domain_Domain:
		prefix = "domain:"
	case router.Domain_Plain:
		prefix = "keyword:"
	case router.Domain_Regex:
		prefix = "regexp:"
	default:
		return d.Value
	}
	return ansi(dim) + prefix + r() + d.Value
}

// ── IP helpers ────────────────────────────────────────────────────────────────

// matchedCIDRs returns each CIDR in the entry that contains ip.
func matchedCIDRs(ip netip.Addr, cidrs []*router.CIDR) []string {
	var rules []string
	for _, c := range cidrs {
		addr, ok := netip.AddrFromSlice(c.Ip)
		if !ok {
			continue
		}
		prefix := netip.PrefixFrom(addr, int(c.Prefix))
		if !prefix.IsValid() {
			continue
		}
		if prefix.Contains(ip) {
			rules = append(rules, coloredCIDR(prefix))
		}
	}
	return rules
}

// coloredCIDR formats a CIDR as "addr/bits" with /bits dimmed.
func coloredCIDR(p netip.Prefix) string {
	addr := p.Addr().String()
	bits := fmt.Sprintf("%d", p.Bits())
	return addr + ansi(dim) + "/" + bits + r()
}

// ── Output helpers ────────────────────────────────────────────────────────────

// printQueryHeader prints the query line.
// When original differs from query (e.g. URL was given), it shows the source dimly.
func printQueryHeader(query, kind, original string) {
	line := fmt.Sprintf("%sQuery:%s %s%s%s %s(%s)%s",
		ansi(dim), r(),
		ansi(bold), query, r(),
		ansi(dim), kind, r(),
	)
	if original != query {
		line += fmt.Sprintf("  %s← %s%s", ansi(dim), original, r())
	}
	fmt.Println(line)
	fmt.Println()
}

// printCategoryLine prints one matched category with its rules on the same line.
//   GEOSITE,CN (5823)  →  domain:google.com  keyword:google
func printCategoryLine(ruleType, code string, total int, rules []string) {
	line := fmt.Sprintf("  %s%s,%s%s%s%s %s(%d)%s",
		ansi(dim), ruleType, r(),
		ansi(bold, cyan), code, r(),
		ansi(dim), total, r(),
	)
	if len(rules) > 0 {
		sep := fmt.Sprintf("  %s→%s  ", ansi(dim), r())
		line += sep + strings.Join(rules, ansi(dim)+"  "+r())
	}
	fmt.Println(line)
}

// printNoMatch prints the "no match" message.
func printNoMatch(what string) {
	fmt.Printf("%sNo matched %s categories.%s\n", ansi(dim), what, r())
}

// printSectionHeader prints "Matched X categories (N):".
func printSectionHeader(what string, n int) {
	fmt.Printf("Matched %s categories %s(%d)%s:\n",
		what,
		ansi(bold, yellow), n, r(),
	)
}

// ── Lookup ────────────────────────────────────────────────────────────────────

func lookupDomain(domain, original string) {
	path := C.Path.GeoSite()
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: read GeoSite.dat from %s: %v\n", path, err)
		os.Exit(1)
	}
	var list router.GeoSiteList
	if err := proto.Unmarshal(data, &list); err != nil {
		fmt.Fprintln(os.Stderr, "Error: parse GeoSite.dat:", err)
		os.Exit(1)
	}

	type result struct {
		code  string
		total int
		rules []string
	}
	var matched []result

	for _, entry := range list.Entry {
		code := strings.ToLower(entry.CountryCode)

		if len(entry.Domain) == 0 {
			continue
		}
		entries := matchedDomainEntries(domain, entry.Domain)
		if len(entries) == 0 {
			continue
		}

		// ApplyDomain fast-rejects non-matching entries; matchedDomainEntries
		// then retrieves the individual matching rules for display.
		type group struct {
			attrSuffix string
			total      int
			rules      []string
		}
		allRules := make([]string, 0, len(entries))
		groups := map[string]*group{}
		var order []string
		for _, d := range entries {
			rule := coloredDomainRule(d)
			allRules = append(allRules, rule)
			if len(d.Attribute) == 0 {
				continue
			}
			sig := attrSig(d.Attribute)
			if _, ok := groups[sig]; !ok {
				groups[sig] = &group{attrSuffix: attrDisplay(d.Attribute)}
				order = append(order, sig)
			}
			groups[sig].rules = append(groups[sig].rules, rule)
		}
		// count total rules per attr group across the whole entry
		for _, d := range entry.Domain {
			if len(d.Attribute) == 0 {
				continue
			}
			sig := attrSig(d.Attribute)
			if g, ok := groups[sig]; ok {
				g.total++
			}
		}
		matched = append(matched, result{code, len(entry.Domain), allRules})
		for _, sig := range order {
			g := groups[sig]
			matched = append(matched, result{code + g.attrSuffix, g.total, g.rules})
		}
	}

	printQueryHeader(domain, "domain", original)
	if len(matched) == 0 {
		printNoMatch("GeoSite")
		return
	}
	printSectionHeader("GeoSite", len(matched))
	for _, r := range matched {
		printCategoryLine("GEOSITE", r.code, r.total, r.rules)
	}
}

func lookupIP(ip netip.Addr, original string) {
	path := C.Path.GeoIP()
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: read GeoIP.dat from %s: %v\n", path, err)
		os.Exit(1)
	}
	var list router.GeoIPList
	if err := proto.Unmarshal(data, &list); err != nil {
		fmt.Fprintln(os.Stderr, "Error: parse GeoIP.dat:", err)
		os.Exit(1)
	}

	type result struct {
		code  string
		total int
		cidrs []string
	}
	var matched []result

	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsMulticast() || ip.IsUnspecified() {
		matched = append(matched, result{"lan", 0, nil})
	}

	for _, entry := range list.Entry {
		code := strings.ToLower(entry.CountryCode)
		cidrs := matchedCIDRs(ip, entry.Cidr)
		if len(cidrs) > 0 {
			matched = append(matched, result{code, len(entry.Cidr), cidrs})
		}
	}

	printQueryHeader(ip.String(), "IP", original)
	if len(matched) == 0 {
		printNoMatch("GeoIP")
		return
	}
	printSectionHeader("GeoIP", len(matched))
	for _, r := range matched {
		printCategoryLine("GEOIP", r.code, r.total, r.cidrs)
	}
}
