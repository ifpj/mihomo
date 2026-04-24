package main

import (
	"flag"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
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
	green  = "32"
)

// ── Entry point ───────────────────────────────────────────────────────────────

func main() {
	dirFlag     := flag.String("dir", "", "data directory containing GeoSite.dat and GeoIP.dat\n\t(default: ~/.config/mihomo/)")
	noColorFlag := flag.Bool("no-color", false, "disable colored output")
	listFlag    := flag.String("list", "", "list all rules in a category (e.g. GEOSITE,CN or GEOIP,CN)")
	typeFlag    := flag.String("type", "", "filter by rule type: full, domain, keyword, regexp (only with --list GEOSITE,*)")
	filterFlag  := flag.String("filter", "", "filter rules containing this substring (only with --list)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: geo-lookup [flags] <domain|IP>\n       geo-lookup --list <GEOSITE,code|GEOIP,code> [--type TYPE] [--filter STR]\n\nFlags:\n")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\nExamples:")
		fmt.Fprintln(os.Stderr, "  geo-lookup google.com")
		fmt.Fprintln(os.Stderr, "  geo-lookup 8.8.8.8")
		fmt.Fprintln(os.Stderr, "  geo-lookup --list GEOSITE,CN")
		fmt.Fprintln(os.Stderr, "  geo-lookup --list GEOSITE,CN@ads --type domain --filter google")
		fmt.Fprintln(os.Stderr, "  geo-lookup --list GEOIP,CN --filter 1.0")
	}
	flag.Parse()

	isTTY := false
	if !*noColorFlag && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb" {
		if stat, err := os.Stdout.Stat(); err == nil {
			isTTY = (stat.Mode() & os.ModeCharDevice) != 0
			colorEnabled = isTTY
		}
	}

	if *dirFlag != "" {
		C.SetHomeDir(*dirFlag)
	}

	if *listFlag != "" {
		listCategory(*listFlag, *typeFlag, *filterFlag, isTTY)
		return
	}

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	input := flag.Arg(0)
	host := extractHost(input)

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
	if strings.Contains(input, "://") {
		if u, err := url.Parse(input); err == nil && u.Hostname() != "" {
			return u.Hostname()
		}
	}
	if strings.HasPrefix(input, "//") {
		if u, err := url.Parse(input); err == nil && u.Hostname() != "" {
			return u.Hostname()
		}
	}
	if strings.Contains(input, ":") {
		if _, err := netip.ParseAddr(input); err != nil {
			if host, _, err := net.SplitHostPort(input); err == nil {
				return host
			}
		}
	}
	if idx := strings.IndexByte(input, '/'); idx != -1 {
		return input[:idx]
	}
	return input
}

// ── Domain helpers ────────────────────────────────────────────────────────────

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

func attrKeys(attrs []*router.Domain_Attribute) []string {
	keys := make([]string, len(attrs))
	for i, a := range attrs {
		keys[i] = strings.ToLower(a.GetKey())
	}
	return keys
}

func attrSig(attrs []*router.Domain_Attribute) string {
	keys := attrKeys(attrs)
	sort.Strings(keys)
	return strings.Join(keys, "@")
}

func attrDisplay(attrs []*router.Domain_Attribute) string {
	if len(attrs) == 0 {
		return ""
	}
	return "@" + strings.Join(attrKeys(attrs), "@")
}

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

// domainTypeName returns the canonical type name for filtering.
func domainTypeName(t router.Domain_Type) string {
	switch t {
	case router.Domain_Full:
		return "full"
	case router.Domain_Domain:
		return "domain"
	case router.Domain_Plain:
		return "keyword"
	case router.Domain_Regex:
		return "regexp"
	}
	return ""
}

// ── IP helpers ────────────────────────────────────────────────────────────────

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

func coloredCIDR(p netip.Prefix) string {
	addr := p.Addr().String()
	bits := fmt.Sprintf("%d", p.Bits())
	return addr + ansi(dim) + "/" + bits + r()
}

// ── Output helpers ────────────────────────────────────────────────────────────

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
//
//	GEOSITE,CN (5823)  →  domain:google.com  keyword:google
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

func printNoMatch(what string) {
	fmt.Printf("%sNo matched %s categories.%s\n", ansi(dim), what, r())
}

func printSectionHeader(what string, n int) {
	fmt.Printf("Matched %s categories %s(%d)%s:\n",
		what,
		ansi(bold, yellow), n, r(),
	)
}

// ── Pager ─────────────────────────────────────────────────────────────────────

// withPager runs fn, piping its stdout through less when isTTY is true.
func withPager(isTTY bool, fn func()) {
	if !isTTY {
		fn()
		return
	}
	less, err := exec.LookPath("less")
	if err != nil {
		fn()
		return
	}
	cmd := exec.Command(less, "-R", "-F", "-X")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	pr, pw, err := os.Pipe()
	if err != nil {
		fn()
		return
	}
	cmd.Stdin = pr

	origStdout := os.Stdout
	os.Stdout = pw

	if err := cmd.Start(); err != nil {
		os.Stdout = origStdout
		pw.Close()
		pr.Close()
		fn()
		return
	}

	fn()

	pw.Close()
	os.Stdout = origStdout
	pr.Close()
	cmd.Wait()
}

// ── List category ─────────────────────────────────────────────────────────────

// listCategory prints all rules in the given category spec (e.g. "GEOSITE,CN" or "GEOIP,CN").
// typeFilter: "full"/"domain"/"keyword"/"regexp" (empty = all; only for GEOSITE)
// filterStr:  substring filter on rule value (empty = all)
func listCategory(spec, typeFilter, filterStr string, isTTY bool) {
	upper := strings.ToUpper(spec)
	if strings.HasPrefix(upper, "GEOSITE,") {
		code := spec[len("GEOSITE,"):]
		withPager(isTTY, func() { listGeoSite(code, typeFilter, filterStr) })
	} else if strings.HasPrefix(upper, "GEOIP,") {
		code := spec[len("GEOIP,"):]
		withPager(isTTY, func() { listGeoIP(code, filterStr) })
	} else {
		fmt.Fprintf(os.Stderr, "Error: --list must start with GEOSITE, or GEOIP, (got %q)\n", spec)
		os.Exit(1)
	}
}

func listGeoSite(codeSpec, typeFilter, filterStr string) {
	// codeSpec may include attr suffix: "cn@ads"
	attrFilter := ""
	baseCode := strings.ToUpper(codeSpec)
	if idx := strings.Index(baseCode, "@"); idx != -1 {
		attrFilter = strings.ToLower(baseCode[idx+1:])
		baseCode = baseCode[:idx]
	}

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

	var entry *router.GeoSite
	for _, e := range list.Entry {
		if strings.EqualFold(e.CountryCode, baseCode) {
			entry = e
			break
		}
	}
	if entry == nil {
		fmt.Fprintf(os.Stderr, "Error: category %q not found in GeoSite.dat\n", baseCode)
		os.Exit(1)
	}

	// collect domains, applying attr/type/filter
	var domains []*router.Domain
	for _, d := range entry.Domain {
		if attrFilter != "" {
			keys := attrKeys(d.Attribute)
			found := false
			for _, k := range keys {
				if k == attrFilter {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		if typeFilter != "" && domainTypeName(d.Type) != typeFilter {
			continue
		}
		if filterStr != "" && !strings.Contains(strings.ToLower(d.Value), strings.ToLower(filterStr)) {
			continue
		}
		domains = append(domains, d)
	}

	// count by type (before filter, but after attr filter)
	var totalFull, totalDomain, totalKeyword, totalRegexp int
	for _, d := range entry.Domain {
		if attrFilter != "" {
			keys := attrKeys(d.Attribute)
			found := false
			for _, k := range keys {
				if k == attrFilter {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		switch d.Type {
		case router.Domain_Full:
			totalFull++
		case router.Domain_Domain:
			totalDomain++
		case router.Domain_Plain:
			totalKeyword++
		case router.Domain_Regex:
			totalRegexp++
		}
	}
	totalAll := totalFull + totalDomain + totalKeyword + totalRegexp

	displayCode := strings.ToLower(baseCode)
	if attrFilter != "" {
		displayCode += "@" + attrFilter
	}

	// header
	fmt.Printf("%sCategory:%s %sGEOSITE,%s%s %s(%d)%s\n",
		ansi(dim), r(),
		ansi(bold, cyan), displayCode, r(),
		ansi(dim), totalAll, r(),
	)
	fmt.Printf("  %sfull:%s %s%d%s   %sdomain:%s %s%d%s   %skeyword:%s %s%d%s   %sregexp:%s %s%d%s\n\n",
		ansi(dim), r(), ansi(bold, green), totalFull, r(),
		ansi(dim), r(), ansi(bold, green), totalDomain, r(),
		ansi(dim), r(), ansi(bold, green), totalKeyword, r(),
		ansi(dim), r(), ansi(bold, green), totalRegexp, r(),
	)

	if len(domains) == 0 {
		fmt.Printf("%sNo rules match the given filters.%s\n", ansi(dim), r())
		return
	}

	if typeFilter != "" || filterStr != "" {
		fmt.Printf("%sShowing %d / %d rules%s\n\n", ansi(dim), len(domains), totalAll, r())
	}

	for _, d := range domains {
		fmt.Println("  " + coloredDomainRule(d))
	}
}

func listGeoIP(code, filterStr string) {
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

	var entry *router.GeoIP
	for _, e := range list.Entry {
		if strings.EqualFold(e.CountryCode, code) {
			entry = e
			break
		}
	}
	if entry == nil {
		fmt.Fprintf(os.Stderr, "Error: category %q not found in GeoIP.dat\n", code)
		os.Exit(1)
	}

	// build all prefixes
	type prefixEntry struct {
		p   netip.Prefix
		str string
	}
	var all []prefixEntry
	for _, c := range entry.Cidr {
		addr, ok := netip.AddrFromSlice(c.Ip)
		if !ok {
			continue
		}
		p := netip.PrefixFrom(addr, int(c.Prefix))
		if !p.IsValid() {
			continue
		}
		s := p.String()
		if filterStr != "" && !strings.Contains(s, filterStr) {
			continue
		}
		all = append(all, prefixEntry{p, s})
	}

	displayCode := strings.ToLower(code)
	fmt.Printf("%sCategory:%s %sGEOIP,%s%s %s(%d)%s\n\n",
		ansi(dim), r(),
		ansi(bold, cyan), displayCode, r(),
		ansi(dim), len(entry.Cidr), r(),
	)

	if filterStr != "" {
		fmt.Printf("%sShowing %d / %d rules%s\n\n", ansi(dim), len(all), len(entry.Cidr), r())
	}

	if len(all) == 0 {
		fmt.Printf("%sNo rules match the given filters.%s\n", ansi(dim), r())
		return
	}

	for _, e := range all {
		fmt.Println("  " + coloredCIDR(e.p))
	}
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
