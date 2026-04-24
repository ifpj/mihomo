//go:build js && wasm

package main

import (
	"encoding/json"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"syscall/js"

	"github.com/metacubex/mihomo/component/geodata/router"
	"google.golang.org/protobuf/proto"
)

// ── Cached parsed data ────────────────────────────────────────────────────────

var (
	siteList *router.GeoSiteList
	ipList   *router.GeoIPList
)

// ── Result type ───────────────────────────────────────────────────────────────

type result struct {
	Code  string   `json:"code"`
	Rules []string `json:"rules"`
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

func domainRuleStr(d *router.Domain) string {
	switch d.Type {
	case router.Domain_Full:
		return "full:" + d.Value
	case router.Domain_Domain:
		return "domain:" + d.Value
	case router.Domain_Plain:
		return "keyword:" + d.Value
	case router.Domain_Regex:
		return "regexp:" + d.Value
	default:
		return d.Value
	}
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
			rules = append(rules, prefix.String())
		}
	}
	return rules
}

// ── Lookup logic ──────────────────────────────────────────────────────────────

func lookupDomain(domain string) []result {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	var matched []result
	for _, entry := range siteList.Entry {
		if len(entry.Domain) == 0 {
			continue
		}
		entries := matchedDomainEntries(domain, entry.Domain)
		if len(entries) == 0 {
			continue
		}
		code := strings.ToUpper(entry.CountryCode)
		type group struct {
			attrSuffix string
			rules      []string
		}
		allRules := make([]string, 0, len(entries))
		groups := map[string]*group{}
		var order []string
		for _, d := range entries {
			rule := domainRuleStr(d)
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
		matched = append(matched, result{code, allRules})
		for _, sig := range order {
			g := groups[sig]
			matched = append(matched, result{code + strings.ToUpper(g.attrSuffix), g.rules})
		}
	}
	return matched
}

func lookupIP(ipStr string) ([]result, error) {
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return nil, err
	}
	ip = ip.Unmap()

	var matched []result
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsMulticast() || ip.IsUnspecified() {
		matched = append(matched, result{"LAN", nil})
	}
	for _, entry := range ipList.Entry {
		cidrs := matchedCIDRs(ip, entry.Cidr)
		if len(cidrs) > 0 {
			matched = append(matched, result{strings.ToUpper(entry.CountryCode), cidrs})
		}
	}
	return matched, nil
}

// ── JS exports ────────────────────────────────────────────────────────────────

// geoInit(siteUint8Array, ipUint8Array) → "ok" | error string
func jsInit(_ js.Value, args []js.Value) any {
	if len(args) < 2 {
		return "error: need 2 args (siteData, ipData)"
	}

	siteBuf := make([]byte, args[0].Length())
	js.CopyBytesToGo(siteBuf, args[0])
	var sl router.GeoSiteList
	if err := proto.Unmarshal(siteBuf, &sl); err != nil {
		return "error: parse GeoSite.dat: " + err.Error()
	}
	siteList = &sl

	ipBuf := make([]byte, args[1].Length())
	js.CopyBytesToGo(ipBuf, args[1])
	var il router.GeoIPList
	if err := proto.Unmarshal(ipBuf, &il); err != nil {
		return "error: parse GeoIP.dat: " + err.Error()
	}
	ipList = &il

	return "ok"
}

// geoLookup(query) → JSON string  {type, query, results:[{code,rules}]}
func jsLookup(_ js.Value, args []js.Value) any {
	if len(args) < 1 {
		return `{"error":"need query arg"}`
	}
	if siteList == nil || ipList == nil {
		return `{"error":"data not initialized"}`
	}

	query := strings.TrimSpace(args[0].String())
	if query == "" {
		return `{"error":"empty query"}`
	}

	type response struct {
		Type    string   `json:"type"`
		Query   string   `json:"query"`
		Results []result `json:"results"`
	}

	var resp response
	if ip, err := netip.ParseAddr(query); err == nil {
		results, _ := lookupIP(ip.String())
		resp = response{"ip", ip.Unmap().String(), results}
	} else {
		domain := strings.ToLower(strings.TrimSuffix(query, "."))
		resp = response{"domain", domain, lookupDomain(domain)}
	}

	data, _ := json.Marshal(resp)
	return string(data)
}

func main() {
	js.Global().Set("geoInit", js.FuncOf(jsInit))
	js.Global().Set("geoLookup", js.FuncOf(jsLookup))
	<-make(chan struct{})
}
