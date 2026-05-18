package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/common/convert"
	mihomoyaml "github.com/metacubex/mihomo/common/yaml"
	C "github.com/metacubex/mihomo/constant"
	"gopkg.in/yaml.v3"
)

func init() {
	flag.Usage = func() {
		writeHelp(os.Stderr)
	}
}

// Fields not listed here are appended at the end in their natural order.
var preferredKeyOrder = []string{
	"name",
	"type",
	"server",
	"port",
	"password",
	"uuid",
	"cipher",
	"username",
	"tls",
	"skip-cert-verify",
	"sni",
	"servername",
	"client-fingerprint",
	"flow",
	"network",
	"udp",
	"xudp",
	"smux",
	"obfs",
	"obfs-password",
	"obfs-param",
	"alpn",
	"reality-opts",
	"grpc-opts",
	"ws-opts",
	"h2-opts",
	"http-opts",
	"fingerprint",
	"down",
	"up",
}

func sortKeys(keys []string) {
	order := make(map[string]int)
	for i, k := range preferredKeyOrder {
		order[k] = i
	}

	// Assign high number to unknown keys so they go at the end
	unknownOrder := len(preferredKeyOrder)
	sort.Slice(keys, func(i, j int) bool {
		oi, ok1 := order[keys[i]]
		oj, ok2 := order[keys[j]]
		if !ok1 {
			oi = unknownOrder
		}
		if !ok2 {
			oj = unknownOrder
		}
		if oi != oj {
			return oi < oj
		}
		return keys[i] < keys[j]
	})
}

const (
	defaultTestURL = "https://www.gstatic.com/generate_204"
	ipinfoURL      = "https://ipinfo.io/json"
	ipsbURL        = "https://api-ipv4.ip.sb/geoip"
	ipwhoURL       = "https://ipwho.is/"
	scoreURL       = "https://my.ippure.com/v1/info"
	testTimeout    = 5 * time.Second
	ipinfoTimeout  = 10 * time.Second
	ipsbTimeout    = 10 * time.Second
	ipwhoTimeout   = 10 * time.Second
	scoreTimeout   = 10 * time.Second
	cacheTTL       = 24 * time.Hour
)

// ProxySchema mirrors the internal schema for parsing
type ProxySchema struct {
	Proxies []map[string]any `yaml:"proxies"`
}

// ProxyWithSource wraps a proxy config with its source URL
type ProxyWithSource struct {
	Config    map[string]any
	SourceURL string
}

// NodeInfo stores the result of a checked node
type NodeInfo struct {
	OriginalName string
	NewName      string
	CountryCode  string
	Country      string
	ISP          string
	IP           string
	Delay        uint16
	FraudScore   int  // 评分模式的欺诈分数
	Config       map[string]any
	APIUsed      string // 记录使用的 API
	SourceURL    string // 记录节点来源的订阅 URL
	// configHash caches the hash of config (excluding name) for deduplication
	configHash string
}

// ScoreResponse is the response from my.ippure.com/v1/info
type ScoreResponse struct {
	IP             string `json:"ip"`
	ASN            int    `json:"asn"`
	ASOrganization string `json:"asOrganization"`
	Country        string `json:"country"`
	CountryCode    string `json:"countryCode"`
	Region         string `json:"region"`
	RegionCode     string `json:"regionCode"`
	City           string `json:"city"`
	Timezone       string `json:"timezone"`
	Longitude      string `json:"longitude"`
	Latitude       string `json:"latitude"`
	PostalCode     string `json:"postalCode"`
	FraudScore     int    `json:"fraudScore"`
	IsResidential  bool   `json:"isResidential"`
	IsBroadcast    bool   `json:"isBroadcast"`
	UserAgent      string `json:"userAgent"`
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if shouldShowInteractiveHelp(os.Args[1:]) {
		showInteractiveHelp()
		return
	}

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		fmt.Println("\nInterrupted, shutting down...")
		cancel()
	}()

	// Read input files from remaining args (after flags)
	outputFile := flag.String("o", "", "output YAML file (default: <first-input>-checked.yaml)")
	parallelFetch := flag.Int("parallel", 100, "number of parallel fetch workers (default: 100)")
	filterType := flag.String("type", "", "filter proxies by type, comma-separated (e.g., ss,vmess,trojan)")
	excludeType := flag.String("exclude-type", "", "exclude proxies by type, comma-separated (e.g., ss,vmess)")
	mergeMode := flag.Bool("merge", false, "merge checked YAML files without re-testing")
	viewMode := flag.Bool("view", false, "show type and country statistics for input files")
	filterCountry := flag.String("country", "", "filter proxies by country code")
	excludeCountry := flag.String("exclude-country", "", "exclude proxies by country code")
	mergeHysteriaPorts := flag.Bool("merge-ports", false, "merge Hysteria/Hysteria2 nodes with same config but different ports")
	trackSource := flag.Bool("track-source", false, "add source-url field to track subscription origin")
	scoreMode := flag.Bool("score", false, "score mode: query fraud score for each proxy")
	pruneMode := flag.Bool("prune", false, "prune mode: remove dead nodes from checked/scored YAML")
	normalizedArgs, err := normalizeArgs(os.Args[1:])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(2)
	}
	if err := flag.CommandLine.Parse(normalizedArgs); err != nil {
		os.Exit(2)
	}

	// Get input files from flag or remaining args
	var inputFiles []string
	if flag.NArg() > 0 {
		// Use remaining positional args as input files
		inputFiles = flag.Args()
	} else {
		// Default to node.txt if no files provided
		inputFiles = []string{"node.txt"}
	}

	// Derive output filename from first input if not specified
	out := *outputFile
	if out == "" {
		suffix := "-checked.yaml"
		if *mergeMode {
			suffix = "-merged.yaml"
		} else if *pruneMode {
			suffix = "-pruned.yaml"
		}
		out = strings.TrimSuffix(inputFiles[0], filepath.Ext(inputFiles[0])) + suffix
	}

	countries := parseCountryList(*filterCountry)
	excludeCountries := parseCountryList(*excludeCountry)
	if len(countries) > 0 && len(excludeCountries) > 0 {
		fmt.Println("Error: cannot use -country and -exclude-country together")
		os.Exit(1)
	}

	filterTypes := parseTypeList(*filterType)
	excludeTypes := parseTypeList(*excludeType)
	if len(filterTypes) > 0 && len(excludeTypes) > 0 {
		fmt.Println("Error: cannot use -type and -exclude-type together")
		os.Exit(1)
	}

	if *viewMode {
		if *mergeMode {
			fmt.Println("Error: cannot use -view and -merge together")
			os.Exit(1)
		}
		if *pruneMode {
			fmt.Println("Error: cannot use -view and -prune together")
			os.Exit(1)
		}
		if *parallelFetch != 100 {
			fmt.Println("Error: cannot use -parallel with -view")
			os.Exit(1)
		}
		if out != strings.TrimSuffix(inputFiles[0], filepath.Ext(inputFiles[0]))+"-checked.yaml" && *outputFile != "" {
			fmt.Println("Error: cannot use -o with -view")
			os.Exit(1)
		}
		if err := viewInputFiles(inputFiles, filterTypes, excludeTypes, countries, excludeCountries); err != nil {
			fmt.Printf("Failed to view input files: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *mergeMode {
		if err := mergeCheckedFiles(inputFiles, out, filterTypes, excludeTypes, countries, excludeCountries, *mergeHysteriaPorts); err != nil {
			fmt.Printf("Failed to merge checked files: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *pruneMode {
		if err := pruneDeadNodes(ctx, inputFiles, out, *parallelFetch); err != nil {
			fmt.Printf("Failed to prune dead nodes: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Phase 1: Collect all subscription URLs and local files
	fmt.Println("=== Phase 1: Collecting input sources ===")
	var allProviderURLs []string
	var localFiles []string

	for _, nodeFile := range inputFiles {
		inputData, err := os.ReadFile(nodeFile)
		if err != nil {
			fmt.Printf("Failed to read %s: %v\n", nodeFile, err)
			continue
		}

		if isLocalMode(inputData) {
			// Local proxy config file
			fmt.Printf("Local config file: %s\n", nodeFile)
			localFiles = append(localFiles, nodeFile)
		} else {
			// Subscription URL file
			urls := readProviderURLsFromData(inputData)
			fmt.Printf("Subscription file: %s (%d URLs, %d unique in file)\n", nodeFile, len(urls), len(deduplicateStrings(urls)))
			allProviderURLs = append(allProviderURLs, urls...)
		}
	}

	fmt.Printf("\nTotal URLs before dedup: %d\n", len(allProviderURLs))

	// Deduplicate subscription URLs
	allProviderURLs = deduplicateStrings(allProviderURLs)
	fmt.Printf("Total unique subscription URLs: %d\n", len(allProviderURLs))
	fmt.Printf("Total local config files: %d\n\n", len(localFiles))

	// Phase 2: Fetch all subscriptions
	var allProxiesWithSource []ProxyWithSource

	if len(allProviderURLs) > 0 {
		fmt.Println("=== Phase 2: Fetching subscriptions ===")
		if *parallelFetch > 1 {
			allProxiesWithSource = fetchProxiesParallel(ctx, allProviderURLs, *parallelFetch)
		} else {
			allProxiesWithSource = fetchProxiesSerial(allProviderURLs)
		}
		fmt.Printf("\nFetched %d proxies from subscriptions\n\n", len(allProxiesWithSource))
	}

	// Phase 3: Parse local config files and merge
	if len(localFiles) > 0 {
		fmt.Println("=== Phase 3: Loading local config files ===")
		for _, localFile := range localFiles {
			inputData, err := os.ReadFile(localFile)
			if err != nil {
				fmt.Printf("Failed to read %s: %v\n", localFile, err)
				continue
			}
			mappings, err := parseProxies(inputData)
			if err != nil {
				fmt.Printf("Failed to parse %s: %v\n", localFile, err)
				continue
			}
			fmt.Printf("Loaded %d proxies from %s\n", len(mappings), localFile)
			// Add local file proxies with source tracking
			for _, m := range mappings {
				allProxiesWithSource = append(allProxiesWithSource, ProxyWithSource{
					Config:    m,
					SourceURL: localFile,
				})
			}
		}
		fmt.Println()
	}

	if len(allProxiesWithSource) == 0 {
		fmt.Println("No proxies found from any provider")
		os.Exit(1)
	}

	// Deduplicate by config hash (not by name)
	// This keeps nodes with same name but different configs
	seen := make(map[string]struct{})
	var uniqueProxiesWithSource []ProxyWithSource
	for _, p := range allProxiesWithSource {
		// Compute hash excluding name field
		hash := computeConfigHash(p.Config)
		if hash == "" {
			// If hash computation fails, fallback to name-based dedup
			name, _ := p.Config["name"].(string)
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			uniqueProxiesWithSource = append(uniqueProxiesWithSource, p)
			continue
		}
		if _, ok := seen[hash]; ok {
			continue // Skip same config
		}
		seen[hash] = struct{}{}
		uniqueProxiesWithSource = append(uniqueProxiesWithSource, p)
	}

	fmt.Printf("\nTotal unique proxies: %d\n\n", len(uniqueProxiesWithSource))

	// Parse proxies
	proxies := make([]C.Proxy, 0, len(uniqueProxiesWithSource))
	var proxyConfigs []map[string]any
	var sourceURLs []string
	var names []string

	if len(filterTypes) > 0 {
		fmt.Printf("Filtering by types: %v\n", filterTypes)
	} else if len(excludeTypes) > 0 {
		fmt.Printf("Excluding types: %v\n", excludeTypes)
	}
	if len(countries) > 0 {
		fmt.Printf("Filtering by countries: %v\n", countries)
	} else if len(excludeCountries) > 0 {
		fmt.Printf("Excluding countries: %v\n", excludeCountries)
	}
	if len(filterTypes) > 0 || len(excludeTypes) > 0 || len(countries) > 0 || len(excludeCountries) > 0 {
		fmt.Println()
	}

	for i, proxyWithSource := range uniqueProxiesWithSource {
		mapping := proxyWithSource.Config
		name, _ := mapping["name"].(string)
		if name == "" {
			name = fmt.Sprintf("proxy-%d", i)
			mapping["name"] = name
		}

		proxyType, _ := mapping["type"].(string)
		proxyTypeLower := strings.ToLower(proxyType)

		// Filter by types if specified
		if len(filterTypes) > 0 && !contains(filterTypes, proxyTypeLower) {
			continue
		}

		// Exclude by types if specified
		if len(excludeTypes) > 0 && contains(excludeTypes, proxyTypeLower) {
			continue
		}

		p, err := adapter.ParseProxy(mapping)
		if err != nil {
			fmt.Printf("  SKIP %s: %v\n", name, err)
			continue
		}
		proxies = append(proxies, p)
		proxyConfigs = append(proxyConfigs, mapping)
		sourceURLs = append(sourceURLs, proxyWithSource.SourceURL)
		names = append(names, name)
	}

	fmt.Printf("Parsed %d proxies\n\n", len(proxies))

	// Score mode: query fraud score and write output
	if *scoreMode {
		if err := scoreProxies(ctx, proxies, names, proxyConfigs, sourceURLs, out, *parallelFetch, *trackSource); err != nil {
			fmt.Printf("Score mode failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Phase 1: Test connectivity
	fmt.Println("=== Phase 1: Connectivity Test ===")
	aliveIndices := testConnectivity(ctx, proxies, names, *parallelFetch)
	fmt.Printf("Alive: %d / %d\n\n", len(aliveIndices), len(proxies))

	if len(aliveIndices) == 0 {
		fmt.Println("No alive proxies")
		os.Exit(0)
	}

	// Phase 2: Query ipwho.is for alive proxies
	fmt.Println("=== Phase 2: IP Lookup (ipwho.is) ===")
	var results []NodeInfo
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, *parallelFetch)
	var doneCount atomic.Int32

	// Create a done channel to signal early exit
	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, idx := range aliveIndices {
			select {
			case <-ctx.Done():
				return
			default:
			}

			wg.Add(1)
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				wg.Done()
				return
			}

			go func(i int) {
				defer wg.Done()
				defer func() { <-sem }()

				proxy := proxies[i]
				info := queryIPInfo(ctx, proxy, names[i], proxyConfigs[i])
				info.SourceURL = sourceURLs[i]

				mu.Lock()
				results = append(results, info)
				doneCount.Add(1)
				fmt.Printf("  [%d/%d] %s -> %s\n", doneCount.Load(), len(aliveIndices), names[i], info.NewName)
				mu.Unlock()
			}(idx)
		}
	}()

	select {
	case <-done:
		// Normal completion
	case <-ctx.Done():
		fmt.Println("\n  IP lookup interrupted")
	}

	wg.Wait()

	// Filter out failed lookups
	var validResults []NodeInfo
	for _, r := range results {
		if r.NewName != "" {
			validResults = append(validResults, r)
		}
	}

	validResults = filterCheckedResultsByCountry(validResults, countries, excludeCountries)

	// Sort results by name (country code first since name starts with it)
	sort.Slice(validResults, func(i, j int) bool {
		return validResults[i].NewName < validResults[j].NewName
	})

	// Step 1: Remove completely duplicate nodes (same base name + same config hash)
	// This must happen BEFORE deduplicateNames to avoid unnecessary hash suffixes
	beforeDupRemoval := len(validResults)
	validResults = removeDuplicateNodes(validResults)
	removedDups := beforeDupRemoval - len(validResults)

	// Step 2: Deduplicate names by appending config hash for nodes with same base name but different config
	deduplicateNames(validResults)
	hashedNames := 0
	for _, r := range validResults {
		if strings.Contains(r.NewName, "-") && len(r.configHash) > 0 && strings.HasSuffix(r.NewName, r.configHash) {
			hashedNames++
		}
	}

	fmt.Printf("Valid lookups: %d / %d", len(validResults), len(results))
	if removedDups > 0 {
		fmt.Printf(" (removed %d duplicates)", removedDups)
	}
	if hashedNames > 0 {
		fmt.Printf(" [%d with hash suffix]", hashedNames)
	}
	fmt.Println()
	fmt.Println()

	// Print API usage statistics
	apiStats := make(map[string]int)
	for _, r := range validResults {
		if r.APIUsed != "" {
			apiStats[r.APIUsed]++
		}
	}
	if len(apiStats) > 0 {
		fmt.Println("=== API 使用统计 ===")
		for api, count := range apiStats {
			fmt.Printf("  %s: %d\n", api, count)
		}
		fmt.Println()
	}

	if len(validResults) == 0 {
		fmt.Println("No valid IP lookups")
		os.Exit(0)
	}

	// Phase 3: Merge Hysteria/Hysteria2 ports if requested
	if *mergeHysteriaPorts {
		beforeMerge := len(validResults)
		validResults = mergeHysteriaPortsByConfig(validResults)
		merged := beforeMerge - len(validResults)
		if merged > 0 {
			fmt.Printf("Merged %d Hysteria/Hysteria2 nodes by ports\n", merged)
		}
		fmt.Println()
	}

	// Phase 4: Write output
	if err := writeYAML(validResults, out, *trackSource); err != nil {
		fmt.Printf("Failed to write output: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Written %d proxies to %s\n", len(validResults), out)
}

func shouldShowInteractiveHelp(args []string) bool {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" || arg == "-help" {
			return true
		}
	}
	return false
}

func supportsColor(file *os.File) bool {
	if file == nil {
		return false
	}
	term := strings.ToLower(os.Getenv("TERM"))
	return term != "" && term != "dumb"
}

func colorize(enabled bool, code string, text string) string {
	if !enabled {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func renderHelp(colored bool) string {
	var b strings.Builder
	cmd := filepath.Base(os.Args[0])
	section := func(title string) string {
		return colorize(colored, "1;36", title)
	}
	flagName := func(name string) string {
		return colorize(colored, "1;33", name)
	}
	code := func(text string) string {
		return colorize(colored, "32", text)
	}

	fmt.Fprintf(&b, "%s %s [选项] [输入文件...]\n\n", section("用法:"), cmd)
	fmt.Fprintf(&b, "%s\n", section("选项:"))
	fmt.Fprintf(&b, "  %s\n", flagName("-o string"))
	fmt.Fprintf(&b, "        输出YAML文件路径 (默认: 普通模式 <第一个输入文件>-checked.yaml, 合并模式 <第一个输入文件>-merged.yaml)\n")
	fmt.Fprintf(&b, "  %s\n", flagName("-parallel int"))
	fmt.Fprintf(&b, "        并行请求工作数 (默认 100, 仅普通模式)\n")
	fmt.Fprintf(&b, "  %s\n", flagName("-type string"))
	fmt.Fprintf(&b, "        按类型筛选节点,逗号分隔 (如: ss,vmess,trojan)\n")
	fmt.Fprintf(&b, "  %s\n", flagName("-exclude-type string"))
	fmt.Fprintf(&b, "        排除指定类型节点,逗号分隔 (如: ss,vmess)\n")
	fmt.Fprintf(&b, "  %s\n", flagName("-country string"))
	fmt.Fprintf(&b, "        按国家代码筛选节点,逗号分隔 (如: US,JP,HK)\n")
	fmt.Fprintf(&b, "  %s\n", flagName("-exclude-country string"))
	fmt.Fprintf(&b, "        排除指定国家代码,逗号分隔 (如: CN,RU)\n")
	fmt.Fprintf(&b, "  %s\n", flagName("-merge"))
	fmt.Fprintf(&b, "        合并已检查过的 YAML 文件,跳过测活和 IP 查询\n")
	fmt.Fprintf(&b, "  %s\n", flagName("-view"))
	fmt.Fprintf(&b, "        展示传入文件中的类型和国家代码统计,不写输出文件\n")
	fmt.Fprintf(&b, "  %s\n", flagName("-merge-ports"))
	fmt.Fprintf(&b, "        合并 Hysteria/Hysteria2 节点的端口 (相同配置不同端口合并为 ports 字段)\n")
	fmt.Fprintf(&b, "  %s\n", flagName("-track-source"))
	fmt.Fprintf(&b, "        添加 source-url 字段追踪订阅来源\n")
	fmt.Fprintf(&b, "  %s\n", flagName("-prune"))
	fmt.Fprintf(&b, "        修剪模式: 读取已检查/已评分的YAML,移除不可用节点,保留分数\n\n")

	fmt.Fprintf(&b, "%s\n", section("说明:"))
	fmt.Fprintf(&b, "  选项可以写在输入文件前面或后面\n")
	fmt.Fprintf(&b, "  文件名若以 - 开头,请使用 -- 放在选项与文件之间\n")
	fmt.Fprintf(&b, "  -type 与 -exclude-type 不能同时使用\n")
	fmt.Fprintf(&b, "  -country 与 -exclude-country 不能同时使用\n")
	fmt.Fprintf(&b, "  -merge, -view, -prune 两两不能同时使用\n")
	fmt.Fprintf(&b, "  -merge 与 -view 模式下不能使用 -parallel\n")
	fmt.Fprintf(&b, "  -view 模式下不写输出文件\n")
	fmt.Fprintf(&b, "  -prune 模式下不能使用 -type, -exclude-type, -country, -exclude-country\n")
	fmt.Fprintf(&b, "  -merge-ports 仅对 Hysteria/Hysteria2 协议有效\n\n")

	fmt.Fprintf(&b, "%s\n", section("参数:"))
	fmt.Fprintf(&b, "  [输入文件...]    普通模式: 订阅链接文件或本地配置文件\n")
	fmt.Fprintf(&b, "                   合并模式: 已检查过的 YAML 文件\n")
	fmt.Fprintf(&b, "                   修剪模式: 已检查/已评分的 YAML 文件\n")
	fmt.Fprintf(&b, "                   (默认: node.txt)\n\n")

	fmt.Fprintf(&b, "%s\n", section("示例:"))
	fmt.Fprintf(&b, "  普通检查:\n")
	fmt.Fprintf(&b, "    %s\n", code(cmd+" node.txt"))
	fmt.Fprintf(&b, "    %s\n", code(cmd+" -o output.yaml sub1.txt sub2.txt"))
	fmt.Fprintf(&b, "    %s\n", code(cmd+" -type ss,vmess -country JP,US node.txt"))
	fmt.Fprintf(&b, "    %s\n", code(cmd+" node.txt -exclude-type hysteria2 -exclude-country CN,RU -parallel 50"))
	fmt.Fprintf(&b, "  端口合并:\n")
	fmt.Fprintf(&b, "    %s\n", code(cmd+" -type hysteria2 -merge-ports node.txt"))
	fmt.Fprintf(&b, "    %s\n", code(cmd+" -merge-ports -o output.yaml node.txt"))
	fmt.Fprintf(&b, "  查看统计:\n")
	fmt.Fprintf(&b, "    %s\n", code(cmd+" -view node.txt"))
	fmt.Fprintf(&b, "    %s\n", code(cmd+" a.yaml b.yaml -view -type ss -country JP,US"))
	fmt.Fprintf(&b, "  合并已检查文件:\n")
	fmt.Fprintf(&b, "    %s\n", code(cmd+" -merge -o merged.yaml a-checked.yaml b-checked.yaml"))
	fmt.Fprintf(&b, "    %s\n", code(cmd+" a-checked.yaml b-checked.yaml -merge -type ss -country JP,US -o merged.yaml"))
	fmt.Fprintf(&b, "  修剪不可用节点:\n")
	fmt.Fprintf(&b, "    %s\n", code(cmd+" -prune scored.yaml"))
	fmt.Fprintf(&b, "    %s\n", code(cmd+" -prune -parallel 50 -o alive.yaml scored.yaml"))

	return b.String()
}

func writeHelp(w io.Writer) {
	_, _ = io.WriteString(w, renderHelp(false))
}

func showInteractiveHelp() {
	coloured := supportsColor(os.Stdout)
	_, _ = io.WriteString(os.Stdout, renderHelp(coloured))
}

// parseTypeList parses comma-separated type list into slice
func parseTypeList(input string) []string {
	if input == "" {
		return nil
	}
	parts := strings.Split(input, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(strings.ToLower(p))
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// contains checks if slice contains item
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func parseCountryList(input string) []string {
	if input == "" {
		return nil
	}
	parts := strings.Split(input, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(strings.ToUpper(p))
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

func isKnownFlag(arg string) bool {
	name := arg
	if strings.HasPrefix(name, "--") {
		name = strings.TrimPrefix(name, "--")
	} else if strings.HasPrefix(name, "-") {
		name = strings.TrimPrefix(name, "-")
	} else {
		return false
	}
	if idx := strings.IndexByte(name, '='); idx >= 0 {
		name = name[:idx]
	}

	switch name {
	case "o", "parallel", "type", "exclude-type", "country", "exclude-country", "merge", "view", "merge-ports", "track-source", "score", "prune", "h", "help":
		return true
	default:
		return false
	}
}

func flagNeedsValue(arg string) bool {
	name := arg
	if strings.HasPrefix(name, "--") {
		name = strings.TrimPrefix(name, "--")
	} else if strings.HasPrefix(name, "-") {
		name = strings.TrimPrefix(name, "-")
	}
	if idx := strings.IndexByte(name, '='); idx >= 0 {
		return false
	}

	switch name {
	case "o", "parallel", "type", "exclude-type", "country", "exclude-country":
		return true
	default:
		return false
	}
}

func normalizeArgs(args []string) ([]string, error) {
	var flags []string
	var files []string
	parsingFlags := true

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if parsingFlags && arg == "--" {
			parsingFlags = false
			continue
		}
		if parsingFlags && isKnownFlag(arg) {
			flags = append(flags, arg)
			if flagNeedsValue(arg) {
				if i+1 >= len(args) {
					return nil, fmt.Errorf("flag needs an argument: %s", arg)
				}
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		files = append(files, arg)
	}

	return append(flags, files...), nil
}

func countryCodeFromName(name string) string {
	parts := strings.Fields(strings.TrimSpace(name))
	if len(parts) == 0 {
		return ""
	}
	return strings.ToUpper(parts[0])
}

func filterCheckedResultsByCountry(results []NodeInfo, countries []string, excludeCountries []string) []NodeInfo {
	if len(countries) == 0 && len(excludeCountries) == 0 {
		return results
	}

	filtered := make([]NodeInfo, 0, len(results))
	for _, result := range results {
		countryCode := countryCodeFromName(result.NewName)
		if len(countries) > 0 && !contains(countries, countryCode) {
			continue
		}
		if len(excludeCountries) > 0 && contains(excludeCountries, countryCode) {
			continue
		}
		filtered = append(filtered, result)
	}
	return filtered
}

func filterProxyMappingsByType(mappings []map[string]any, filterTypes []string, excludeTypes []string) []map[string]any {
	if len(filterTypes) == 0 && len(excludeTypes) == 0 {
		return mappings
	}

	filtered := make([]map[string]any, 0, len(mappings))
	for _, mapping := range mappings {
		proxyType, _ := mapping["type"].(string)
		proxyTypeLower := strings.ToLower(proxyType)
		if len(filterTypes) > 0 && !contains(filterTypes, proxyTypeLower) {
			continue
		}
		if len(excludeTypes) > 0 && contains(excludeTypes, proxyTypeLower) {
			continue
		}
		filtered = append(filtered, mapping)
	}
	return filtered
}

// deduplicateStrings removes duplicate strings from slice (case-insensitive for URLs)
func deduplicateStrings(items []string) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, item := range items {
		// Use lowercase for comparison to handle HTTP:// vs http://
		key := strings.ToLower(item)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, item)
	}
	return result
}

// isLocalMode detects if input data is local proxy config (YAML/v2ray links)
// or subscription URLs by checking if any non-empty line starts with http:// or https://
func isLocalMode(data []byte) bool {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lowerLine := strings.ToLower(line)
		// If any non-empty line starts with http:// or https://, treat as subscription URLs
		if strings.HasPrefix(lowerLine, "http://") || strings.HasPrefix(lowerLine, "https://") {
			return false
		}
	}
	return true // Default to local mode if no URLs found
}

func isCheckedOutput(data []byte) bool {
	return bytes.Contains(data, []byte("# Generated by node-check"))
}

func loadCheckedResults(data []byte, filterTypes []string, excludeTypes []string) ([]NodeInfo, error) {
	mappings, err := parseProxies(data)
	if err != nil {
		return nil, err
	}
	mappings = filterProxyMappingsByType(mappings, filterTypes, excludeTypes)

	results := make([]NodeInfo, 0, len(mappings))
	for i, mapping := range mappings {
		name, _ := mapping["name"].(string)
		if name == "" {
			name = fmt.Sprintf("proxy-%d", i)
			mapping["name"] = name
		}
		results = append(results, NodeInfo{
			OriginalName: name,
			NewName:      name,
			Config:       mapping,
			configHash:   computeConfigHash(mapping),
		})
	}

	return results, nil
}

func printSortedStats(title string, stats map[string]int) {
	fmt.Printf("=== %s ===\n", title)
	if len(stats) == 0 {
		fmt.Println("  (none)")
		fmt.Println()
		return
	}

	type statItem struct {
		key   string
		count int
	}
	items := make([]statItem, 0, len(stats))
	for key, count := range stats {
		items = append(items, statItem{key: key, count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].count != items[j].count {
			return items[i].count > items[j].count
		}
		return items[i].key < items[j].key
	})
	for _, item := range items {
		fmt.Printf("  %-12s %d\n", item.key, item.count)
	}
	fmt.Println()
}

func viewInputFiles(inputFiles []string, filterTypes []string, excludeTypes []string, countries []string, excludeCountries []string) error {
	fmt.Println("=== View Mode: Loading input files ===")
	if len(filterTypes) > 0 {
		fmt.Printf("Filtering view results by types: %v\n", filterTypes)
	}
	if len(excludeTypes) > 0 {
		fmt.Printf("Excluding types from view results: %v\n", excludeTypes)
	}
	if len(countries) > 0 {
		fmt.Printf("Filtering view results by countries: %v\n", countries)
	}
	if len(excludeCountries) > 0 {
		fmt.Printf("Excluding countries from view results: %v\n", excludeCountries)
	}
	if len(filterTypes) > 0 || len(excludeTypes) > 0 || len(countries) > 0 || len(excludeCountries) > 0 {
		fmt.Println()
	}

	typeStats := make(map[string]int)
	countryStats := make(map[string]int)
	total := 0

	for _, inputFile := range inputFiles {
		inputData, err := os.ReadFile(inputFile)
		if err != nil {
			return fmt.Errorf("read %s: %w", inputFile, err)
		}

		mappings, err := parseProxies(inputData)
		if err != nil {
			return fmt.Errorf("parse %s: %w", inputFile, err)
		}
		mappings = filterProxyMappingsByType(mappings, filterTypes, excludeTypes)

		fileCount := 0
		for _, mapping := range mappings {
			proxyType, _ := mapping["type"].(string)
			proxyTypeLower := strings.ToLower(proxyType)
			if proxyTypeLower == "" {
				proxyTypeLower = "unknown"
			}

			name, _ := mapping["name"].(string)
			countryCode := countryCodeFromName(name)
			if countryCode == "" {
				countryCode = "UNKNOWN"
			}
			if len(countries) > 0 && !contains(countries, countryCode) {
				continue
			}
			if len(excludeCountries) > 0 && contains(excludeCountries, countryCode) {
				continue
			}

			typeStats[proxyTypeLower]++
			countryStats[countryCode]++
			fileCount++
			total++
		}
		fmt.Printf("Loaded %d proxies from %s\n", fileCount, inputFile)
	}

	fmt.Println()
	fmt.Printf("Total matched proxies: %d\n\n", total)
	printSortedStats("Type Statistics", typeStats)
	printSortedStats("Country Code Statistics", countryStats)
	return nil
}

func mergeCheckedFiles(inputFiles []string, out string, filterTypes []string, excludeTypes []string, countries []string, excludeCountries []string, mergeHysteriaPorts bool) error {
	fmt.Println("=== Merge Mode: Loading checked YAML files ===")
	if len(filterTypes) > 0 {
		fmt.Printf("Filtering merge results by types: %v\n", filterTypes)
	}
	if len(excludeTypes) > 0 {
		fmt.Printf("Excluding types from merge results: %v\n", excludeTypes)
	}
	if len(countries) > 0 {
		fmt.Printf("Filtering merge results by countries: %v\n", countries)
	}
	if len(excludeCountries) > 0 {
		fmt.Printf("Excluding countries from merge results: %v\n", excludeCountries)
	}

	var allResults []NodeInfo
	for _, inputFile := range inputFiles {
		inputData, err := os.ReadFile(inputFile)
		if err != nil {
			return fmt.Errorf("read %s: %w", inputFile, err)
		}
		if !isCheckedOutput(inputData) {
			return fmt.Errorf("%s is not a node-check generated checked YAML file", inputFile)
		}

		results, err := loadCheckedResults(inputData, filterTypes, excludeTypes)
		if err != nil {
			return fmt.Errorf("parse %s: %w", inputFile, err)
		}
		results = filterCheckedResultsByCountry(results, countries, excludeCountries)
		fmt.Printf("Loaded %d checked proxies from %s\n", len(results), inputFile)
		allResults = append(allResults, results...)
	}

	if len(allResults) == 0 {
		return fmt.Errorf("no checked proxies found")
	}

	// Sort results by name (country code first since name starts with it)
	sort.Slice(allResults, func(i, j int) bool {
		return allResults[i].NewName < allResults[j].NewName
	})

	beforeDupRemoval := len(allResults)
	allResults = removeDuplicateNodes(allResults)
	removedDups := beforeDupRemoval - len(allResults)
	deduplicateNames(allResults)

	// Apply port merging if requested
	if mergeHysteriaPorts {
		beforePortMerge := len(allResults)
		allResults = mergeHysteriaPortsByConfig(allResults)
		portMerged := beforePortMerge - len(allResults)
		if portMerged > 0 {
			fmt.Printf("Merged %d Hysteria/Hysteria2 nodes by ports\n", portMerged)
		}
	}

	// Sort again after all processing
	sort.Slice(allResults, func(i, j int) bool {
		return allResults[i].NewName < allResults[j].NewName
	})

	if err := writeYAML(allResults, out, false); err != nil {
		return err
	}

	fmt.Printf("Merged %d proxies", len(allResults))
	if removedDups > 0 {
		fmt.Printf(" (removed %d duplicates)", removedDups)
	}
	fmt.Println()
	fmt.Printf("Written merged proxies to %s\n", out)
	return nil
}

// pruneDeadNodes reads checked/scored YAML files, tests connectivity, and keeps only alive nodes.
// Original names (including fraud scores like "⭐95") are preserved.
func pruneDeadNodes(ctx context.Context, inputFiles []string, out string, parallel int) error {
	fmt.Println("=== Prune Mode: Removing dead nodes ===")

	var allMappings []map[string]any
	for _, f := range inputFiles {
		data, err := os.ReadFile(f)
		if err != nil {
			return fmt.Errorf("read %s: %w", f, err)
		}
		mappings, err := parseProxies(data)
		if err != nil {
			return fmt.Errorf("parse %s: %w", f, err)
		}
		fmt.Printf("Loaded %d proxies from %s\n", len(mappings), f)
		allMappings = append(allMappings, mappings...)
	}

	if len(allMappings) == 0 {
		return fmt.Errorf("no proxies found")
	}

	// Parse proxies for connectivity testing
	var proxies []C.Proxy
	var names []string
	var configs []map[string]any

	for i, m := range allMappings {
		name, _ := m["name"].(string)
		if name == "" {
			name = fmt.Sprintf("proxy-%d", i)
			m["name"] = name
		}

		p, err := adapter.ParseProxy(m)
		if err != nil {
			fmt.Printf("  SKIP %s: %v\n", name, err)
			continue
		}
		proxies = append(proxies, p)
		names = append(names, name)
		configs = append(configs, m)
	}

	fmt.Printf("\nParsed %d proxies\n\n", len(proxies))

	// Test connectivity
	aliveIndices := testConnectivity(ctx, proxies, names, parallel)
	fmt.Printf("Alive: %d / %d\n\n", len(aliveIndices), len(proxies))

	if len(aliveIndices) == 0 {
		fmt.Println("No alive proxies")
		return nil
	}

	// Build results keeping original names intact
	var results []NodeInfo
	for _, idx := range aliveIndices {
		results = append(results, NodeInfo{
			OriginalName: names[idx],
			NewName:      names[idx],
			Config:       configs[idx],
		})
	}

	// Sort by name
	sort.Slice(results, func(i, j int) bool {
		return results[i].NewName < results[j].NewName
	})

	// Write output
	if err := writeYAML(results, out, false); err != nil {
		return fmt.Errorf("write output: %w", err)
	}

	fmt.Printf("Written %d alive proxies to %s\n", len(results), out)
	return nil
}

// readProviderURLsFromData extracts HTTP URLs from byte data (case-insensitive)
func readProviderURLsFromData(data []byte) []string {
	var urls []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lowerLine := strings.ToLower(line)
		if strings.HasPrefix(lowerLine, "http://") || strings.HasPrefix(lowerLine, "https://") {
			urls = append(urls, line)
		}
	}
	return urls
}

// readProviderURLs reads the node file and extracts HTTP URLs
func readProviderURLs(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		fmt.Printf("Failed to open %s: %v\n", path, err)
		return nil
	}
	defer f.Close()

	var urls []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
			urls = append(urls, line)
		}
	}
	return urls
}

// fetchProxiesSerial fetches subscriptions one by one (default behavior)
func fetchProxiesSerial(providerURLs []string) []ProxyWithSource {
	var allProxiesWithSource []ProxyWithSource
	for _, u := range providerURLs {
		mappings, fromCache, err := fetchProxies(u)
		if err != nil {
			fmt.Printf("Fetching %s ... FAILED: %v\n", u, err)
			continue
		}
		tag := ""
		if fromCache {
			tag = " (cache)"
		}
		fmt.Printf("Fetching %s ... OK%s (%d proxies)\n", u, tag, len(mappings))
		for _, m := range mappings {
			allProxiesWithSource = append(allProxiesWithSource, ProxyWithSource{
				Config:    m,
				SourceURL: u,
			})
		}
	}
	return allProxiesWithSource
}

// fetchProxiesParallel fetches subscriptions concurrently with limited workers
func fetchProxiesParallel(ctx context.Context, providerURLs []string, workers int) []ProxyWithSource {
	type result struct {
		url       string
		mappings  []map[string]any
		fromCache bool
		err       error
	}

	var wg sync.WaitGroup
	urlChan := make(chan string, len(providerURLs))
	resultChan := make(chan result, len(providerURLs))

	// Start workers
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for u := range urlChan {
				select {
				case <-ctx.Done():
					return
				default:
					mappings, fromCache, err := fetchProxies(u)
					resultChan <- result{url: u, mappings: mappings, fromCache: fromCache, err: err}
				}
			}
		}()
	}

	// Send URLs to workers
	go func() {
		for _, u := range providerURLs {
			select {
			case urlChan <- u:
			case <-ctx.Done():
				break
			}
		}
		close(urlChan)
	}()

	// Close result channel when all workers done
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	var allProxiesWithSource []ProxyWithSource
	var mu sync.Mutex
	var doneCount atomic.Int32
	total := len(providerURLs)

	for res := range resultChan {
		if ctx.Err() != nil {
			// Drain remaining results without processing
			go func() {
				for range resultChan {
				}
			}()
			break
		}

		doneCount.Add(1)
		if res.err != nil {
			fmt.Printf("[%d/%d] Fetching %s ... FAILED: %v\n", doneCount.Load(), total, res.url, res.err)
			continue
		}
		tag := ""
		if res.fromCache {
			tag = " (cache)"
		}
		fmt.Printf("[%d/%d] Fetching %s ... OK%s (%d proxies)\n", doneCount.Load(), total, res.url, tag, len(res.mappings))
		mu.Lock()
		for _, m := range res.mappings {
			allProxiesWithSource = append(allProxiesWithSource, ProxyWithSource{
				Config:    m,
				SourceURL: res.url,
			})
		}
		mu.Unlock()
	}

	return allProxiesWithSource
}

// fetchProxies downloads and parses a proxy subscription, with file-based caching.
// Returns (mappings, fromCache, error).
func fetchProxies(subURL string) ([]map[string]any, bool, error) {
	cacheDir := getCacheDir()
	cacheFile := filepath.Join(cacheDir, cacheKey(subURL))

	// Try cache first
	if cached, err := readCache(cacheFile); err == nil && time.Since(cached.At) < cacheTTL {
		return cached.Data, true, nil
	}

	// Fetch from network
	body, err := fetchRaw(subURL)
	if err != nil {
		return nil, false, err
	}

	// Parse
	mappings, err := parseProxies(body)
	if err != nil {
		return nil, false, err
	}

	// Save to cache
	_ = writeCache(cacheFile, mappings)
	return mappings, false, nil
}

// fetchRaw downloads the raw subscription data
func fetchRaw(subURL string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, subURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ClashMeta/v2.11.5")

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	defer client.CloseIdleConnections()

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

// parseProxies tries YAML first, then v2ray share links
func parseProxies(body []byte) ([]map[string]any, error) {
	var schema ProxySchema
	if err := mihomoyaml.Unmarshal(body, &schema); err == nil && len(schema.Proxies) > 0 {
		return schema.Proxies, nil
	}
	return convert.ConvertsV2Ray(body)
}

// cacheEntry is the on-disk cache format
type cacheEntry struct {
	At   time.Time        `json:"at"`
	URL  string           `json:"url"`
	Data []map[string]any `json:"data"`
}

func getCacheDir() string {
	dir := filepath.Join("cache", "node-check")
	os.MkdirAll(dir, 0o755)
	return dir
}

func cacheKey(subURL string) string {
	h := sha256.Sum256([]byte(subURL))
	return fmt.Sprintf("%x.json", h[:16])
}

func readCache(path string) (*cacheEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var entry cacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

func writeCache(path string, data []map[string]any) error {
	entry := cacheEntry{At: time.Now(), Data: data}
	buf, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return os.WriteFile(path, buf, 0o644)
}

// testConnectivity tests all proxies concurrently
func testConnectivity(ctx context.Context, proxies []C.Proxy, names []string, concurrency int) []int {
	var aliveIndices []int
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	var doneCount atomic.Int32
	total := len(proxies)

	// Create a done channel to signal early exit
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i, p := range proxies {
			select {
			case <-ctx.Done():
				return
			default:
			}

			wg.Add(1)
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				wg.Done()
				return
			}

			go func(idx int, proxy C.Proxy) {
				defer wg.Done()
				defer func() { <-sem }()

				testCtx, testCancel := context.WithTimeout(ctx, testTimeout)
				defer testCancel()

				delay, err := proxy.URLTest(testCtx, defaultTestURL, nil)
				alive := err == nil && delay > 0

				mu.Lock()
				if alive {
					aliveIndices = append(aliveIndices, idx)
				}
				d := doneCount.Add(1)
				status := "OK"
				if !alive {
					status = "FAIL"
				}
				fmt.Printf("  [%d/%d] %-30s %s (%dms)\n", d, total, names[idx], status, delay)
				mu.Unlock()
			}(i, p)
		}
	}()

	select {
	case <-done:
		// Normal completion
	case <-ctx.Done():
		fmt.Println("\n  Connectivity test interrupted")
	}

	wg.Wait()
	return aliveIndices
}

// IPSBResponse is the response from ip.sb (second fallback)
type IPSBResponse struct {
	IP          string `json:"ip"`
	CountryCode string `json:"country_code"`
	Country     string `json:"country"`
	Region      string `json:"region"`
	City        string `json:"city"`
	ISP         string `json:"isp"`
	ASN         int    `json:"asn"`
	Org         string `json:"organization"`
}

// IPInfoResponse is the response from ipinfo.io (primary)
type IPInfoResponse struct {
	IP       string `json:"ip"`
	City     string `json:"city"`
	Region   string `json:"region"`
	Country  string `json:"country"`
	Location string `json:"loc"`
	Org      string `json:"org"`
	Postal   string `json:"postal"`
	Timezone string `json:"timezone"`
}

// IPWhoResponse is the response from ipwho.is (third fallback)
type IPWhoResponse struct {
	IP            string `json:"ip"`
	Success       bool   `json:"success"`
	Type          string `json:"type"`
	Continent     string `json:"continent"`
	ContinentCode string `json:"continent_code"`
	Country       string `json:"country"`
	CountryCode   string `json:"country_code"`
	Region        string `json:"region"`
	City          string `json:"city"`
	ISP           string `json:"connection",omitempty"`
	ORG           string `json:"org"`
	ASN           int    `json:"asn"`
	Domain        string `json:"domain"`
}

// Connection field from ipwho.is
type IPWhoConnection struct {
	ASN    int    `json:"asn"`
	ORG    string `json:"org"`
	ISP    string `json:"isp"`
	Domain string `json:"domain"`
	Type   string `json:"type"`
}

type IPWhoFullResponse struct {
	IP          string          `json:"ip"`
	Success     bool            `json:"success"`
	Type        string          `json:"type"`
	Continent   string          `json:"continent"`
	Country     string          `json:"country"`
	CountryCode string          `json:"country_code"`
	Region      string          `json:"region"`
	City        string          `json:"city"`
	Connection  IPWhoConnection `json:"connection"`
}

// queryIPInfo queries ipinfo.io through the proxy, with ip.sb and ipwho.is as fallbacks
func queryIPInfo(ctx context.Context, proxy C.Proxy, name string, config map[string]any) NodeInfo {
	info := NodeInfo{
		OriginalName: name,
		Config:       config,
	}

	// Try ipinfo.io first (primary)
	testCtx, testCancel := context.WithTimeout(ctx, ipinfoTimeout)
	defer testCancel()

	respBody, err := dialThroughProxy(testCtx, proxy, ipinfoURL)
	if err == nil {
		var ipResp IPInfoResponse
		if err := json.Unmarshal(respBody, &ipResp); err == nil && ipResp.IP != "" {
			countryCode := ipResp.Country
			if countryCode == "" {
				countryCode = "XX"
			}
			countryCode = strings.ToUpper(countryCode)

			// Extract ISP from org field (format: "ASXXXXX ISP Name")
			isp := normalizeISPFromOrg(ipResp.Org)
			if isp == "" {
				isp = "Unknown"
			}

			info.CountryCode = countryCode
			info.Country = ipResp.Region
			if info.Country == "" {
				info.Country = ipResp.City
			}
			info.ISP = isp
			info.IP = ipResp.IP
			info.NewName = fmt.Sprintf("%s %s %s", countryCode, isp, ipResp.IP)
			info.APIUsed = "ipinfo.io"
			info.configHash = computeConfigHash(config)
			return info
		}
	}

	// Fallback to ip.sb (second)
	testCtx2, testCancel2 := context.WithTimeout(ctx, ipsbTimeout)
	defer testCancel2()

	respBody, err = dialThroughProxy(testCtx2, proxy, ipsbURL)
	if err == nil {
		var ipResp IPSBResponse
		if err := json.Unmarshal(respBody, &ipResp); err == nil && ipResp.IP != "" {
			countryCode := ipResp.CountryCode
			if countryCode == "" {
				countryCode = "XX"
			}
			countryCode = strings.ToUpper(countryCode)

			// Use ISP field, fallback to Org
			isp := normalizeISP(ipResp.ISP)
			if isp == "" {
				isp = normalizeISP(ipResp.Org)
			}
			if isp == "" {
				isp = "Unknown"
			}

			info.CountryCode = countryCode
			info.Country = ipResp.Country
			info.ISP = isp
			info.IP = ipResp.IP
			info.NewName = fmt.Sprintf("%s %s %s", countryCode, isp, ipResp.IP)
			info.APIUsed = "ip.sb"
			info.configHash = computeConfigHash(config)
			return info
		}
	}

	// Fallback to ipwho.is (third)
	testCtx3, testCancel3 := context.WithTimeout(ctx, ipwhoTimeout)
	defer testCancel3()

	respBody, err = dialThroughProxy(testCtx3, proxy, ipwhoURL)
	if err != nil {
		fmt.Printf("  SKIP %s: IP lookup failed: %v\n", name, err)
		return info
	}

	var ipResp IPWhoFullResponse
	if err := json.Unmarshal(respBody, &ipResp); err != nil {
		fmt.Printf("  SKIP %s: JSON parse error: %v\n", name, err)
		return info
	}

	if !ipResp.Success {
		fmt.Printf("  SKIP %s: ipwho.is returned failure\n", name)
		return info
	}

	countryCode := ipResp.CountryCode
	if countryCode == "" {
		countryCode = "XX"
	}
	countryCode = strings.ToUpper(countryCode)

	isp := ipResp.Connection.ISP
	if isp == "" {
		isp = ipResp.Connection.ORG
	}
	if isp == "" {
		isp = "Unknown"
	}

	// Normalize ISP name: take first meaningful segment
	isp = normalizeISP(isp)

	info.CountryCode = countryCode
	info.Country = ipResp.Country
	info.ISP = isp
	info.IP = ipResp.IP
	info.NewName = fmt.Sprintf("%s %s %s", countryCode, isp, ipResp.IP)
	info.APIUsed = "ipwho.is"
	// Pre-compute config hash for potential deduplication (excludes name field)
	info.configHash = computeConfigHash(config)

	return info
}

// computeConfigHash computes a short hash of the config excluding the name field
func computeConfigHash(config map[string]any) string {
	// Create a copy without the name field
	cfgCopy := make(map[string]any, len(config))
	for k, v := range config {
		if k != "name" {
			cfgCopy[k] = v
		}
	}
	// Marshal to JSON for consistent hashing
	data, err := json.Marshal(cfgCopy)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:4]) // Use first 4 bytes (8 hex chars) for brevity
}

// deduplicateNames finds duplicate names and appends config hash to make them unique
func deduplicateNames(results []NodeInfo) {
	// Group by name
	nameGroups := make(map[string][]int) // name -> indices in results
	for i := range results {
		name := results[i].NewName
		nameGroups[name] = append(nameGroups[name], i)
	}

	// For each group with duplicates, append hash
	for _, indices := range nameGroups {
		if len(indices) <= 1 {
			continue // No duplicates
		}
		for _, idx := range indices {
			hash := results[idx].configHash
			if hash != "" {
				results[idx].NewName = fmt.Sprintf("%s-%s", results[idx].NewName, hash)
			}
		}
	}
}

// removeDuplicateNodes removes nodes that have identical config hash
// This removes completely identical nodes before adding hash suffixes to distinguish
// nodes with the same IP but different configs
func removeDuplicateNodes(results []NodeInfo) []NodeInfo {
	seen := make(map[string]struct{})
	var unique []NodeInfo
	for _, r := range results {
		// Use only config hash as key - nodes with identical configs are duplicates
		// regardless of their current name
		if _, ok := seen[r.configHash]; ok {
			continue // Skip duplicate
		}
		seen[r.configHash] = struct{}{}
		unique = append(unique, r)
	}
	return unique
}

// dialThroughProxy makes a request through the proxy to get IP info
func dialThroughProxy(ctx context.Context, proxy C.Proxy, targetURL string) ([]byte, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}

	metadata := &C.Metadata{}
	if err := metadata.SetRemoteAddress(net.JoinHostPort(u.Hostname(), port)); err != nil {
		return nil, err
	}

	conn, err := proxy.DialContext(ctx, metadata)
	if err != nil {
		return nil, fmt.Errorf("dial failed: %w", err)
	}
	defer conn.Close()

	transport := &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return conn, nil
		},
		TLSHandshakeTimeout:   ipwhoTimeout,
		ResponseHeaderTimeout: ipwhoTimeout,
	}

	client := &http.Client{
		Timeout:   ipwhoTimeout,
		Transport: transport,
	}
	defer client.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ClashMeta/v2.11.5")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

// normalizeISP takes an ISP name and returns a shortened/clean version
func normalizeISP(isp string) string {
	if isp == "" {
		return "Unknown"
	}
	// Remove common suffixes and clean up
	isp = strings.TrimSpace(isp)
	// Take the first meaningful part if it contains common separators
	for _, sep := range []string{",", ";", " / ", " | "} {
		if idx := strings.Index(isp, sep); idx > 0 {
			isp = strings.TrimSpace(isp[:idx])
		}
	}
	if isp == "" {
		return "Unknown"
	}
	return isp
}

// normalizeISPFromOrg extracts ISP name from ipinfo.io org field
// org format: "ASXXXXX ISP Name" or "AS9808 China Mobile Communications Group Co., Ltd."
func normalizeISPFromOrg(org string) string {
	if org == "" {
		return "Unknown"
	}
	org = strings.TrimSpace(org)

	// Remove AS number prefix (e.g., "AS9808 ")
	if strings.HasPrefix(org, "AS") {
		if idx := strings.Index(org, " "); idx > 0 {
			org = strings.TrimSpace(org[idx+1:])
		}
	}

	// Apply same normalization as normalizeISP
	return normalizeISP(org)
}

// mergeHysteriaPortsByConfig merges Hysteria/Hysteria2 nodes that have identical configs except port
// It combines them into single nodes with "ports" field containing comma-separated port list
func mergeHysteriaPortsByConfig(results []NodeInfo) []NodeInfo {
	// Group nodes by: type + config (excluding name and port)
	type groupKey struct {
		proxyType string
		baseHash  string // hash of config excluding name, port, and ports fields
	}

	groups := make(map[groupKey][]int) // groupKey -> indices in results

	for i, r := range results {
		proxyType, ok := r.Config["type"].(string)
		if !ok {
			continue
		}
		proxyTypeLower := strings.ToLower(proxyType)

		// Only process hysteria and hysteria2
		if proxyTypeLower != "hysteria" && proxyTypeLower != "hysteria2" {
			continue
		}

		// Compute hash excluding name, port, and ports
		baseHash := computeBaseConfigHash(r.Config)
		if baseHash == "" {
			continue
		}

		key := groupKey{
			proxyType: proxyTypeLower,
			baseHash:  baseHash,
		}
		groups[key] = append(groups[key], i)
	}

	// Track which indices should be kept vs merged
	merged := make(map[int]bool) // indices that were merged into another node
	var newResults []NodeInfo

	for _, indices := range groups {
		if len(indices) <= 1 {
			continue // No duplicates, skip
		}

		// Collect all ports from this group
		var ports []int
		portSet := make(map[int]struct{})

		for _, idx := range indices {
			if port, ok := results[idx].Config["port"].(int); ok {
				if _, exists := portSet[port]; !exists {
					ports = append(ports, port)
					portSet[port] = struct{}{}
				}
			}
		}

		if len(ports) <= 1 {
			continue // All same port or no valid ports
		}

		// Sort ports for consistent output
		sort.Ints(ports)

		// Use first node as base, merge ports into it
		baseIdx := indices[0]
		baseNode := results[baseIdx]

		// Build ports string
		portsStr := joinPorts(ports)

		// Update config: remove single port, add ports field
		delete(baseNode.Config, "port")
		baseNode.Config["ports"] = portsStr

		// Clean up name (remove hash suffix if present)
		baseName := baseNode.NewName
		// Remove hash suffix like "-b0709fa2" if present
		if idx := strings.LastIndex(baseName, "-"); idx > 0 {
			// Check if suffix looks like a hash (8 hex chars)
			suffix := baseName[idx+1:]
			if len(suffix) == 8 && isHexString(suffix) {
				baseName = baseName[:idx]
			}
		}
		baseNode.NewName = baseName

		newResults = append(newResults, baseNode)

		// Mark all nodes in this group as merged
		for _, idx := range indices {
			merged[idx] = true
		}
	}

	// Add all non-merged nodes
	for i, r := range results {
		if !merged[i] {
			newResults = append(newResults, r)
		}
	}

	return newResults
}

// computeBaseConfigHash computes hash of config excluding name, port, and ports fields
func computeBaseConfigHash(config map[string]any) string {
	cfgCopy := make(map[string]any, len(config))
	for k, v := range config {
		if k != "name" && k != "port" && k != "ports" {
			cfgCopy[k] = v
		}
	}
	data, err := json.Marshal(cfgCopy)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:4])
}

// joinPorts creates a compact port list string (e.g., "443,8443,10000")
// If there are more than 28 ports (mihomo's limit), it compresses to "min-max" format
func joinPorts(ports []int) string {
	if len(ports) == 0 {
		return ""
	}

	// mihomo has a limit of 28 ranges
	// If we have more than 28 ports, compress to a single range: min-max
	if len(ports) > 28 {
		minPort := ports[0]
		maxPort := ports[len(ports)-1]
		return fmt.Sprintf("%d-%d", minPort, maxPort)
	}

	// Try to compress consecutive ports into ranges
	compressed := compressPortRanges(ports)

	// If compressed still has too many segments, fall back to min-max
	if len(compressed) > 28 {
		minPort := ports[0]
		maxPort := ports[len(ports)-1]
		return fmt.Sprintf("%d-%d", minPort, maxPort)
	}

	return strings.Join(compressed, ",")
}

// compressPortRanges compresses consecutive ports into ranges
// e.g., [443, 444, 445, 8443, 10000, 10001] -> ["443-445", "8443", "10000-10001"]
func compressPortRanges(ports []int) []string {
	if len(ports) == 0 {
		return nil
	}

	var result []string
	start := ports[0]
	end := ports[0]

	for i := 1; i < len(ports); i++ {
		if ports[i] == end+1 {
			// Consecutive port, extend range
			end = ports[i]
		} else {
			// Gap found, save current range
			if start == end {
				result = append(result, strconv.Itoa(start))
			} else if end == start+1 {
				// Only 2 consecutive ports, list them separately (shorter)
				result = append(result, strconv.Itoa(start))
				result = append(result, strconv.Itoa(end))
			} else {
				// 3+ consecutive ports, use range
				result = append(result, fmt.Sprintf("%d-%d", start, end))
			}
			start = ports[i]
			end = ports[i]
		}
	}

	// Save last range
	if start == end {
		result = append(result, strconv.Itoa(start))
	} else if end == start+1 {
		result = append(result, strconv.Itoa(start))
		result = append(result, strconv.Itoa(end))
	} else {
		result = append(result, fmt.Sprintf("%d-%d", start, end))
	}

	return result
}

// isHexString checks if a string contains only hexadecimal characters
func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// writeYAML writes the results in proxy-provider YAML format
func writeYAML(results []NodeInfo, path string, trackSource bool) error {
	// Build the document using yaml.v3 Node for controlled key ordering
	root := &yaml.Node{Kind: yaml.DocumentNode}
	doc := &yaml.Node{Kind: yaml.MappingNode}
	root.Content = append(root.Content, doc)

	// proxies key first
	doc.Content = append(doc.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Value: "proxies"},
	)

	// proxies as a sequence
	seq := &yaml.Node{Kind: yaml.SequenceNode}
	for _, r := range results {
		proxyNode := &yaml.Node{Kind: yaml.MappingNode}

		// name first
		proxyNode.Content = append(proxyNode.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: "name"},
			&yaml.Node{Kind: yaml.ScalarNode, Value: r.NewName},
		)

		// remaining keys sorted
		keys := make([]string, 0, len(r.Config))
		for k := range r.Config {
			if k != "name" {
				keys = append(keys, k)
			}
		}
		sortKeys(keys)
		for _, k := range keys {
			keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: k}
			valNode := new(yaml.Node)
			if err := valNode.Encode(r.Config[k]); err != nil {
				valNode.Kind = yaml.ScalarNode
				valNode.Value = fmt.Sprintf("%v", r.Config[k])
			}
			proxyNode.Content = append(proxyNode.Content, keyNode, valNode)
		}

		// Add source-url field if tracking is enabled and source is available
		if trackSource && r.SourceURL != "" {
			proxyNode.Content = append(proxyNode.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Value: "source-url"},
				&yaml.Node{Kind: yaml.ScalarNode, Value: r.SourceURL},
			)
		}

		seq.Content = append(seq.Content, proxyNode)
	}
	doc.Content = append(doc.Content, seq)

	data, err := yaml.Marshal(root)
	if err != nil {
		return fmt.Errorf("marshal yaml: %w", err)
	}

	// Reduce indentation from 4 spaces to 2 spaces (standard for mihomo configs)
	data = bytes.ReplaceAll(data, []byte("\n    "), []byte("\n  "))

	// Add header comment
	output := fmt.Sprintf("# Node checker results\n# Total: %d proxies\n# Generated by node-check\n\n%s", len(results), string(data))
	return os.WriteFile(path, []byte(output), 0o644)
}

// queryScore queries fraud score through the proxy (IPv4 only)
func queryScore(ctx context.Context, proxy C.Proxy, name string) (int, error) {
	testCtx, testCancel := context.WithTimeout(ctx, scoreTimeout)
	defer testCancel()

	respBody, err := dialThroughProxyIPv4(testCtx, proxy, scoreURL)
	if err != nil {
		return -1, fmt.Errorf("request failed: %w", err)
	}

	var resp ScoreResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return -1, fmt.Errorf("json parse error: %w, body: %s", err, string(respBody))
	}

	// Check if returned IP is IPv6, discard if so
	if net.ParseIP(resp.IP).To4() == nil {
		return -1, fmt.Errorf("returned IPv6: %s", resp.IP)
	}

	return resp.FraudScore, nil
}

// dialThroughProxyIPv4 makes a request through the proxy using only IPv4
func dialThroughProxyIPv4(ctx context.Context, proxy C.Proxy, targetURL string) ([]byte, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	// Force resolve to IPv4 address
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", u.Hostname())
	if err != nil {
		return nil, fmt.Errorf("IPv4 lookup failed: %w", err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IPv4 address found for %s", u.Hostname())
	}
	ipv4 := ips[0].String()

	port := u.Port()
	if port == "" {
		port = "443"
	}

	metadata := &C.Metadata{}
	if err := metadata.SetRemoteAddress(net.JoinHostPort(ipv4, port)); err != nil {
		return nil, err
	}

	conn, err := proxy.DialContext(ctx, metadata)
	if err != nil {
		return nil, fmt.Errorf("dial failed: %w", err)
	}
	defer conn.Close()

	transport := &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return conn, nil
		},
		TLSClientConfig: &tls.Config{
			ServerName: u.Hostname(),
		},
		TLSHandshakeTimeout:   scoreTimeout,
		ResponseHeaderTimeout: scoreTimeout,
	}

	client := &http.Client{
		Timeout:   scoreTimeout,
		Transport: transport,
	}
	defer client.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ClashMeta/v2.11.5")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

// scoreProxies queries fraud score for all proxies and writes output
func scoreProxies(ctx context.Context, proxies []C.Proxy, names []string, proxyConfigs []map[string]any, sourceURLs []string, out string, parallel int, trackSource bool) error {
	fmt.Println("=== Score Mode: Querying fraud score ===")
	var results []NodeInfo
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, parallel)
	var doneCount atomic.Int32

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range proxies {
			select {
			case <-ctx.Done():
				return
			default:
			}

			wg.Add(1)
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				wg.Done()
				return
			}

			go func(idx int) {
				defer wg.Done()
				defer func() { <-sem }()

				proxy := proxies[idx]
				name := names[idx]

				score, err := queryScore(ctx, proxy, name)
				newName := name
				if err == nil {
					newName = fmt.Sprintf("%s ⭐%d", name, score)
				}

				info := NodeInfo{
					OriginalName: name,
					NewName:      newName,
					FraudScore:   score,
					Config:       proxyConfigs[idx],
					SourceURL:    sourceURLs[idx],
					configHash:   computeConfigHash(proxyConfigs[idx]),
				}

				mu.Lock()
				results = append(results, info)
				doneCount.Add(1)
				if err != nil {
					fmt.Printf("  [%d/%d] %s -> score failed: %v\n", doneCount.Load(), len(proxies), name, err)
				} else {
					fmt.Printf("  [%d/%d] %s -> ⭐%d\n", doneCount.Load(), len(proxies), name, score)
				}
				mu.Unlock()
			}(i)
		}
	}()

	select {
	case <-done:
		// Normal completion
	case <-ctx.Done():
		fmt.Println("\n  Score lookup interrupted")
	}

	wg.Wait()

	// Filter out results (keep all, even failed ones)
	if len(results) == 0 {
		return fmt.Errorf("no results")
	}

	// Sort results by name
	sort.Slice(results, func(i, j int) bool {
		return results[i].NewName < results[j].NewName
	})

	// Remove duplicate nodes
	results = removeDuplicateNodes(results)

	fmt.Printf("\nTotal: %d proxies\n\n", len(results))

	// Write output
	if err := writeYAML(results, out, trackSource); err != nil {
		return fmt.Errorf("write output: %w", err)
	}

	fmt.Printf("Written %d proxies to %s\n", len(results), out)
	return nil
}
