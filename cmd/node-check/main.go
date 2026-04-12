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
		fmt.Fprintf(os.Stderr, "用法: %s [选项] [输入文件...]\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "选项:")
		fmt.Fprintln(os.Stderr, "  -o string")
		fmt.Fprintln(os.Stderr, "        输出YAML文件路径 (默认: <第一个输入文件>-checked.yaml)")
		fmt.Fprintln(os.Stderr, "  -parallel int")
		fmt.Fprintln(os.Stderr, "        并行请求工作数 (默认 100)")
		fmt.Fprintln(os.Stderr, "  -type string")
		fmt.Fprintln(os.Stderr, "        按类型筛选节点,逗号分隔 (如: ss,vmess,trojan)")
		fmt.Fprintln(os.Stderr, "  -exclude-type string")
		fmt.Fprintln(os.Stderr, "        排除指定类型节点,逗号分隔 (如: ss,vmess)")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "参数:")
		fmt.Fprintln(os.Stderr, "  [输入文件...]    订阅链接文件或本地配置文件")
		fmt.Fprintln(os.Stderr, "                   (默认: node.txt)")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "示例:")
		fmt.Fprintln(os.Stderr, "  node-check node.txt")
		fmt.Fprintln(os.Stderr, "  node-check -o output.yaml sub1.txt sub2.txt")
		fmt.Fprintln(os.Stderr, "  node-check -type ss,vmess node.txt")
		fmt.Fprintln(os.Stderr, "  node-check -exclude-type hysteria2 -parallel 50 node.txt")
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
	ipwhoURL       = "https://ipwho.is/"
	testTimeout    = 5 * time.Second
	ipinfoTimeout  = 10 * time.Second
	ipwhoTimeout   = 10 * time.Second
	cacheTTL       = 24 * time.Hour
)

// ProxySchema mirrors the internal schema for parsing
type ProxySchema struct {
	Proxies []map[string]any `yaml:"proxies"`
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
	Config       map[string]any
	// configHash caches the hash of config (excluding name) for deduplication
	configHash string
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
	flag.Parse()

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
		out = strings.TrimSuffix(inputFiles[0], filepath.Ext(inputFiles[0])) + "-checked.yaml"
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
	var allMappings []map[string]any

	if len(allProviderURLs) > 0 {
		fmt.Println("=== Phase 2: Fetching subscriptions ===")
		if *parallelFetch > 1 {
			allMappings = fetchProxiesParallel(ctx, allProviderURLs, *parallelFetch)
		} else {
			allMappings = fetchProxiesSerial(allProviderURLs)
		}
		fmt.Printf("\nFetched %d proxies from subscriptions\n\n", len(allMappings))
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
			allMappings = append(allMappings, mappings...)
		}
		fmt.Println()
	}

	if len(allMappings) == 0 {
		fmt.Println("No proxies found from any provider")
		os.Exit(1)
	}

	// Deduplicate by config hash (not by name)
	// This keeps nodes with same name but different configs
	seen := make(map[string]struct{})
	var uniqueMappings []map[string]any
	for _, m := range allMappings {
		// Compute hash excluding name field
		hash := computeConfigHash(m)
		if hash == "" {
			// If hash computation fails, fallback to name-based dedup
			name, _ := m["name"].(string)
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			uniqueMappings = append(uniqueMappings, m)
			continue
		}
		if _, ok := seen[hash]; ok {
			continue // Skip same config
		}
		seen[hash] = struct{}{}
		uniqueMappings = append(uniqueMappings, m)
	}

	fmt.Printf("\nTotal unique proxies: %d\n\n", len(uniqueMappings))

	// Parse proxies
	proxies := make([]C.Proxy, 0, len(uniqueMappings))
	var proxyConfigs []map[string]any
	var names []string

	filterTypes := parseTypeList(*filterType)
	excludeTypes := parseTypeList(*excludeType)

	if len(filterTypes) > 0 && len(excludeTypes) > 0 {
		fmt.Println("Error: cannot use -type and -exclude-type together")
		os.Exit(1)
	}

	if len(filterTypes) > 0 {
		fmt.Printf("Filtering by types: %v\n\n", filterTypes)
	} else if len(excludeTypes) > 0 {
		fmt.Printf("Excluding types: %v\n\n", excludeTypes)
	}

	for i, mapping := range uniqueMappings {
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
		names = append(names, name)
	}

	fmt.Printf("Parsed %d proxies\n\n", len(proxies))

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
	fmt.Println("\n")

	if len(validResults) == 0 {
		fmt.Println("No valid IP lookups")
		os.Exit(0)
	}

	// Phase 3: Write output
	if err := writeYAML(validResults, out); err != nil {
		fmt.Printf("Failed to write output: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Written %d proxies to %s\n", len(validResults), out)
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
func fetchProxiesSerial(providerURLs []string) []map[string]any {
	var allMappings []map[string]any
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
		allMappings = append(allMappings, mappings...)
	}
	return allMappings
}

// fetchProxiesParallel fetches subscriptions concurrently with limited workers
func fetchProxiesParallel(ctx context.Context, providerURLs []string, workers int) []map[string]any {
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
	var allMappings []map[string]any
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
		allMappings = append(allMappings, res.mappings...)
		mu.Unlock()
	}

	return allMappings
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
	At  time.Time          `json:"at"`
	URL string             `json:"url"`
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

// IPWhoResponse is the response from ipwho.is (fallback)
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

// queryIPInfo queries ipinfo.io through the proxy, with ipwho.is as fallback
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
			info.configHash = computeConfigHash(config)
			return info
		}
	}

	// Fallback to ipwho.is
	testCtx2, testCancel2 := context.WithTimeout(ctx, ipwhoTimeout)
	defer testCancel2()

	respBody, err = dialThroughProxy(testCtx2, proxy, ipwhoURL)
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

// writeYAML writes the results in proxy-provider YAML format
func writeYAML(results []NodeInfo, path string) error {
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
