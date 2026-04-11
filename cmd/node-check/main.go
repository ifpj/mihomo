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

// preferredKeyOrder defines the desired order of YAML fields in each proxy entry.
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
	defaultTestURL  = "https://www.gstatic.com/generate_204"
	ipwhoURL        = "https://ipwho.is/"
	testTimeout     = 5 * time.Second
	testConcurrency = 20
	ipwhoTimeout    = 10 * time.Second
	cacheTTL        = 24 * time.Hour
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

	// Read input file
	nodeFile := flag.String("i", "node.txt", "input file containing provider URLs or proxy data")
	outputFile := flag.String("o", "", "output YAML file (default: <input>-checked.yaml)")
	localMode := flag.Bool("local", false, "treat input file as proxy data directly (YAML or v2ray share links)")
	parallelFetch := flag.Int("parallel", 1, "number of parallel fetch workers for downloading subscriptions (default: 1, serial)")
	flag.Parse()

	// Derive output filename from input if not specified
	out := *outputFile
	if out == "" {
		out = strings.TrimSuffix(*nodeFile, filepath.Ext(*nodeFile)) + "-checked.yaml"
	}

	// Fetch and parse all proxies
	var allMappings []map[string]any
	if *localMode {
		// Read local proxy file directly
		body, err := os.ReadFile(*nodeFile)
		if err != nil {
			fmt.Printf("Failed to read %s: %v\n", *nodeFile, err)
			os.Exit(1)
		}
		fmt.Printf("Reading local file %s ... ", *nodeFile)
		mappings, err := parseProxies(body)
		if err != nil {
			fmt.Printf("FAILED: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("OK (%d proxies)\n", len(mappings))
		allMappings = append(allMappings, mappings...)
	} else {
		providerURLs := readProviderURLs(*nodeFile)
		if len(providerURLs) == 0 {
			fmt.Println("No provider URLs found in", *nodeFile)
			os.Exit(1)
		}

		fmt.Printf("Found %d provider URLs\n", len(providerURLs))

		// Fetch and parse all proxies from all provider URLs
		if *parallelFetch > 1 {
			allMappings = fetchProxiesParallel(ctx, providerURLs, *parallelFetch)
		} else {
			allMappings = fetchProxiesSerial(providerURLs)
		}
	}

	if len(allMappings) == 0 {
		fmt.Println("No proxies found from any provider")
		os.Exit(1)
	}

	// Deduplicate by name
	seen := make(map[string]struct{})
	var uniqueMappings []map[string]any
	for _, m := range allMappings {
		name, _ := m["name"].(string)
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		uniqueMappings = append(uniqueMappings, m)
	}

	fmt.Printf("\nTotal unique proxies: %d\n\n", len(uniqueMappings))

	// Parse proxies
	proxies := make([]C.Proxy, 0, len(uniqueMappings))
	var proxyConfigs []map[string]any
	var names []string

	for i, mapping := range uniqueMappings {
		name, _ := mapping["name"].(string)
		if name == "" {
			name = fmt.Sprintf("proxy-%d", i)
			mapping["name"] = name
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
	aliveIndices := testConnectivity(ctx, proxies, names)
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
	sem := make(chan struct{}, testConcurrency)
	var doneCount atomic.Int32

	for _, idx := range aliveIndices {
		wg.Add(1)
		sem <- struct{}{}
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

	fmt.Printf("Valid lookups: %d / %d\n\n", len(validResults), len(results))

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

// readProviderURLs reads the node-hk file and extracts HTTP URLs
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
					resultChan <- result{url: u, err: ctx.Err()}
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
			urlChan <- u
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
func testConnectivity(ctx context.Context, proxies []C.Proxy, names []string) []int {
	var aliveIndices []int
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, testConcurrency)
	var doneCount atomic.Int32
	total := len(proxies)

	for i, p := range proxies {
		wg.Add(1)
		sem <- struct{}{}
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

	wg.Wait()
	return aliveIndices
}

// IPWhoResponse is the response from ipwho.is
type IPWhoResponse struct {
	IP         string `json:"ip"`
	Success    bool   `json:"success"`
	Type       string `json:"type"`
	Continent  string `json:"continent"`
	ContinentCode string `json:"continent_code"`
	Country    string `json:"country"`
	CountryCode string `json:"country_code"`
	Region     string `json:"region"`
	City       string `json:"city"`
	ISP        string `json:"connection",omitempty"`
	ORG        string `json:"org"`
	ASN        int    `json:"asn"`
	Domain     string `json:"domain"`
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
	IP           string            `json:"ip"`
	Success      bool              `json:"success"`
	Type         string            `json:"type"`
	Continent    string            `json:"continent"`
	Country      string            `json:"country"`
	CountryCode  string            `json:"country_code"`
	Region       string            `json:"region"`
	City         string            `json:"city"`
	Connection   IPWhoConnection   `json:"connection"`
}

// queryIPInfo queries ipwho.is through the proxy
func queryIPInfo(ctx context.Context, proxy C.Proxy, name string, config map[string]any) NodeInfo {
	info := NodeInfo{
		OriginalName: name,
		Config:       config,
	}

	testCtx, testCancel := context.WithTimeout(ctx, ipwhoTimeout)
	defer testCancel()

	// Try to get IP through the proxy by making a request
	respBody, err := dialThroughProxy(testCtx, proxy)
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

	return info
}

// dialThroughProxy makes a request through the proxy to get IP info
func dialThroughProxy(ctx context.Context, proxy C.Proxy) ([]byte, error) {
	u, err := url.Parse(ipwhoURL)
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ipwhoURL, nil)
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
