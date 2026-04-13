package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/metacubex/mihomo/common/convert"
	mihomoyaml "github.com/metacubex/mihomo/common/yaml"
)

const (
	maxFileSize      = 50 * 1024 // 50KB
	maxFilesPerURL   = 100       // 每个URL最多检查文件数
	maxWorkersPerURL = 5         // 每个URL并发数
)

// 文件后缀优先级（小写），顺序越靠前优先级越高
var extPriority = []string{".yaml", ".yml", ".txt", ".conf", ".json", ".ini"}

// 明显不是订阅的后缀，直接跳过
var skipExts = []string{
	".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg", ".ico",
	".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".webm",
	".mp3", ".wav", ".flac", ".aac", ".ogg", ".wma",
	".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".tgz", ".tbz2", ".txz",
	".exe", ".dll", ".so", ".dylib", ".bin",
	".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
	".ttf", ".otf", ".woff", ".woff2",
	".css", ".js", ".map",
}

// 订阅关键词（用于排序），匹配越多优先级越高
var subKeywords = []string{
	"clash", "v2ray", "v2", "proxy", "proxies", "node", "nodes",
	"sub", "subscription", "机场", "订阅", "ss", "vmess", "trojan",
}

// ProxySchema 与 node-check 保持一致
type ProxySchema struct {
	Proxies []map[string]any `yaml:"proxies"`
}

// URLResult 单个URL的处理结果
type URLResult struct {
	Index      int
	URL        string
	SubURLs    []string
	Error      error
	Checked    int
	Found      int
	SkipSize   int
	SkipExt    int
	Fail       int
}

func main() {
	var (
		urlFile    = flag.String("f", "", "包含URL列表的文件")
		outputFile = flag.String("o", "subscriptions.txt", "订阅链接输出文件")
		workers    = flag.Int("workers", 5, "每个URL的并发数")
	)
	flag.Parse()

	var targetURLs []string

	if *urlFile != "" {
		urls, err := readURLsFromFile(*urlFile)
		if err != nil {
			fmt.Printf("读取URL文件失败: %v\n", err)
			os.Exit(1)
		}
		targetURLs = urls
	}

	if flag.NArg() > 0 {
		targetURLs = append(targetURLs, flag.Args()...)
	}

	if len(targetURLs) == 0 {
		fmt.Println("用法: dir-crawler -f urls.txt [-o subscriptions.txt]")
		fmt.Println("   或: dir-crawler http://example.com/path1/ http://example.com/path2/ [-o subscriptions.txt]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	fmt.Printf("目标URL数量: %d\n", len(targetURLs))
	fmt.Printf("同时并行URL数: 100\n")
	fmt.Printf("每个URL并发数: %d\n", *workers)
	fmt.Printf("大小限制: 50KB\n")
	fmt.Printf("订阅输出: %s\n\n", *outputFile)

	// 结果channel
	resultChan := make(chan URLResult, len(targetURLs))

	// 使用信号量控制同时处理的URL数量（100个）
	urlSem := make(chan struct{}, 100)

	// 启动任务调度器
	go func() {
		for i, targetURL := range targetURLs {
			urlSem <- struct{}{} // 获取信号量（最多100个并发）

			go func(index int, url string) {
				result := processURL(index, url, *workers)
				resultChan <- result
				<-urlSem // 释放信号量
			}(i, targetURL)
		}
	}()

	// 创建输出文件（用于实时写入）
	outFile, err := os.Create(*outputFile)
	if err != nil {
		fmt.Printf("创建输出文件失败: %v\n", err)
		os.Exit(1)
	}
	defer outFile.Close()

	// 使用互斥锁保护文件写入
	var writeMu sync.Mutex
	var totalSubCount int

	// 收集结果
	completed := 0
	total := len(targetURLs)

	for completed < total {
		result := <-resultChan
		completed++

		fmt.Printf("========== [%d/%d] %s ==========\n", result.Index+1, total, result.URL)
		if result.Error != nil {
			fmt.Printf("  错误: %v\n", result.Error)
		} else if len(result.SubURLs) > 0 {
			for _, sub := range result.SubURLs {
				fmt.Printf("  ✓ %s\n", sub)

				// 实时写入文件
				writeMu.Lock()
				outFile.WriteString(sub + "\n")
				outFile.Sync() // 立即刷盘
				totalSubCount++
				writeMu.Unlock()
			}
		} else {
			fmt.Printf("  ✗ 未找到订阅\n")
		}
		fmt.Printf("  统计: 检查%d, 订阅%d, 跳过(过大)%d, 跳过后缀%d, 失败%d\n\n",
			result.Checked, result.Found, result.SkipSize, result.SkipExt, result.Fail)
	}

	fmt.Printf("========== 最终结果 ==========\n")
	fmt.Printf("已实时写入 %d 个订阅链接到 %s\n", totalSubCount, *outputFile)
	if totalSubCount > 0 {
		fmt.Printf("\n下一步: node-check -o output.yaml %s\n", *outputFile)
	} else {
		fmt.Println("未找到任何订阅链接")
	}
}

// readURLsFromFile 从文件读取URL列表
func readURLsFromFile(filename string) ([]string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var urls []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		urls = append(urls, line)
	}

	return urls, scanner.Err()
}

// processURLAsync 异步处理单个URL
func processURLAsync(index int, targetURL string, workers int, resultChan chan<- URLResult, startSignal <-chan struct{}) {
	// 等待启动信号（如果有）
	if startSignal != nil {
		<-startSignal
	}

	result := processURL(index, targetURL, workers)
	resultChan <- result
}

// processURL 处理单个URL（带2分钟整体超时）
func processURL(index int, targetURL string, workers int) URLResult {
	result := URLResult{Index: index, URL: targetURL}

	// 创建整体超时context（2分钟）
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// 首先尝试直接获取根目录内容
	content, err := fetchContentWithContext(ctx, targetURL, maxFileSize)
	if err == nil {
		if proxies, err := parseProxies(content); err == nil && len(proxies) > 0 {
			result.SubURLs = append(result.SubURLs, targetURL)
			result.Checked = 1
			result.Found = 1
			return result
		}
	}

	// 根目录不是订阅，获取文件列表（限制最多10000个，防止内存溢出）
	files, err := listFilesLimited(targetURL, 10000)
	if err != nil {
		result.Error = err
		return result
	}

	if len(files) == 0 {
		return result
	}

	// 限制文件数量
	if len(files) > maxFilesPerURL {
		files = files[:maxFilesPerURL]
	}

	// 过滤和排序
	var filteredFiles []FileInfo
	for _, f := range files {
		if shouldSkipExt(f.Name) {
			result.SkipExt++
			continue
		}
		filteredFiles = append(filteredFiles, f)
	}
	filteredFiles = sortByPriority(filteredFiles)

	if len(filteredFiles) == 0 {
		return result
	}

	// 创建可取消的context
	ctx2, cancel2 := context.WithCancel(ctx)
	defer cancel2()

	foundSub := atomic.Bool{}

	// 启动文件处理
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)

	var mu sync.Mutex
	checkedCnt := 0
	skipSizeCnt := 0
	failCnt := 0

	for _, file := range filteredFiles {
		// 检查是否已找到订阅或超时
		select {
		case <-ctx2.Done():
			break
		default:
		}

		if foundSub.Load() {
			break
		}

		wg.Add(1)

		go func(f FileInfo) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx2.Done():
				return
			}

			if foundSub.Load() {
				return
			}

			mu.Lock()
			checkedCnt++
			mu.Unlock()

			// 预检查大小
			if f.Size > 0 && f.Size > maxFileSize {
				mu.Lock()
				skipSizeCnt++
				mu.Unlock()
				return
			}

			// 获取内容（带context）
			content, err := fetchContentWithContext(ctx2, f.URL, maxFileSize)
			if err != nil {
				mu.Lock()
				if strings.Contains(err.Error(), "大小超过限制") {
					skipSizeCnt++
				} else {
					failCnt++
				}
				mu.Unlock()
				return
			}

			// 解析
			if proxies, err := parseProxies(content); err == nil && len(proxies) > 0 {
				mu.Lock()
				result.SubURLs = append(result.SubURLs, f.URL)
				mu.Unlock()

				foundSub.Store(true)
				cancel2()
			}
		}(file)
	}

	wg.Wait()

	result.Checked = checkedCnt
	result.Found = len(result.SubURLs)
	result.SkipSize = skipSizeCnt
	result.Fail = failCnt

	return result
}

// shouldSkipExt 检查是否应该跳过后缀
func shouldSkipExt(filename string) bool {
	lower := strings.ToLower(filename)
	for _, ext := range skipExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// getExtPriority 获取后缀优先级
func getExtPriority(filename string) int {
	lower := strings.ToLower(filename)
	for i, ext := range extPriority {
		if strings.HasSuffix(lower, ext) {
			return i
		}
	}
	return len(extPriority)
}

// countKeywords 统计匹配的关键词数量
func countKeywords(s string) int {
	lower := strings.ToLower(s)
	count := 0
	for _, kw := range subKeywords {
		if strings.Contains(lower, kw) {
			count++
		}
	}
	return count
}

// sortByPriority 按优先级排序文件
func sortByPriority(files []FileInfo) []FileInfo {
	result := make([]FileInfo, len(files))
	copy(result, files)

	for i := 0; i < len(result); i++ {
		for j := i + 1; j < len(result); j++ {
			pi, pj := getExtPriority(result[i].Name), getExtPriority(result[j].Name)
			if pi != pj {
				if pi > pj {
					result[i], result[j] = result[j], result[i]
				}
				continue
			}
			ci, cj := countKeywords(result[i].Name), countKeywords(result[j].Name)
			if ci < cj {
				result[i], result[j] = result[j], result[i]
			}
		}
	}

	return result
}

// parseProxies 与 node-check 完全相同的解析逻辑
func parseProxies(body []byte) ([]map[string]any, error) {
	var schema ProxySchema
	if err := mihomoyaml.Unmarshal(body, &schema); err == nil && len(schema.Proxies) > 0 {
		return schema.Proxies, nil
	}
	return convert.ConvertsV2Ray(body)
}

// FileInfo 文件信息
type FileInfo struct {
	Name string
	URL  string
	Size int64
}

// listFilesLimited 只获取一级目录的文件（限制数量）
func listFilesLimited(baseURL string, maxFiles int) ([]FileInfo, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Get(baseURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, err
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	var files []FileInfo
	count := 0

	doc.Find("a").Each(func(i int, s *goquery.Selection) {
		if count >= maxFiles {
			return
		}

		href, ok := s.Attr("href")
		if !ok {
			return
		}

		if href == "../" || href == "./" || href == "/" ||
			strings.HasPrefix(href, "?C=") || strings.HasPrefix(href, "?O=") {
			return
		}

		href, _ = url.QueryUnescape(href)

		if strings.HasSuffix(href, "/") {
			return
		}

		cleanHref := strings.TrimPrefix(href, "/")
		if strings.Contains(cleanHref, "/") {
			return
		}

		fileURL, err := base.Parse(href)
		if err != nil {
			return
		}

		if fileURL.Host != base.Host {
			return
		}

		filename := path.Base(cleanHref)
		if filename == "" || filename == "." {
			return
		}

		size := extractSize(s)

		files = append(files, FileInfo{
			Name: filename,
			URL:  fileURL.String(),
			Size: size,
		})
		count++
	})

	return files, nil
}

// extractSize 从HTML提取文件大小
func extractSize(s *goquery.Selection) int64 {
	parent := s.Parent()
	if parent.Is("td") {
		sizeText := parent.Next().Text()
		if sizeText != "" {
			return parseSizeString(sizeText)
		}
	}
	if title, ok := s.Attr("title"); ok {
		return parseSizeString(title)
	}
	return -1
}

// parseSizeString 解析大小字符串
func parseSizeString(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return -1
	}

	var n int64
	if _, err := fmt.Sscanf(s, "%d", &n); err == nil {
		return n
	}

	s = strings.ToUpper(strings.TrimSpace(s))
	multiplier := int64(1)

	switch {
	case strings.HasSuffix(s, "K"):
		multiplier = 1024
		s = strings.TrimSuffix(s, "K")
	case strings.HasSuffix(s, "M"):
		multiplier = 1024 * 1024
		s = strings.TrimSuffix(s, "M")
	case strings.HasSuffix(s, "G"):
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, "G")
	}

	s = strings.TrimSpace(s)
	if f, err := fmt.Sscanf(s, "%f", new(float64)); err == nil && f == 1 {
		var val float64
		fmt.Sscanf(s, "%f", &val)
		return int64(val * float64(multiplier))
	}

	return -1
}

// formatSize 格式化大小
func formatSize(n int64) string {
	if n < 0 {
		return "未知"
	}
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	if n < 1024*1024 {
		return fmt.Sprintf("%.2f KB", float64(n)/1024)
	}
	return fmt.Sprintf("%.2f MB", float64(n)/(1024*1024))
}

// fetchContentWithContext 获取文件内容（支持context）
func fetchContentWithContext(ctx context.Context, fileURL string, maxBytes int) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fileURL, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 10 * time.Second}

	// 尝试 HEAD
	headReq, err := http.NewRequestWithContext(ctx, http.MethodHead, fileURL, nil)
	if err == nil {
		headResp, err := client.Do(headReq)
		if err == nil && headResp.StatusCode == http.StatusOK {
			size := headResp.ContentLength
			headResp.Body.Close()
			if size > int64(maxBytes) {
				return nil, fmt.Errorf("大小超过限制 (%s)", formatSize(size))
			}
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	if resp.ContentLength > int64(maxBytes) {
		return nil, fmt.Errorf("大小超过限制 (%s)", formatSize(resp.ContentLength))
	}

	limitedReader := io.LimitReader(resp.Body, int64(maxBytes)+1)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, err
	}

	if len(data) > maxBytes {
		return nil, fmt.Errorf("大小超过限制")
	}

	return data, nil
}

// fetchContent 获取文件内容
func fetchContent(fileURL string, maxBytes int) ([]byte, error) {
	return fetchContentWithContext(context.Background(), fileURL, maxBytes)
}

// writeSubsToFile 写入订阅链接到文件
func writeSubsToFile(urls []string, filename string) error {
	var buf bytes.Buffer
	for _, u := range urls {
		buf.WriteString(u)
		buf.WriteByte('\n')
	}
	return os.WriteFile(filename, buf.Bytes(), 0644)
}
