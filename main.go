package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ANSI 颜色
const (
	colorReset  = "\033[0m"
	colorHeader = "\033[35m" // magenta
	colorBranch = "\033[90m" // bright black (gray)
	colorFile   = "\033[36m" // cyan
	colorDomain = "\033[32m" // green
	colorCount  = "\033[90m" // gray
)

// 代理白名单 （各个分场景均生效）
var whitelist = []string{}

// 拦截名单
var blocklist = []string{
	"*analy*.wikimedia.org",

	"brave.com",
	"*.brave.com",
	".bravesoftware.com",
	"*.mozilla.org",

	"mtalk.google.com",
	"*.googleapis.com",

	"browser-intake-datadoghq.com",
	"*.browser-intake-datadoghq.com",
}

// 不同模式下的代理名单
var proxyRules = map[string][]string{
	"down": {},
	"WORK": {},
	"work": {},
	"fun":  {},
	"FUN": {
		"s*-e*.*.*",
	},
}

// 当前模式，默认工作模式
var currentMode = "work"
var mu sync.RWMutex

// 初始化：从程序所在目录（递归）加载所有以 .whitelist 结尾的文件，
// 将其中的域名作为 whitelist 的内容（若找到则覆盖默认值；若未找到则保留默认值）。
func init() {
	exe, err := os.Executable()
	if err != nil {
		log.Printf("init: cannot determine executable path: %v", err)
		return
	}
	baseDir := filepath.Dir(exe)

	var files []string
	// 递归遍历，搜集所有 .whitelist 文件
	_ = filepath.Walk(baseDir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			// 忽略单个路径错误，继续遍历
			return nil
		}
		if info == nil || info.IsDir() {
			return nil
		}
		if strings.HasSuffix(info.Name(), ".whitelist") {
			files = append(files, p)
		}
		return nil
	})

	if len(files) == 0 {
		log.Printf("init: no .whitelist files found under %s, keeping built-in whitelist (%d entries)", baseDir, len(whitelist))
		return
	}

	// 读取文件中的域名，去重与清洗
	unique := make(map[string]struct{})
	// 记录每个域名来源的 whitelist 文件名（去重）
	domainSources := make(map[string]map[string]struct{})
	total := 0
	for _, fp := range files {
		f, err := os.Open(fp)
		if err != nil {
			log.Printf("init: failed to open %s: %v", fp, err)
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			// 去除行内注释（# 或 //）
			if idx := strings.Index(line, "#"); idx >= 0 {
				line = strings.TrimSpace(line[:idx])
			}
			if idx := strings.Index(line, "//"); idx >= 0 {
				line = strings.TrimSpace(line[:idx])
			}
			if line == "" {
				continue
			}
			if _, ok := unique[line]; !ok {
				unique[line] = struct{}{}
				total++
			}
			// 记录来源文件名
			bn := filepath.Base(fp)
			if domainSources[line] == nil {
				domainSources[line] = make(map[string]struct{})
			}
			domainSources[line][bn] = struct{}{}
		}
		if err := scanner.Err(); err != nil {
			log.Printf("init: read error in %s: %v", fp, err)
		}
		_ = f.Close()
	}

	if total > 0 {
		// 覆盖内置白名单
		whitelist = whitelist[:0]
		for k := range unique {
			whitelist = append(whitelist, k)
		}
		log.Printf("init: loaded %d whitelist entries from %d file(s) under %s", len(whitelist), len(files), baseDir)
	} else {
		log.Printf("init: .whitelist files found but no valid entries; keeping built-in whitelist (%d entries)", len(whitelist))
	}

	// 打印已加载的域名列表（树形结构：文件 -> 域名）
	if len(whitelist) > 0 {
		// 构建 文件名 -> 域名列表 的映射
		fileToDomains := make(map[string][]string)
		for domain, srcSet := range domainSources {
			for src := range srcSet {
				fileToDomains[src] = append(fileToDomains[src], domain)
			}
		}

		// 为了稳定输出，对文件名和域名排序
		var filesSorted []string
		for fn := range fileToDomains {
			filesSorted = append(filesSorted, fn)
		}
		sort.Strings(filesSorted)

		// 统计总数
		totalDomains := 0
		for _, ds := range fileToDomains {
			totalDomains += len(ds)
		}

		log.Printf("%sload: whitelist entries by file%s (%s%d files%s, %s%d domains%s):", colorHeader, colorReset, colorCount, len(filesSorted), colorReset, colorCount, totalDomains, colorReset)
		for i, fn := range filesSorted {
			ds := fileToDomains[fn]
			sort.Strings(ds)
			isLastFile := i == len(filesSorted)-1
			fileBranch := "├──"
			childIndent := "│   "
			if isLastFile {
				fileBranch = "└──"
				childIndent = "    "
			}
			log.Printf("  %s%s%s %s%s%s (%s%d%s)", colorBranch, fileBranch, colorReset, colorFile, fn, colorReset, colorCount, len(ds), colorReset)
			for j, d := range ds {
				isLastDomain := j == len(ds)-1
				domainBranch := "├──"
				if isLastDomain {
					domainBranch = "└──"
				}
				log.Printf("  %s%s%s%s %s%s", childIndent, colorBranch, domainBranch, colorReset, colorDomain, d)
			}
		}
	} else {
		log.Println("lod: whitelist is empty")
	}
}
func isBlocklisted(host string) bool {
	h := host
	if strings.Contains(host, ":") {
		h = strings.Split(host, ":")[0]
	}
	for _, rule := range blocklist {
		match, _ := path.Match(rule, h)
		if match {
			log.Printf("[BLOCK]  host=[%80s] REJECTED ⛔ rule=[%30s]", host, rule)
			return true
		}
	}
	return false
}

func shouldProxy(host string) bool {
	if isBlocklisted(host) {
		return false
	}

	h := host
	if strings.Contains(host, ":") {
		h = strings.Split(host, ":")[0]
	}

	for _, rule := range whitelist {
		match, _ := path.Match(rule, h)
		if match {
			log.Printf("[PROXY]  host=[%80s] FORWARD w↩️  rule=[%30s]", host, rule)
			return true
		}
	}

	mu.RLock()
	rules := proxyRules[currentMode]
	mu.RUnlock()

	for _, rule := range rules {
		match, _ := path.Match(rule, h)
		if match {
			log.Printf("[PROXY]  host=[%80s] FORWARD  ↩️  rule=[%30s]", host, rule)
			return true
		}
	}
	log.Printf("[DIRECT] host=[%80s] DIRECT   🔗", host)
	return false
}

// HTTPS 隧道处理
func handleTunneling(w http.ResponseWriter, r *http.Request, upstreamAddr string) {
	host := r.Host
	if isBlocklisted(host) {
		http.Error(w, "Forbidden by blacklist", http.StatusForbidden)
		return
	}

	var destConn net.Conn
	var err error

	if shouldProxy(host) {
		destConn, err = net.Dial("tcp", upstreamAddr)
		if err == nil {
			_, err = destConn.Write([]byte("CONNECT " + host + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n"))
			if err == nil {
				buf := make([]byte, 1024)
				n, _ := destConn.Read(buf)
				if !strings.Contains(string(buf[:n]), "200") {
					err = fmt.Errorf("upstream proxy refused: %s", string(buf[:n]))
				}
			}
		}
	} else {
		destConn, err = net.Dial("tcp", host)
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	go transfer(destConn, clientConn)
	go transfer(clientConn, destConn)
}

// 数据转发
func transfer(to net.Conn, from net.Conn) {
	defer to.Close()
	defer from.Close()
	_, _ = io.Copy(to, from)
}

// HTTP 请求处理
func handleHTTP(w http.ResponseWriter, r *http.Request, upstreamAddr string) {
	host := r.URL.Hostname()
	if isBlocklisted(host) {
		http.Error(w, "Forbidden by blacklist", http.StatusForbidden)
		return
	}

	if shouldProxy(host) {
		proxyURL, _ := url.Parse(fmt.Sprintf("http://%s", upstreamAddr))
		transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
		proxy := httputil.NewSingleHostReverseProxy(r.URL)
		proxy.Transport = transport
		proxy.ServeHTTP(w, r)
	} else {
		transport := &http.Transport{}
		resp, err := transport.RoundTrip(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		defer resp.Body.Close()
		copyHeader(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}
}

// 复制 Header
func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// 快捷键监听
func watchKeys() {
	reader := bufio.NewReader(os.Stdin)
	for {
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if input == "d" {
			mu.Lock()
			currentMode = "down"
			mu.Unlock()
			log.Println(" 🌱 [Switched to down mode]")
		} else if input == "w" {
			mu.Lock()
			currentMode = "work"
			mu.Unlock()
			log.Println(" 💼 [Switched to work mode]")
		} else if input == "W" {
			mu.Lock()
			currentMode = "WORK"
			mu.Unlock()
			log.Println(" 💼 [Switched to WORK mode]")
		} else if input == "f" {
			mu.Lock()
			currentMode = "fun"
			mu.Unlock()
			log.Println(" 🎬 [Switched to fun mode]")
		} else if input == "F" {
			mu.Lock()
			currentMode = "FUN"
			mu.Unlock()
			log.Println(" 🎬 [Switched to FUN mode]")
		}
	}
}

// 在启动时检测上游 HTTP 代理是否可用
func checkUpstream(upstreamAddr string) error {
    // 1) TCP 直连探测
    conn, err := net.DialTimeout("tcp", upstreamAddr, 2*time.Second)
    if err != nil {
        return fmt.Errorf("tcp dial failed: %w", err)
    }
    defer conn.Close()

    // 2) 发送最小化的 HTTP 代理请求并验证响应首行
    // 使用 HEAD 到 http://example.com，符合 HTTP 代理语义
    _ = conn.SetDeadline(time.Now().Add(2 * time.Second))
    _, err = conn.Write([]byte("HEAD http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"))
    if err != nil {
        return fmt.Errorf("write probe failed: %w", err)
    }

    buf := make([]byte, 1024)
    n, err := conn.Read(buf)
    if err != nil {
        return fmt.Errorf("read probe failed: %w", err)
    }
    line := string(buf[:n])
    if !strings.HasPrefix(line, "HTTP/") {
        return fmt.Errorf("unexpected upstream response: %q", line)
    }
    return nil
}

func waitForUpstream(upstreamAddr string, retries int, delay time.Duration) error {
    var err error
    for i := 0; i < retries; i++ {
        if i > 0 {
            time.Sleep(delay)
        }
        if err = checkUpstream(upstreamAddr); err == nil {
            return nil
        }
        log.Printf("upstream check failed (attempt %d/%d): %v", i+1, retries, err)
    }
    return err
}

// 配置结构与加载逻辑
type Config struct {
    UpstreamAddr string `json:"upstreamAddr"`
    FrontAddr    string `json:"frontAddr"`
}

// loadConfig 会从以下位置加载配置（优先级从高到低）：
// 1) 环境变量 SMARTPROXY_CONFIG 指定的路径
// 2) 可执行文件同目录下的 smartproxy.json
// 若都不存在或解析失败，则使用内置默认值。
func loadConfig() (frontAddr, upstreamAddr string) {
    // 默认值
    frontAddr = ":7895"
    upstreamAddr = "127.0.0.1:7890"

    var paths []string
    if p := os.Getenv("SMARTPROXY_CONFIG"); p != "" {
        paths = append(paths, p)
    }
    if exe, err := os.Executable(); err == nil {
        exeDir := filepath.Dir(exe)
        paths = append(paths, filepath.Join(exeDir, "smartproxy.json"))
    }

    var used string
    for _, p := range paths {
        // 只尝试存在的文件
        if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
            b, err := os.ReadFile(p)
            if err != nil {
                log.Printf("config: failed reading %s: %v", p, err)
                continue
            }
            var cfg Config
            if err := json.Unmarshal(b, &cfg); err != nil {
                log.Printf("config: failed parsing %s: %v", p, err)
                continue
            }
            if cfg.FrontAddr != "" {
                frontAddr = cfg.FrontAddr
            }
            if cfg.UpstreamAddr != "" {
                upstreamAddr = cfg.UpstreamAddr
            }
            used = p
            break
        }
    }

    if used != "" {
        log.Printf("config: loaded from %s (frontAddr=%s, upstreamAddr=%s)", used, frontAddr, upstreamAddr)
    } else {
        log.Printf("config: using defaults (frontAddr=%s, upstreamAddr=%s)", frontAddr, upstreamAddr)
    }
    return
}

func main() {
	frontAddr, upstreamAddr := loadConfig()
	log.Println("upstreamAddr: ", upstreamAddr)

	// 启动前检查上游代理是否可用（重试 3 次，每次间隔 1.5s）
	if err := waitForUpstream(upstreamAddr, 3, 1500*time.Millisecond); err != nil {
		log.Fatalf("Upstream %s not available: %v", upstreamAddr, err)
	}

	go watchKeys() // 启动快捷键监听

	server := &http.Server{
		Addr: frontAddr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleTunneling(w, r, upstreamAddr)
			} else {
				handleHTTP(w, r, upstreamAddr)
			}
		}),
	}

	log.Println("Starting proxy server on ", frontAddr)
	log.Println("Default mode: [work] (press 「d W w f F」 to switch mode)")
	log.Fatal(server.ListenAndServe())
}
