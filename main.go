package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
)

// 代理名单
var proxyRules = map[string][]string{
	"down": {},
	"WORK": {
		"google.com",
		"*.google.com",
		"chatgpt.com",
		"github.com",
	},
	"work": {
		"google.com",
		"*.google.com",
		"chatgpt.com",
	},
	"fun": {
		"google.com",
		"*.google.com",
		"chatgpt.com",

		"youtube.com",
		"*.youtube.com",
		"*.ytimg.com",
		"*.googlevideo.com",

		"iyf.tv",
		"www.iyf.tv",
		"static.iyf.tv",
		"rankv21.iyf.tv",
		"m10.iyf.tv",
	},
	"FUN": {
		"google.com",
		"*.google.com",
		"chatgpt.com",

		"youtube.com",
		"*.youtube.com",
		".ytimg.com",
		"*.googlevideo.com",

		"iyf.tv",
		"www.iyf.tv",
		"static.iyf.tv",
		"rankv21.iyf.tv",
		"m10.iyf.tv",
		"s*-e1.etc*.xyz",
	},
}

// 拦截名单
var blocklist = []string{
	"brave.com",
	"*.brave.com",
	".bravesoftware.com",

	"mtalk.google.com",
	"*.googleapis.com",
}

// 当前模式，默认工作模式
var currentMode = "work"
var mu sync.RWMutex

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

func main() {
	frontAddr := ":7895"
	upstreamAddr := "127.0.0.1:7890"

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
