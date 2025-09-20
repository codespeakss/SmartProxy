package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
)

// 匹配规则
var proxyRules = []string{
	"google.com",
	"*.google.com",
	"chatgpt.com",
	"*.chatgpt.com",
}

func shouldProxy(host string) bool {
	// 只取域名部分 (去掉端口)
	h := host
	if strings.Contains(host, ":") {
		h = strings.Split(host, ":")[0]
	}
	for _, rule := range proxyRules {
		match, _ := path.Match(rule, h)
		if match {
			log.Printf("[PROXY]  host=[%80s] FORWARD ↪️  rule=[%30s]", host, rule)
			return true
		}
	}
	log.Printf("[DIRECT] host=[%80s] DIRECT  🔗", host)
	return false
}

// HTTPS 隧道处理
func handleTunneling(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	var destConn net.Conn
	var err error

	if shouldProxy(host) {
		// 建立到上游代理的 TCP 连接
		destConn, err = net.Dial("tcp", "127.0.0.1:7890")
		if err == nil {
			// 把 CONNECT 请求转发给上游代理
			_, err = destConn.Write([]byte("CONNECT " + host + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n"))
			if err == nil {
				// 读取上游代理响应
				buf := make([]byte, 1024)
				n, _ := destConn.Read(buf)
				if !strings.Contains(string(buf[:n]), "200") {
					err = fmt.Errorf("upstream proxy refused: %s", string(buf[:n]))
				}
			}
		}
	} else {
		// 直接连接目标
		destConn, err = net.Dial("tcp", host)
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// hijack 客户端连接
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

	// 通知客户端建立隧道成功
	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// 双向转发
	go transfer(destConn, clientConn)
	go transfer(clientConn, destConn)
}

// 数据转发
func transfer(destination net.Conn, source net.Conn) {
	defer destination.Close()
	defer source.Close()
	_, _ = io.Copy(destination, source)
}

// HTTP 请求处理
func handleHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Hostname()
	if shouldProxy(host) {
		// 使用上游代理
		proxyURL, _ := url.Parse("http://127.0.0.1:7890")
		transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
		proxy := httputil.NewSingleHostReverseProxy(r.URL)
		proxy.Transport = transport
		proxy.ServeHTTP(w, r)
	} else {
		// DIRECT 转发
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

func main() {
	frontPort := ":7895"
	server := &http.Server{
		Addr: frontPort,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleTunneling(w, r)
			} else {
				handleHTTP(w, r)
			}
		}),
	}

	log.Println("Starting proxy server on ", frontPort)
	log.Fatal(server.ListenAndServe())
}
