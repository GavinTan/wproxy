package main

import (
	"crypto/tls"
	"encoding/base64"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

type config struct {
	Addr   string // 监听地址
	Port   string // 监听端口
	Auth   string // 认证账号密码
	TProxy bool   // 透明代理模式
	Debug  bool   // 调试模式
}

var Cfg config

func handleTunneling(w http.ResponseWriter, r *http.Request) {
	if Cfg.Debug {
		log.Printf("Received request %s %s %s\n", r.Method, r.Host, r.RemoteAddr)
	}

	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
	go transfer(destConn, clientConn)
	go transfer(clientConn, destConn)
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func handleHTTP(w http.ResponseWriter, req *http.Request) {
	if Cfg.Debug {
		log.Printf("Received request %s %s %s\n", req.Method, req.Host, req.RemoteAddr)
	}

	if Cfg.TProxy {
		if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
			if v, ok := req.Header["X-Forwarded-For"]; ok {
				clientIP = strings.Join(v, ", ") + ", " + clientIP
			}
			req.Header.Set("X-Forwarded-For", clientIP)
		}
	}

	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func checkAuth(auth string) bool {
	c := strings.SplitN(auth, " ", 2)
	if len(c) != 2 || c[0] != "Basic" {
		return false
	}
	payload, err := base64.StdEncoding.DecodeString(c[1])
	if err != nil {
		return false
	}

	return string(payload) == Cfg.Auth
}

func init() {
	flag.StringVar(&Cfg.Addr, "addr", "0.0.0.0", "监听地址")
	flag.StringVar(&Cfg.Port, "port", "8888", "监听端口")
	flag.StringVar(&Cfg.Auth, "a", "", "启用认证，用户名:密码 (tt:123)")
	flag.BoolVar(&Cfg.TProxy, "tproxy", false, "透明代理模式 (能获取真实客户端IP)")
	flag.BoolVar(&Cfg.Debug, "debug", false, "调试模式显示更多信息")
	flag.Parse()
}

func main() {
	server := &http.Server{
		Addr: Cfg.Addr + ":" + Cfg.Port,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Authorization
			if Cfg.Auth != "" {
				auth := r.Header.Get("Proxy-Authorization")
				if auth == "" || !checkAuth(auth) {
					w.Header().Set("Proxy-Authenticate", `Basic realm="WProxy Basic Authentication"`)
					http.Error(w, "Authorization required", http.StatusProxyAuthRequired)
					return
				}
			}

			if r.Method == http.MethodConnect {
				handleTunneling(w, r)
			} else {
				handleHTTP(w, r)
			}

		}),
		// Disable HTTP/2.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	log.Printf("WProxy is runing on %s:%s\n", Cfg.Addr, Cfg.Port)
	log.Fatal(server.ListenAndServe())
}
