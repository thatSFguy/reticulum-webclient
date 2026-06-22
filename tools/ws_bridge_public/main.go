// tools/ws_bridge_public/main.go
//
// Hardened, PUBLIC-FACING WebSocket→TCP bridge for the Reticulum web client.
//
// This is a separate program from tools/ws_bridge.go. That one is the
// convenience bridge for localhost (it dials whatever host:port the client
// asks for — fine on a personal machine, but an open TCP proxy / SSRF relay
// if exposed to the internet). This program is meant to be hosted publicly
// (e.g. on michmesh.net behind a TLS reverse proxy) and is locked down:
//
//   - It NEVER dials a client-chosen arbitrary target. You either pin a
//     single rnsd with -target, or whitelist a fixed set with -allow.
//     With no -target and no -allow it refuses to start — there is no
//     open-proxy mode here, by design.
//   - Global and per-IP concurrent-connection caps.
//   - Optional per-connection total byte cap and idle timeout.
//   - IP/CIDR blocklist file (hot-reloadable with SIGHUP on Unix).
//   - Origin allow-list (defaults to the official web client origin).
//   - Optional shared-secret token.
//   - Inbound WebSocket frame size limit + HTTP header read timeout
//     (slowloris mitigation).
//   - Binds to 127.0.0.1 by default; run it behind Caddy/nginx for TLS
//     (the web client is served over HTTPS, so it can only reach wss://).
//
// Message content is always end-to-end encrypted by the browser; this
// bridge only copies bytes and cannot read, modify, or forge messages.
// These controls protect the HOST, not message confidentiality.
//
// Build (no cgo, cross-compiles like the other bridge):
//   cd tools && go build -trimpath -ldflags="-s -w" -o ws_bridge_public ./ws_bridge_public
//
// Typical michmesh deployment (rnsd local on the same box, TLS via Caddy):
//   ./ws_bridge_public -target 127.0.0.1:4242 -trust-proxy \
//       -max-bytes 209715200 -idle-timeout 15m \
//       -blocklist /etc/ws_bridge/blocklist.txt
//
// See README.md in this directory for the reverse-proxy and systemd setup.

package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

const version = "1.0.0"

// ---- configuration (set from flags in main) ------------------------

var (
	pinnedTarget   string          // -target: dial only this; ignore client host/port
	allowSet       map[string]bool // -allow: permitted client-chosen host:port targets
	maxConns       int64           // -max-conns (0 = unlimited)
	maxConnsPerIP  int             // -max-conns-per-ip (0 = unlimited)
	maxBytes       int64           // -max-bytes per connection (0 = unlimited)
	idleTimeout    time.Duration   // -idle-timeout (0 = off)
	token          string          // -token (empty = no token required)
	trustProxy     bool            // -trust-proxy (use X-Forwarded-For)
	maxFrame       int64           // -max-frame inbound WS bytes (0 = unlimited)
	allowedOrigins map[string]bool // -allowed-origins (exact, lowercased)
	originAny      bool            // -allowed-origins contained "*"
	blocklistPath  string          // -blocklist file path
	dialTimeout    = 10 * time.Second
)

// ---- live state ----------------------------------------------------

var (
	curConns   int64
	totalConns int64
	totalBytes int64

	perIPMu sync.Mutex
	perIP   = map[string]int{}

	blockMu   sync.RWMutex
	blockNets []*net.IPNet
)

var upgrader = websocket.Upgrader{
	CheckOrigin:     checkOrigin,
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
}

func checkOrigin(r *http.Request) bool {
	if originAny {
		return true
	}
	return allowedOrigins[strings.ToLower(strings.TrimSpace(r.Header.Get("Origin")))]
}

// clientIP returns the connecting client's IP. Behind a trusted reverse
// proxy (-trust-proxy) the real client is in X-Forwarded-For/X-Real-IP;
// without that flag those headers are attacker-controlled and ignored.
func clientIP(r *http.Request) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if first := strings.TrimSpace(strings.Split(xff, ",")[0]); first != "" {
				return first
			}
		}
		if xr := strings.TrimSpace(r.Header.Get("X-Real-IP")); xr != "" {
			return xr
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ---- blocklist -----------------------------------------------------

func isBlocked(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	blockMu.RLock()
	defer blockMu.RUnlock()
	for _, n := range blockNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// loadBlocklist parses a file of IPs and CIDRs (one per line; blank lines
// and #-comments ignored) and atomically swaps it in.
func loadBlocklist(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	var nets []*net.IPNet
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, "/") {
			if strings.Contains(line, ":") {
				line += "/128"
			} else {
				line += "/32"
			}
		}
		_, n, err := net.ParseCIDR(line)
		if err != nil {
			log.Printf("blocklist: skipping invalid entry %q: %v", line, err)
			continue
		}
		nets = append(nets, n)
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	blockMu.Lock()
	blockNets = nets
	blockMu.Unlock()
	return len(nets), nil
}

// ---- per-IP connection accounting ----------------------------------

func ipAcquire(ip string) bool {
	perIPMu.Lock()
	defer perIPMu.Unlock()
	if maxConnsPerIP > 0 && perIP[ip] >= maxConnsPerIP {
		return false
	}
	perIP[ip]++
	return true
}

func ipRelease(ip string) {
	perIPMu.Lock()
	defer perIPMu.Unlock()
	if perIP[ip] <= 1 {
		delete(perIP, ip)
	} else {
		perIP[ip]--
	}
}

// resolveTarget decides what to dial. Pinned mode ignores client input;
// allowlist mode requires the client's host:port to be whitelisted.
func resolveTarget(r *http.Request) (string, bool) {
	if pinnedTarget != "" {
		return pinnedTarget, true
	}
	host := r.URL.Query().Get("host")
	port := r.URL.Query().Get("port")
	if host == "" || port == "" {
		return "", false
	}
	target := net.JoinHostPort(host, port)
	if allowSet[strings.ToLower(target)] {
		return target, true
	}
	return "", false
}

// ---- bridge handler ------------------------------------------------

func handleBridge(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)

	if isBlocked(ip) {
		http.Error(w, "forbidden", http.StatusForbidden)
		log.Printf("[%s] rejected: blocklisted", ip)
		return
	}
	if token != "" && r.URL.Query().Get("token") != token {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		log.Printf("[%s] rejected: missing/invalid token", ip)
		return
	}
	target, ok := resolveTarget(r)
	if !ok {
		http.Error(w, "target not permitted", http.StatusForbidden)
		log.Printf("[%s] rejected: target not permitted", ip)
		return
	}

	// Global concurrent-connection cap.
	if n := atomic.AddInt64(&curConns, 1); maxConns > 0 && n > maxConns {
		atomic.AddInt64(&curConns, -1)
		http.Error(w, "server busy", http.StatusServiceUnavailable)
		log.Printf("[%s] rejected: global connection cap (%d) reached", ip, maxConns)
		return
	}
	defer atomic.AddInt64(&curConns, -1)

	// Per-IP concurrent-connection cap.
	if !ipAcquire(ip) {
		http.Error(w, "too many connections", http.StatusTooManyRequests)
		log.Printf("[%s] rejected: per-IP cap (%d) reached", ip, maxConnsPerIP)
		return
	}
	defer ipRelease(ip)

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[%s] ws upgrade failed: %v", ip, err)
		return
	}
	defer ws.Close()
	if maxFrame > 0 {
		ws.SetReadLimit(maxFrame)
	}

	tcp, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		log.Printf("[%s] tcp dial %s failed: %v", ip, target, err)
		_ = ws.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseInternalServerErr, "rnsd unreachable"))
		return
	}
	defer tcp.Close()
	atomic.AddInt64(&totalConns, 1)
	log.Printf("[%s] connected -> %s (active=%d)", ip, target, atomic.LoadInt64(&curConns))

	var connBytes int64
	lastActive := time.Now().UnixNano()
	overCap := func() bool { return maxBytes > 0 && atomic.LoadInt64(&connBytes) > maxBytes }
	touch := func(n int) {
		atomic.AddInt64(&connBytes, int64(n))
		atomic.AddInt64(&totalBytes, int64(n))
		atomic.StoreInt64(&lastActive, time.Now().UnixNano())
	}

	// Idle watchdog: closes a connection with no traffic in either
	// direction for idleTimeout. Reclaims dead/leaked sockets without a
	// false kill of a quiet-but-alive session (any byte resets the clock).
	stop := make(chan struct{})
	if idleTimeout > 0 {
		go func() {
			t := time.NewTicker(15 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-stop:
					return
				case <-t.C:
					if time.Since(time.Unix(0, atomic.LoadInt64(&lastActive))) > idleTimeout {
						log.Printf("[%s] closing: idle > %s", ip, idleTimeout)
						ws.Close()
						tcp.Close()
						return
					}
				}
			}
		}()
	}

	// ws -> tcp pump (goroutine); tcp -> ws pump on this goroutine.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			mt, msg, err := ws.ReadMessage()
			if err != nil {
				tcp.Close()
				return
			}
			if mt != websocket.BinaryMessage {
				continue
			}
			if _, err := tcp.Write(msg); err != nil {
				return
			}
			touch(len(msg))
			if overCap() {
				log.Printf("[%s] closing: per-connection byte cap (%d) exceeded", ip, maxBytes)
				ws.Close()
				tcp.Close()
				return
			}
		}
	}()

	buf := make([]byte, 4096)
	for {
		n, err := tcp.Read(buf)
		if n > 0 {
			if werr := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); werr != nil {
				break
			}
			touch(n)
			if overCap() {
				log.Printf("[%s] closing: per-connection byte cap (%d) exceeded", ip, maxBytes)
				break
			}
		}
		if err != nil {
			break
		}
	}

	ws.Close()
	tcp.Close()
	close(stop)
	<-done
	log.Printf("[%s] closed (%d bytes)", ip, atomic.LoadInt64(&connBytes))
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "ok active=%d total_conns=%d total_bytes=%d\n",
		atomic.LoadInt64(&curConns), atomic.LoadInt64(&totalConns), atomic.LoadInt64(&totalBytes))
}

func main() {
	bind := flag.String("bind", "127.0.0.1", "bind address (run behind a TLS reverse proxy; 0.0.0.0 only to expose directly)")
	port := flag.Int("port", 7878, "listen port")
	flag.StringVar(&pinnedTarget, "target", "", "pin the rnsd target host:port; client-supplied host/port are ignored (recommended)")
	allow := flag.String("allow", "", "comma-separated allowlist of permitted client-chosen host:port targets (used only when -target is empty)")
	mc := flag.Int64("max-conns", 512, "max concurrent connections (0 = unlimited)")
	flag.IntVar(&maxConnsPerIP, "max-conns-per-ip", 8, "max concurrent connections per client IP (0 = unlimited)")
	flag.Int64Var(&maxBytes, "max-bytes", 0, "per-connection total byte cap, both directions (0 = unlimited)")
	idle := flag.Duration("idle-timeout", 0, "close a connection idle this long, e.g. 15m (0 = off)")
	flag.StringVar(&token, "token", "", "if set, require a matching ?token=... on every connection")
	flag.BoolVar(&trustProxy, "trust-proxy", false, "derive client IP from X-Forwarded-For/X-Real-IP (set ONLY when behind a trusted reverse proxy)")
	flag.Int64Var(&maxFrame, "max-frame", 1<<20, "max inbound WebSocket frame bytes (0 = unlimited)")
	origins := flag.String("allowed-origins", "https://thatsfguy.github.io", "comma-separated allowed Origins, or * for any")
	flag.StringVar(&blocklistPath, "blocklist", "", "path to an IP/CIDR blocklist file (reload with SIGHUP)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("ws_bridge_public v%s\n", version)
		return
	}

	maxConns = *mc
	idleTimeout = *idle

	allowedOrigins = map[string]bool{}
	for _, o := range strings.Split(*origins, ",") {
		o = strings.ToLower(strings.TrimSpace(o))
		if o == "*" {
			originAny = true
		} else if o != "" {
			allowedOrigins[o] = true
		}
	}

	// Safe by default: refuse to run as an open proxy.
	if pinnedTarget == "" && strings.TrimSpace(*allow) == "" {
		log.Fatalf("refusing to start as an open proxy: set -target host:port (recommended) or -allow host:port[,host:port...]")
	}
	allowSet = map[string]bool{}
	for _, a := range strings.Split(*allow, ",") {
		if a = strings.ToLower(strings.TrimSpace(a)); a != "" {
			allowSet[a] = true
		}
	}

	if blocklistPath != "" {
		n, err := loadBlocklist(blocklistPath)
		if err != nil {
			log.Fatalf("blocklist: %v", err)
		}
		log.Printf("loaded %d blocklist entr%s from %s", n, plural(n), blocklistPath)
	}

	// Hot-reload the blocklist on SIGHUP (Unix; no-op on Windows).
	go func() {
		for range reloadSignals() {
			if blocklistPath == "" {
				continue
			}
			if n, err := loadBlocklist(blocklistPath); err != nil {
				log.Printf("blocklist reload failed: %v", err)
			} else {
				log.Printf("blocklist reloaded: %d entr%s", n, plural(n))
			}
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealth)
	mux.HandleFunc("/", handleBridge)

	addr := fmt.Sprintf("%s:%d", *bind, *port)
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second, // slowloris mitigation
	}

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt)
		<-sig
		log.Printf("shutting down")
		_ = srv.Close()
	}()

	mode := "pinned target " + pinnedTarget
	if pinnedTarget == "" {
		mode = fmt.Sprintf("allowlist of %d target(s)", len(allowSet))
	}
	log.Printf("ws_bridge_public v%s listening on ws://%s (%s)", version, addr, mode)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("listen: %v", err)
	}
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
