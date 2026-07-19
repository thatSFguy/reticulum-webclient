// tools/ws_bridge.go
//
// WebSocket-to-TCP bridge for the Reticulum web client (Go version).
//
// Browsers cannot open raw TCP sockets, so the web client's "TCP"
// option speaks WebSocket to this bridge, which forwards raw bytes
// in both directions to a remote rnsd's TCPServerInterface. HDLC
// framing is preserved end to end — the bridge never parses or
// reassembles frames.
//
// Differences from the Python ws_bridge.py:
//   - The rnsd target (host + port) is supplied PER CONNECTION by the
//     webapp via query parameters: ws://localhost:7878/?host=X&port=Y.
//     The bridge itself takes no rnsd flags — one running bridge can
//     serve any number of webapp instances pointed at any number of
//     different rnsds without restart.
//   - Single self-contained binary, no Python or pip required.
//   - Shows a live in-place status display in the terminal (connected
//     clients, byte counts, links) instead of a scrolling log. Use
//     -plain to fall back to line-by-line logging (for services or
//     when stdout is redirected).
//
// Build:
//   # cross-compile for Windows from any host:
//   GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o ws_bridge.exe
//
//   # native build (Linux / macOS / Windows):
//   go build -ldflags="-s -w" -o ws_bridge
//
// The -s -w flags strip the symbol table and DWARF debug info,
// roughly halving the binary. Expect ~3-4 MB stripped on amd64.
//
// Run:
//   ws_bridge.exe                 # listen on localhost:7878, live display
//   ws_bridge.exe -port 9090      # custom port
//   ws_bridge.exe -bind 0.0.0.0   # listen on all interfaces (LAN-visible)
//   ws_bridge.exe -plain          # plain logging, no live display

package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

const (
	version     = "0.6.0"
	urlWebapp   = "https://thatsfguy.github.io/reticulum-webclient/"
	urlSource   = "https://github.com/thatSFguy/reticulum-webclient/blob/master/tools/ws_bridge.go"
	urlReleases = "https://github.com/thatSFguy/reticulum-webclient/releases?q=bridge-v"
)

var upgrader = websocket.Upgrader{
	// The webapp is served from github.io; the bridge runs on
	// localhost. Cross-origin WS upgrades are blocked by gorilla's
	// default CheckOrigin — open it up. The bridge has no auth and
	// only forwards bytes, so this is fine; if you bind to a LAN
	// interface and care about who can reach it, use a firewall.
	CheckOrigin:     func(r *http.Request) bool { return true },
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
}

// ---- connected-client registry -------------------------------------

type client struct {
	id      uint64
	browser string
	remote  string
	target  string
	since   time.Time
	up      int64 // ws -> tcp bytes (atomic)
	down    int64 // tcp -> ws bytes (atomic)
}

var (
	regMu     sync.Mutex
	clients   = map[uint64]*client{}
	nextID    uint64
	startedAt = time.Now()
)

func addClient(c *client) {
	regMu.Lock()
	clients[c.id] = c
	regMu.Unlock()
}

func removeClient(id uint64) {
	regMu.Lock()
	delete(clients, id)
	regMu.Unlock()
}

// snapshot returns the current clients oldest-first for a stable display.
func snapshot() []*client {
	regMu.Lock()
	defer regMu.Unlock()
	out := make([]*client, 0, len(clients))
	for _, c := range clients {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].since.Before(out[j].since) })
	return out
}

// ---- log ring buffer (shown in the live display) -------------------

const logKeep = 6

var (
	logMu  sync.Mutex
	logBuf []string
	plain  bool
)

func logf(format string, a ...interface{}) {
	line := time.Now().Format("15:04:05") + " " + fmt.Sprintf(format, a...)
	if plain {
		fmt.Fprintln(os.Stderr, line)
		return
	}
	logMu.Lock()
	logBuf = append(logBuf, line)
	if len(logBuf) > logKeep {
		logBuf = logBuf[len(logBuf)-logKeep:]
	}
	logMu.Unlock()
}

func recentLogs() []string {
	logMu.Lock()
	defer logMu.Unlock()
	out := make([]string, len(logBuf))
	copy(out, logBuf)
	return out
}

// ---- helpers -------------------------------------------------------

// browserName maps a User-Agent to a short label. Order matters:
// Edge/Opera/Chrome UAs all contain "Safari", and Edge/Opera contain
// "Chrome", so the more specific tokens are checked first.
func browserName(ua string) string {
	u := strings.ToLower(ua)
	switch {
	case u == "":
		return "?"
	case strings.Contains(u, "edg"):
		return "Edge"
	case strings.Contains(u, "opr"), strings.Contains(u, "opera"):
		return "Opera"
	case strings.Contains(u, "firefox"), strings.Contains(u, "fxios"):
		return "Firefox"
	case strings.Contains(u, "chrome"), strings.Contains(u, "chromium"), strings.Contains(u, "crios"):
		return "Chrome"
	case strings.Contains(u, "safari"):
		return "Safari"
	default:
		return "other"
	}
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(n)/float64(div), "KMGTPE"[exp])
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 2 {
		return s[:n]
	}
	return s[:n-2] + ".."
}

// ---- bridge --------------------------------------------------------

func handleBridge(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	port := r.URL.Query().Get("port")
	if host == "" || port == "" {
		http.Error(w, "missing required query params: ?host=X&port=Y", http.StatusBadRequest)
		return
	}
	target := net.JoinHostPort(host, port)
	peer := r.RemoteAddr
	browser := browserName(r.UserAgent())

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logf("[%s] ws upgrade failed: %v", peer, err)
		return
	}
	defer ws.Close()

	tcp, err := net.Dial("tcp", target)
	if err != nil {
		logf("[%s] %s tcp dial %s failed: %v", peer, browser, target, err)
		_ = ws.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseInternalServerErr, "rnsd unreachable"))
		return
	}
	defer tcp.Close()

	id := atomic.AddUint64(&nextID, 1)
	c := &client{id: id, browser: browser, remote: peer, target: target, since: time.Now()}
	addClient(c)
	defer removeClient(id)
	logf("[%s] %s connected, bridged to %s", peer, browser, target)

	// ws -> tcp pump runs in its own goroutine. The tcp -> ws pump
	// runs on this goroutine. Either side closing tears down both:
	// closing tcp causes the read loop in the goroutine to error;
	// closing ws causes the read loop here to error.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			mt, msg, err := ws.ReadMessage()
			if err != nil {
				if !websocket.IsCloseError(err,
					websocket.CloseNormalClosure,
					websocket.CloseGoingAway,
					websocket.CloseAbnormalClosure) {
					logf("[%s] ws read: %v", peer, err)
				}
				_ = tcp.Close()
				return
			}
			// The webapp always sends binary; drop anything else.
			if mt != websocket.BinaryMessage {
				logf("[%s] ignoring non-binary ws message (type=%d, len=%d)", peer, mt, len(msg))
				continue
			}
			if _, err := tcp.Write(msg); err != nil {
				logf("[%s] tcp write: %v", peer, err)
				return
			}
			atomic.AddInt64(&c.up, int64(len(msg)))
		}
	}()

	buf := make([]byte, 4096)
	for {
		n, err := tcp.Read(buf)
		if n > 0 {
			if werr := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); werr != nil {
				logf("[%s] ws write: %v", peer, werr)
				break
			}
			atomic.AddInt64(&c.down, int64(n))
		}
		if err != nil {
			if err != io.EOF {
				logf("[%s] tcp read: %v", peer, err)
			}
			break
		}
	}

	_ = ws.Close()
	<-done
	logf("[%s] %s disconnected", peer, browser)
}

// ---- live status display -------------------------------------------

const (
	altScreenOn  = "\x1b[?1049h\x1b[?25l" // alt buffer + hide cursor
	altScreenOff = "\x1b[?25h\x1b[?1049l" // show cursor + restore buffer
)

func renderLoop(addr string, lan bool) {
	draw(addr, lan)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for range ticker.C {
		draw(addr, lan)
	}
}

func draw(addr string, lan bool) {
	cs := snapshot()
	var totUp, totDown int64
	for _, c := range cs {
		totUp += atomic.LoadInt64(&c.up)
		totDown += atomic.LoadInt64(&c.down)
	}

	var L []string
	add := func(f string, a ...interface{}) { L = append(L, fmt.Sprintf(f, a...)) }
	rule := "  " + strings.Repeat("─", 74)

	add("  \x1b[1mReticulum WS Bridge\x1b[0m  v%s", version)
	visibility := "localhost only"
	if lan {
		visibility = "LAN-visible"
	}
	add("  \x1b[32m●\x1b[0m Listening  ws://%s   (%s)", addr, visibility)
	add("  Uptime %s    Clients connected: %d    Total %s ↑ / %s ↓",
		time.Since(startedAt).Truncate(time.Second), len(cs), humanBytes(totUp), humanBytes(totDown))
	add(rule)
	add("  %-8s %-21s %-19s %-15s %s", "CLIENT", "REMOTE", "RNSD TARGET", "UP / DOWN", "SINCE")
	if len(cs) == 0 {
		add("  \x1b[2m(no clients — open the webapp and click Connect (TCP / rnsd))\x1b[0m")
	} else {
		for _, c := range cs {
			ud := humanBytes(atomic.LoadInt64(&c.up)) + " / " + humanBytes(atomic.LoadInt64(&c.down))
			add("  %-8s %-21s %-19s %-15s %s",
				trunc(c.browser, 8), trunc(c.remote, 21), trunc(c.target, 19), trunc(ud, 15),
				c.since.Format("15:04:05"))
		}
	}
	add(rule)
	add("  Webapp    %s", urlWebapp)
	add("  Source    %s", urlSource)
	add("  Releases  %s", urlReleases)
	add(rule)
	add("  \x1b[1mRecent\x1b[0m")
	logs := recentLogs()
	if len(logs) == 0 {
		add("    \x1b[2m(waiting for connections…)\x1b[0m")
	} else {
		for _, ln := range logs {
			add("    \x1b[2m%s\x1b[0m", trunc(ln, 72))
		}
	}
	add("")
	add("  \x1b[2mCtrl+C to quit\x1b[0m")

	// Compose one frame: cursor home, each line cleared to end-of-line
	// (so shorter lines overwrite cleanly), then clear everything below.
	var b strings.Builder
	b.WriteString("\x1b[H")
	for _, ln := range L {
		b.WriteString(ln)
		b.WriteString("\x1b[K\r\n")
	}
	b.WriteString("\x1b[J")
	os.Stdout.WriteString(b.String())
}

func main() {
	bind := flag.String("bind", "localhost", "WebSocket bind host (use 0.0.0.0 for LAN-visible)")
	port := flag.Int("port", 7878, "WebSocket bind port")
	plainFlag := flag.Bool("plain", false, "disable the live status display; log to stderr (for services / redirected output)")
	flag.Parse()
	plain = *plainFlag

	addr := fmt.Sprintf("%s:%d", *bind, *port)
	lan := *bind != "localhost" && *bind != "127.0.0.1"
	http.HandleFunc("/", handleBridge)

	// Bind before touching the screen so an "address already in use"
	// error is printed normally rather than swallowed by the alt buffer.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(1)
	}

	if plain {
		logf("ws_bridge v%s listening on ws://%s (rnsd target per-connection via ?host=X&port=Y)", version, addr)
	} else {
		enableVT() // Windows: turn on ANSI + UTF-8 output. No-op elsewhere.
		os.Stdout.WriteString(altScreenOn)
		// Restore the terminal on Ctrl+C before exiting.
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt)
		go func() {
			<-sig
			os.Stdout.WriteString(altScreenOff)
			os.Exit(0)
		}()
		go renderLoop(addr, lan)
	}

	if err := http.Serve(ln, nil); err != nil {
		if !plain {
			os.Stdout.WriteString(altScreenOff)
		}
		fmt.Fprintf(os.Stderr, "serve: %v\n", err)
		os.Exit(1)
	}
}
