package lite

import (
    "context"
    "log"
    "runtime"
    "sync"
    "sync/atomic"
    "time"

    "github.com/google/gopacket"

    "kaliwall/internal/dpi/capture"
    "kaliwall/internal/dpi/decode"
    "kaliwall/internal/dpi/inspect"
    "kaliwall/internal/dpi/pipeline"
    "kaliwall/internal/dpi/types"
    "kaliwall/internal/logger"
)

// Config controls lightweight IDS/DPI runtime behavior.
type Config struct {
    Interface   string
    Promiscuous bool
    BPF         string
    Workers     int
}

// Stats is a lightweight REST-friendly view for protocol detections.
type Stats struct {
    Enabled      bool      `json:"enabled"`
    Running      bool      `json:"running"`
    Interface    string    `json:"interface"`
    Workers      int       `json:"workers"`
    UptimeSec    float64   `json:"uptime_sec"`
    PacketsSeen  uint64    `json:"packets_seen"`
    DecodeErrors uint64    `json:"decode_errors"`

    HTTPDetected uint64    `json:"http_detected"`
    DNSDetected  uint64    `json:"dns_detected"`
    TLSDetected  uint64    `json:"tls_detected"`

    LastHTTP     string    `json:"last_http"`
    LastDNS      string    `json:"last_dns"`
    LastTLS      string    `json:"last_tls"`
    LastSeenAt   time.Time `json:"last_seen_at"`
}

// Engine is a lightweight live IDS/DPI processor focused on protocol extraction.
type Engine struct {
    cfg    Config
    logger *logger.TrafficLogger

    capturer capture.Capturer
    decoder  decode.Decoder
    inspect  *inspect.Engine

    inputCh chan gopacket.Packet
    stop    context.CancelFunc
    wg      sync.WaitGroup

    startedAt time.Time
    running   atomic.Bool
    enabled   atomic.Bool

    packetsSeen  atomic.Uint64
    decodeErrors atomic.Uint64
    httpDetected atomic.Uint64
    dnsDetected  atomic.Uint64
    tlsDetected  atomic.Uint64

    metaMu     sync.RWMutex
    lastHTTP   string
    lastDNS    string
    lastTLS    string
    lastSeenAt time.Time
}

// New creates a lightweight IDS/DPI engine.
func New(cfg Config, tl *logger.TrafficLogger) *Engine {
    if cfg.Workers <= 0 {
        cfg.Workers = max(2, runtime.NumCPU()/2)
    }
    if cfg.Workers < 1 {
        cfg.Workers = 1
    }

    c := capture.New(capture.Config{
        Interface:   cfg.Interface,
        Promiscuous: cfg.Promiscuous,
        BPF:         cfg.BPF,
    })

    return &Engine{
        cfg:     cfg,
        logger:  tl,
        capturer: c,
        decoder: decode.New(),
        inspect: inspect.New(),
        inputCh: make(chan gopacket.Packet, 4096),
    }
}

// SetEnabled starts/stops the lightweight engine.
func (e *Engine) SetEnabled(enabled bool) error {
    if enabled {
        return e.Start(context.Background())
    }
    e.Stop()
    return nil
}

// Start begins capture + workers.
func (e *Engine) Start(parent context.Context) error {
    if e.running.Load() {
        e.enabled.Store(true)
        return nil
    }

    ctx, cancel := context.WithCancel(parent)
    if err := e.capturer.Start(ctx); err != nil {
        cancel()
        return err
    }

    e.stop = cancel
    e.startedAt = time.Now()
    e.running.Store(true)
    e.enabled.Store(true)

    e.wg.Add(1)
    go e.forwardPackets(ctx)

    e.wg.Add(1)
    go e.captureErrors(ctx)

    for i := 0; i < e.cfg.Workers; i++ {
        e.wg.Add(1)
        go e.worker(ctx)
    }

    log.Printf("DPI lite started iface=%s workers=%d", e.cfg.Interface, e.cfg.Workers)
    return nil
}

// Stop halts capture/workers.
func (e *Engine) Stop() {
    if e.stop != nil {
        e.stop()
    }
    _ = e.capturer.Close()
    e.wg.Wait()
    e.running.Store(false)
    e.enabled.Store(false)
    log.Printf("DPI lite stopped")
}

// Status returns compact status for compatibility with existing API.
func (e *Engine) Status() pipeline.Status {
    uptime := 0.0
    if !e.startedAt.IsZero() {
        uptime = time.Since(e.startedAt).Seconds()
    }
    return pipeline.Status{
        Enabled:      e.enabled.Load(),
        Running:      e.running.Load(),
        Interface:    e.cfg.Interface,
        Workers:      e.cfg.Workers,
        RulesLoaded:  0,
        UptimeSec:    uptime,
        PacketsSeen:  e.packetsSeen.Load(),
        DecodeErrors: e.decodeErrors.Load(),
        ReasmErrors:  0,
        Allowed:      0,
        Blocked:      0,
        Logged:       e.httpDetected.Load() + e.dnsDetected.Load() + e.tlsDetected.Load(),
        RateLimited:  0,
    }
}

// DetailedStats returns protocol-level counters and last-seen artifacts.
func (e *Engine) DetailedStats() Stats {
    e.metaMu.RLock()
    lastHTTP := e.lastHTTP
    lastDNS := e.lastDNS
    lastTLS := e.lastTLS
    lastSeen := e.lastSeenAt
    e.metaMu.RUnlock()

    uptime := 0.0
    if !e.startedAt.IsZero() {
        uptime = time.Since(e.startedAt).Seconds()
    }

    return Stats{
        Enabled:      e.enabled.Load(),
        Running:      e.running.Load(),
        Interface:    e.cfg.Interface,
        Workers:      e.cfg.Workers,
        UptimeSec:    uptime,
        PacketsSeen:  e.packetsSeen.Load(),
        DecodeErrors: e.decodeErrors.Load(),
        HTTPDetected: e.httpDetected.Load(),
        DNSDetected:  e.dnsDetected.Load(),
        TLSDetected:  e.tlsDetected.Load(),
        LastHTTP:     lastHTTP,
        LastDNS:      lastDNS,
        LastTLS:      lastTLS,
        LastSeenAt:   lastSeen,
    }
}

func (e *Engine) forwardPackets(ctx context.Context) {
    defer e.wg.Done()
    defer close(e.inputCh)
    for {
        select {
        case <-ctx.Done():
            return
        case pkt, ok := <-e.capturer.Packets():
            if !ok {
                return
            }
            select {
            case e.inputCh <- pkt:
            case <-ctx.Done():
                return
            }
        }
    }
}

func (e *Engine) captureErrors(ctx context.Context) {
    defer e.wg.Done()
    for {
        select {
        case <-ctx.Done():
            return
        case err, ok := <-e.capturer.Errors():
            if !ok {
                return
            }
            log.Printf("DPI lite capture error: %v", err)
        }
    }
}

func (e *Engine) worker(ctx context.Context) {
    defer e.wg.Done()
    for {
        select {
        case <-ctx.Done():
            return
        case pkt, ok := <-e.inputCh:
            if !ok {
                return
            }
            e.packetsSeen.Add(1)
            decoded, err := e.decoder.Decode(pkt)
            if err != nil {
                e.decodeErrors.Add(1)
                continue
            }

            result := e.inspect.Inspect(types.AppPayload{
                Timestamp: decoded.Timestamp,
                Tuple:     decoded.Tuple,
                Payload:   decoded.Payload,
                DNSQuery:  decoded.DNSQuery,
            })
            e.record(result)
        }
    }
}

func (e *Engine) record(result types.InspectResult) {
    seen := false

    if result.HTTPMethod != "" {
        e.httpDetected.Add(1)
        seen = true
        msg := "[HTTP] " + result.HTTPMethod + " " + result.HTTPURL + " Host: " + result.HTTPHost
        log.Println(msg)
        if e.logger != nil {
            e.logger.Log("LOG", result.Tuple.SrcIP, result.Tuple.DstIP, "http", "dpi:lite:"+msg)
        }
        e.metaMu.Lock()
        e.lastHTTP = msg
        e.lastSeenAt = time.Now()
        e.metaMu.Unlock()
    }

    if result.DNSDomain != "" {
        e.dnsDetected.Add(1)
        seen = true
        msg := "[DNS] Query: " + result.DNSDomain
        log.Println(msg)
        if e.logger != nil {
            e.logger.Log("LOG", result.Tuple.SrcIP, result.Tuple.DstIP, "dns", "dpi:lite:"+msg)
        }
        e.metaMu.Lock()
        e.lastDNS = msg
        e.lastSeenAt = time.Now()
        e.metaMu.Unlock()
    }

    if result.TLSSNI != "" {
        e.tlsDetected.Add(1)
        seen = true
        msg := "[TLS] SNI: " + result.TLSSNI
        log.Println(msg)
        if e.logger != nil {
            e.logger.Log("LOG", result.Tuple.SrcIP, result.Tuple.DstIP, "tls", "dpi:lite:"+msg)
        }
        e.metaMu.Lock()
        e.lastTLS = msg
        e.lastSeenAt = time.Now()
        e.metaMu.Unlock()
    }

    if seen {
        return
    }
}

func max(a, b int) int {
    if a > b {
        return a
    }
    return b
}
