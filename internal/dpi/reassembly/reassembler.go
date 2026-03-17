package reassembly

import (
	"fmt"
	"sync"
	"time"

	"kaliwall/internal/dpi/types"
)

// Reassembler processes transport payloads and emits reassembled application windows.
type Reassembler interface {
	Process(pkt *types.DecodedPacket) ([]types.AppPayload, error)
	Start()
	Stop()
}

type streamState struct {
	ExpectedSeq uint32
	Pending     map[uint32][]byte
	Window      []byte
	Buffered    int
	LastSeen    time.Time
	Init        bool
}

// Config controls TCP stream state limits.
type Config struct {
	MaxBytesPerFlow int
	MaxWindowBytes  int
	FlowTimeout     time.Duration
	CleanupInterval time.Duration
}

// StreamReassembler implements bounded in-memory TCP stream reassembly.
type StreamReassembler struct {
	mu     sync.Mutex
	flows  map[types.FiveTuple]*streamState
	cfg    Config
	stopCh chan struct{}
}

func New(cfg Config) *StreamReassembler {
	if cfg.MaxBytesPerFlow <= 0 {
		cfg.MaxBytesPerFlow = 1 << 20
	}
	if cfg.MaxWindowBytes <= 0 {
		cfg.MaxWindowBytes = 8192
	}
	if cfg.FlowTimeout <= 0 {
		cfg.FlowTimeout = 2 * time.Minute
	}
	if cfg.CleanupInterval <= 0 {
		cfg.CleanupInterval = 30 * time.Second
	}
	return &StreamReassembler{
		flows:  make(map[types.FiveTuple]*streamState, 4096),
		cfg:    cfg,
		stopCh: make(chan struct{}),
	}
}

func (r *StreamReassembler) Start() {
	go r.cleanupLoop()
}

func (r *StreamReassembler) Stop() {
	select {
	case <-r.stopCh:
	default:
		close(r.stopCh)
	}
}

func (r *StreamReassembler) Process(pkt *types.DecodedPacket) ([]types.AppPayload, error) {
	if pkt == nil {
		return nil, nil
	}
	if pkt.Tuple.Protocol != "tcp" {
		if len(pkt.Payload) == 0 && pkt.DNSQuery == "" {
			return nil, nil
		}
		return []types.AppPayload{{
			Timestamp:   pkt.Timestamp,
			Tuple:       pkt.Tuple,
			Payload:     append([]byte(nil), pkt.Payload...),
			DNSQuery:    pkt.DNSQuery,
			Reassembled: false,
		}}, nil
	}
	if len(pkt.Payload) == 0 {
		return nil, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	st, ok := r.flows[pkt.Tuple]
	if !ok {
		st = &streamState{Pending: make(map[uint32][]byte), LastSeen: time.Now()}
		r.flows[pkt.Tuple] = st
	}
	st.LastSeen = time.Now()

	seq := pkt.TCPSeq
	segment := append([]byte(nil), pkt.Payload...)
	if !st.Init {
		st.ExpectedSeq = seq
		st.Init = true
	}

	if seq < st.ExpectedSeq {
		overlap := int(st.ExpectedSeq - seq)
		if overlap >= len(segment) {
			return nil, nil
		}
		segment = segment[overlap:]
		seq = st.ExpectedSeq
	}

	if seq > st.ExpectedSeq {
		if _, exists := st.Pending[seq]; !exists {
			if st.Buffered+len(segment) > r.cfg.MaxBytesPerFlow {
				delete(r.flows, pkt.Tuple)
				return nil, fmt.Errorf("reassembly flow buffer exceeded for %s:%d", pkt.Tuple.SrcIP, pkt.Tuple.SrcPort)
			}
			st.Pending[seq] = segment
			st.Buffered += len(segment)
		}
		return nil, nil
	}

	assembled := make([]byte, 0, len(segment)+1024)
	assembled = append(assembled, segment...)
	st.ExpectedSeq += uint32(len(segment))

	for {
		next, ok := st.Pending[st.ExpectedSeq]
		if !ok {
			break
		}
		assembled = append(assembled, next...)
		st.ExpectedSeq += uint32(len(next))
		st.Buffered -= len(next)
		delete(st.Pending, st.ExpectedSeq-uint32(len(next)))
	}

	if len(assembled) == 0 {
		return nil, nil
	}

	if len(st.Window)+len(assembled) > r.cfg.MaxWindowBytes {
		over := len(st.Window) + len(assembled) - r.cfg.MaxWindowBytes
		if over < len(st.Window) {
			st.Window = st.Window[over:]
		} else {
			st.Window = st.Window[:0]
		}
	}
	st.Window = append(st.Window, assembled...)

	return []types.AppPayload{{
		Timestamp:   pkt.Timestamp,
		Tuple:       pkt.Tuple,
		Payload:     append([]byte(nil), st.Window...),
		DNSQuery:    pkt.DNSQuery,
		Reassembled: true,
	}}, nil
}

func (r *StreamReassembler) cleanupLoop() {
	ticker := time.NewTicker(r.cfg.CleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			now := time.Now()
			r.mu.Lock()
			for key, st := range r.flows {
				if now.Sub(st.LastSeen) > r.cfg.FlowTimeout {
					delete(r.flows, key)
				}
			}
			r.mu.Unlock()
		}
	}
}
