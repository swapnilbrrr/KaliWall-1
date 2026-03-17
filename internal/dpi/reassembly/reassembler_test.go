package reassembly

import (
	"testing"
	"time"

	"kaliwall/internal/dpi/types"
)

func TestOutOfOrderAndRetransmit(t *testing.T) {
	r := New(Config{MaxBytesPerFlow: 4096, MaxWindowBytes: 4096, FlowTimeout: time.Minute, CleanupInterval: time.Minute})
	tuple := types.FiveTuple{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 80, Protocol: "tcp"}

	pkt2 := &types.DecodedPacket{Timestamp: time.Now(), Tuple: tuple, TCPSeq: 1005, Payload: []byte("WORLD")}
	out, err := r.Process(pkt2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected no output for out-of-order packet")
	}

	pkt1 := &types.DecodedPacket{Timestamp: time.Now(), Tuple: tuple, TCPSeq: 1000, Payload: []byte("HELLO")}
	out, err = r.Process(pkt1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 output payload, got %d", len(out))
	}
	if got := string(out[0].Payload); got != "HELLOWORLD" {
		t.Fatalf("unexpected reassembly: %q", got)
	}

	retransmit := &types.DecodedPacket{Timestamp: time.Now(), Tuple: tuple, TCPSeq: 1000, Payload: []byte("HELLO")}
	out, err = r.Process(retransmit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected retransmission to be ignored")
	}
}
