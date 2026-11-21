package spamfilter

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// zeroConn reads endless zeros; nothing else of net.Conn is used.
type zeroConn struct{ net.Conn }

func (zeroConn) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func TestLimiterShared(t *testing.T) {
	l := NewLimiter(80) // 10 MB/s over all readers
	before := WireBytes.Load()
	t0 := time.Now()
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			io.CopyN(io.Discard, &wireConn{Conn: zeroConn{}, l: l}, 5e6)
		}()
	}
	wg.Wait()
	// 20 MB: one second's burst, then 10 MB/s
	if el := time.Since(t0); el < 900*time.Millisecond || el > 2500*time.Millisecond {
		t.Fatalf("20 MB at 10 MB/s took %s", el)
	}
	if got := WireBytes.Load() - before; got < 20e6 {
		t.Fatalf("counted %d bytes, want at least 20e6", got)
	}
	if NewLimiter(0) != nil {
		t.Fatal("0 should mean no limit")
	}
}
