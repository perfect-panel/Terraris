// SPDX-License-Identifier: GPL-3.0-only
// Optional sustained loopback benchmark. Never used by the production node.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

func benchmark(ctx context.Context, dial func(context.Context) (net.Conn, error), header []byte, duration time.Duration, count int) error {
	conns := make([]net.Conn, 0, count)
	defer func() {
		for _, conn := range conns {
			conn.Close()
		}
	}()
	for i := 0; i < count; i++ {
		conn, err := dial(ctx)
		if err != nil {
			return err
		}
		conns = append(conns, conn)
		payload := append(append([]byte{}, header...), 0x37)
		if _, err = conn.Write(payload); err != nil {
			return err
		}
		var response [3]byte
		if _, err = io.ReadFull(conn, response[:]); err != nil {
			return err
		}
		if response != [3]byte{0, 0, 0x37} {
			return fmt.Errorf("invalid benchmark warmup response")
		}
	}
	var received, sent, failures, corrupt atomic.Uint64
	var stopping atomic.Bool
	perFlow := make([]atomic.Uint64, count)
	var jobs sync.WaitGroup
	begin := time.Now()
	var eventsLock sync.Mutex
	events := make([]map[string]interface{}, 0)
	record := func(index int, direction string, err error) {
		if stopping.Load() {
			return
		}
		failures.Add(1)
		eventsLock.Lock()
		defer eventsLock.Unlock()
		events = append(events, map[string]interface{}{"flow": index, "direction": direction, "seconds": time.Since(begin).Seconds(), "error": err.Error()})
	}
	for index, conn := range conns {
		jobs.Add(2)
		go func(index int, conn net.Conn) {
			defer jobs.Done()
			payload := bytes.Repeat([]byte{byte(index)}, 65536)
			for {
				n, err := conn.Write(payload)
				sent.Add(uint64(n))
				if err != nil {
					record(index, "write", err)
					return
				}
			}
		}(index, conn)
		go func(index int, conn net.Conn) {
			defer jobs.Done()
			buffer := make([]byte, 65536)
			for {
				n, err := conn.Read(buffer)
				received.Add(uint64(n))
				perFlow[index].Add(uint64(n))
				for _, b := range buffer[:n] {
					if b != byte(index) {
						corrupt.Add(1)
						break
					}
				}
				if err != nil {
					record(index, "read", err)
					return
				}
			}
		}(index, conn)
	}
	time.Sleep(time.Second)
	before, beforeSent := received.Load(), sent.Load()
	initial, last, stalls := make([]uint64, count), make([]uint64, count), make([]int, count)
	for i := range initial {
		initial[i] = perFlow[i].Load()
		last[i] = initial[i]
	}
	start := time.Now()
	maximumStall := 0
	ticker := time.NewTicker(time.Second)
	timer := time.NewTimer(duration)
loop:
	for {
		select {
		case <-ctx.Done():
			timer.Stop()
			ticker.Stop()
			stopping.Store(true)
			for _, conn := range conns {
				conn.Close()
			}
			jobs.Wait()
			return ctx.Err()
		case <-timer.C:
			break loop
		case <-ticker.C:
			for i := range last {
				now := perFlow[i].Load()
				if now == last[i] {
					stalls[i]++
					if stalls[i] > maximumStall {
						maximumStall = stalls[i]
					}
				} else {
					stalls[i] = 0
				}
				last[i] = now
			}
		}
	}
	ticker.Stop()
	elapsed := time.Since(start).Seconds()
	after, afterSent := received.Load(), sent.Load()
	flowBytes := make([]uint64, count)
	for i := range flowBytes {
		flowBytes[i] = perFlow[i].Load() - initial[i]
	}
	stopping.Store(true)
	for _, conn := range conns {
		conn.Close()
	}
	jobs.Wait()
	return json.NewEncoder(os.Stdout).Encode(map[string]interface{}{
		"connections": count, "seconds": elapsed, "received_bytes": after - before, "sent_bytes": afterSent - beforeSent,
		"gbps": float64(after-before) * 8 / elapsed / 1e9, "unexpected_io_errors": failures.Load(), "corrupt_reads": corrupt.Load(),
		"flow_received_bytes": flowBytes, "max_no_progress_seconds": maximumStall, "io_errors": events,
	})
}

// The harness binds loopback and terminates this test-only process on exit.
func benchmarkEcho(address string) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	defer listener.Close()
	fmt.Println("READY", listener.Addr())
	slots := make(chan struct{}, 128)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		select {
		case slots <- struct{}{}:
			go func() { defer func() { conn.Close(); <-slots }(); io.CopyBuffer(conn, conn, make([]byte, 65536)) }()
		default:
			conn.Close()
		}
	}
}
