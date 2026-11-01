// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/vless/encryption"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

type recordingConn struct {
	net.Conn
	written bytes.Buffer
}

func (c *recordingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.written.Write(p[:n])
	return n, err
}
func main() {
	address := flag.String("address", "", "target")
	config := flag.String("config", "", "public client encryption")
	aes := flag.Bool("aes", true, "AES instead of ChaCha20")
	replay := flag.Bool("replay", false, "replay a resumed connection")
	flag.Parse()
	protocol.HasAESGCMHardwareSupport = *aes
	fields := strings.Split(*config, ".")
	if len(fields) < 4 {
		panic("invalid client config")
	}
	var mode uint32
	switch fields[1] {
	case "xorpub":
		mode = 1
	case "random":
		mode = 2
	case "native":
	default:
		panic("mode")
	}
	var seconds uint32
	if fields[2] == "0rtt" {
		seconds = 1
	}
	var keys [][]byte
	for _, field := range fields[3:] {
		key, err := base64.RawURLEncoding.DecodeString(field)
		must(err)
		keys = append(keys, key)
	}
	client := new(encryption.ClientInstance)
	must(client.Init(keys, mode, seconds, "100-35-35"))
	resumed := 0
	var recorded []byte
	for index := 0; index < 2; index++ {
		raw, err := net.DialTimeout("tcp", *address, 5*time.Second)
		must(err)
		must(raw.SetDeadline(time.Now().Add(10 * time.Second)))
		recording := &recordingConn{Conn: raw}
		conn, err := client.Handshake(recording)
		must(err)
		if conn.Client != nil {
			resumed++
		}
		payload := make([]byte, 65536)
		for i := range payload {
			payload[i] = byte(i + index)
		}
		n, err := conn.Write(payload)
		must(err)
		if n != len(payload) {
			panic("short encrypted write")
		}
		received := make([]byte, len(payload))
		_, err = io.ReadFull(conn, received)
		must(err)
		if !bytes.Equal(received, payload) {
			panic("payload mismatch")
		}
		recorded = append(recorded[:0], recording.written.Bytes()...)
		must(conn.Close())
	}
	if *replay {
		raw, err := net.DialTimeout("tcp", *address, 5*time.Second)
		must(err)
		must(raw.SetDeadline(time.Now().Add(10 * time.Second)))
		_, _ = raw.Write(recorded)
		var b [1]byte
		n, err := raw.Read(b[:])
		raw.Close()
		if n != 0 || err == nil {
			panic("replay accepted")
		}
	}
	json.NewEncoder(os.Stdout).Encode(map[string]int{"connections": 2, "resumed": resumed})
}
func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
