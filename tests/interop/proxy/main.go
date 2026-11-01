// SPDX-License-Identifier: GPL-3.0-only
// Test-only peer using upstream AnyTLS and SagerNet UoT. No Go in the node.
package main

import (
	"anytls/proxy/padding"
	"anytls/proxy/session"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"flag"
	"fmt"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"
	"io"
	"net"
	"os"
	"sync/atomic"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	server := flag.String("server", "", "TLS proxy")
	tcpTarget := flag.String("tcp", "", "TCP echo")
	udpTarget := flag.String("udp", "", "UDP echo")
	caPath := flag.String("ca", "", "test trust anchor")
	password := flag.String("password", "", "test password")
	flag.Parse()
	pem, err := os.ReadFile(*caPath)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return fmt.Errorf("invalid test CA")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var dials atomic.Int32
	dial := func(ctx context.Context) (net.Conn, error) {
		socket, err := (&net.Dialer{}).DialContext(ctx, "tcp", *server)
		if err != nil {
			return nil, err
		}
		conn := tls.Client(socket, &tls.Config{ServerName: "localhost", RootCAs: roots, MinVersion: tls.VersionTLS12})
		if err := conn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		dials.Add(1)
		hash := sha256.Sum256([]byte(*password))
		header := append([]byte{}, hash[:]...)
		n := 0
		if sizes := padding.DefaultPaddingFactory.Load().GenerateRecordPayloadSizes(0); len(sizes) > 0 {
			n = sizes[0]
		}
		header = binary.BigEndian.AppendUint16(header, uint16(n))
		header = append(header, make([]byte, n)...)
		if _, err := conn.Write(header); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}
	client := session.NewClient(ctx, dial, &padding.DefaultPaddingFactory, 30*time.Second, 30*time.Second, 0, false)
	defer client.Close()
	for i := 0; i < 3; i++ {
		stream, err := client.CreateStream(ctx)
		if err != nil {
			return err
		}
		stream.SetDeadline(time.Now().Add(5 * time.Second))
		if err = M.SocksaddrSerializer.WriteAddrPort(stream, M.ParseSocksaddr(*tcpTarget)); err != nil {
			return err
		}
		payload := bytes.Repeat([]byte{byte('a' + i)}, 32768)
		if _, err = stream.Write(payload); err != nil {
			return err
		}
		reply := make([]byte, len(payload))
		if _, err = io.ReadFull(stream, reply); err != nil {
			return err
		}
		if !bytes.Equal(payload, reply) {
			return fmt.Errorf("TCP mismatch")
		}
		stream.Close()
	}
	for _, mode := range []int{1, 2, 3} {
		stream, err := client.CreateStream(ctx)
		if err != nil {
			return err
		}
		stream.SetDeadline(time.Now().Add(5 * time.Second))
		magic := uot.MagicAddress
		if mode == 1 {
			magic = uot.LegacyMagicAddress
		}
		if err = M.SocksaddrSerializer.WriteAddrPort(stream, M.Socksaddr{Fqdn: magic}); err != nil {
			return err
		}
		request := uot.Request{IsConnect: mode == 3, Destination: M.ParseSocksaddr(*udpTarget)}
		if mode != 1 {
			if err = uot.WriteRequest(stream, request); err != nil {
				return err
			}
		}
		conn := uot.NewConn(stream, request)
		for _, payload := range [][]byte{{}, []byte("uot"), bytes.Repeat([]byte{7}, 8192)} {
			if _, err = conn.WriteTo(payload, request.Destination.UDPAddr()); err != nil {
				return err
			}
			reply := make([]byte, 65535)
			n, _, err := conn.ReadFrom(reply)
			if err != nil {
				return err
			}
			if !bytes.Equal(reply[:n], payload) {
				return fmt.Errorf("UDP mismatch")
			}
		}
		stream.Close()
	}
	if n := dials.Load(); n != 1 {
		return fmt.Errorf("expected session reuse, got %d TLS connections", n)
	}
	fmt.Println("AnyTLS TCP, UoT v1/v2/connect and TLS session reuse passed")
	return nil
}
