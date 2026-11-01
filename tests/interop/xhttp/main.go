// SPDX-License-Identifier: GPL-3.0-only
// Optional test peer built inside the pinned Polaris source archive.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/perfect-panel/Polaris/internal/transport/xhttp"
	"github.com/sagernet/sing-vmess/vless"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

type handler struct{}

func (handler) NewConnectionEx(_ context.Context, c net.Conn, _, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		defer c.Close()
		c.SetDeadline(time.Now().Add(20 * time.Second))
		_, err := vless.ReadRequest(c)
		if err == nil {
			_, err = c.Write([]byte{0, 0})
		}
		if err == nil {
			_, err = io.Copy(c, c)
		}
		if onClose != nil {
			onClose(err)
		}
	}()
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	role := flag.String("role", "client", "client/server")
	server := flag.String("server", "127.0.0.1:0", "server endpoint")
	target := flag.String("target", "127.0.0.1:443", "VLESS target")
	mode := flag.String("mode", "packet-up", "XHTTP mode")
	alpn := flag.String("alpn", "", "h2/http/1.1/h3; empty for plaintext")
	cert := flag.String("cert", "", "PEM certificate")
	key := flag.String("key", "", "PEM key")
	extra := flag.String("extra", "{}", "XHTTP extra JSON")
	flag.Parse()
	cfg, err := xhttp.Parse("localhost", "/relay", *mode, *extra)
	if err != nil {
		return err
	}
	var tlsConfig *tls.Config
	if *alpn != "" {
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "localhost", NextProtos: []string{*alpn}}
		if *role == "server" {
			pair, err := tls.LoadX509KeyPair(*cert, *key)
			if err != nil {
				return err
			}
			tlsConfig.Certificates = []tls.Certificate{pair}
		} else {
			pem, err := os.ReadFile(*cert)
			if err != nil {
				return err
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(pem) {
				return fmt.Errorf("bad CA")
			}
			tlsConfig.RootCAs = roots
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if *role == "server" {
		s := xhttp.NewServer(ctx, cfg, tlsConfig, handler{})
		defer s.Close()
		done := make(chan error, 1)
		if *alpn == "h3" {
			packet, err := net.ListenPacket("udp", *server)
			if err != nil {
				return err
			}
			defer packet.Close()
			go func() { done <- s.ServePacket(packet) }()
			fmt.Println("READY", packet.LocalAddr())
		} else {
			listener, err := net.Listen("tcp", *server)
			if err != nil {
				return err
			}
			defer listener.Close()
			go func() { done <- s.Serve(listener) }()
			fmt.Println("READY", listener.Addr())
		}
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
		defer signal.Stop(stop)
		select {
		case <-stop:
			return nil
		case err := <-done:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	dial := func(ctx context.Context, address string, conf *tls.Config) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
		if err != nil {
			return nil, err
		}
		if conf == nil {
			return conn, nil
		}
		secure := tls.Client(conn, conf)
		if err = secure.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		return secure, nil
	}
	client := xhttp.NewClient(xhttp.ClientOptions{Context: ctx, Config: cfg, Server: *server, TLSConfig: tlsConfig, Dial: dial})
	defer client.Close()
	host, port, err := net.SplitHostPort(*target)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host).To4()
	n, err := strconv.Atoi(port)
	if err != nil || ip == nil {
		return fmt.Errorf("fixture needs IPv4 target")
	}
	header := append([]byte{0}, []byte{0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08, 0x11}...)
	header = append(header, 0, 1, byte(n>>8), byte(n), 1)
	header = append(header, ip...)
	for i := 0; i < 3; i++ {
		conn, err := client.DialContext(ctx)
		if err != nil {
			return err
		}
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		payload := make([]byte, 256<<10)
		for j := range payload {
			payload[j] = byte(j*197 + i*71)
		}
		written := make(chan error, 1)
		go func() { _, err := conn.Write(append(append([]byte{}, header...), payload...)); written <- err }()
		reply := make([]byte, len(payload)+2)
		_, err = io.ReadFull(conn, reply)
		if err == nil {
			err = <-written
		}
		conn.Close()
		if err != nil {
			return err
		}
		if !bytes.Equal(reply[:2], []byte{0, 0}) || !bytes.Equal(reply[2:], payload) {
			return fmt.Errorf("echo mismatch")
		}
	}
	fmt.Println("Polaris XHTTP passed", *mode, *alpn)
	return nil
}
