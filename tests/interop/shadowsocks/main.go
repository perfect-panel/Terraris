// SPDX-License-Identifier: GPL-3.0-only
// Optional independent peer using pinned SagerNet/Polaris protocol code.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	SS "github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	S22 "github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type handler struct{}

func (handler) NewConnection(ctx context.Context, c net.Conn, metadata M.Metadata) error {
	defer c.Close()
	c.SetDeadline(time.Now().Add(20 * time.Second))
	upstream, err := (&net.Dialer{}).DialContext(ctx, "tcp", metadata.Destination.String())
	if err != nil {
		return err
	}
	defer upstream.Close()
	upstream.SetDeadline(time.Now().Add(20 * time.Second))
	done := make(chan struct{})
	go func() {
		io.Copy(upstream, c)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
		close(done)
	}()
	_, err = io.Copy(c, upstream)
	c.Close()
	upstream.Close()
	<-done
	return err
}
func (handler) NewPacketConnection(_ context.Context, c N.PacketConn, _ M.Metadata) error {
	defer c.Close()
	options := N.NewReadWaitOptions(c, c)
	for {
		buffer := options.NewPacketBuffer()
		destination, err := c.ReadPacket(buffer)
		// The legacy ReadPacket adapter reports io.EOF for a valid empty buffer;
		// destination is still present. Closed sessions have no destination.
		if err != nil && !(err == io.EOF && destination.Port != 0 && buffer.IsEmpty()) {
			buffer.Release()
			return err
		}
		options.PostReturn(buffer)
		if err = c.WritePacket(buffer, destination); err != nil {
			return err
		}
	}
}

func (handler) NewError(_ context.Context, _ error) {}

type service interface {
	N.TCPConnectionHandler
	N.UDPHandler
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	role := flag.String("role", "client", "client or server")
	name := flag.String("cipher", "aes-128-gcm", "method")
	password := flag.String("password", "", "test credential")
	server := flag.String("server", "127.0.0.1:0", "proxy address")
	tcpTarget := flag.String("tcp", "", "TCP echo")
	udpTarget := flag.String("udp", "", "UDP echo")
	testUot := flag.Bool("uot", false, "also test UoT v1/v2")
	flag.Parse()
	if *role == "vectors" {
		return vectors()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	var method SS.Method
	var err error
	modern := strings.HasPrefix(*name, "2022-")
	if modern {
		method, err = S22.NewWithPassword(*name, *password, nil)
	} else {
		method, err = shadowaead.New(*name, nil, *password)
	}
	if err != nil {
		return err
	}
	if *role == "server" {
		var impl service
		if modern {
			parts := strings.Split(*password, ":")
			if len(parts) == 2 {
				var svc *S22.MultiService[int]
				svc, err = S22.NewMultiServiceWithPassword[int](*name, parts[0], 60, handler{}, nil)
				if err == nil {
					err = svc.UpdateUsersWithPasswords([]int{1}, []string{parts[1]})
				}
				impl = svc
			} else {
				var svc SS.Service
				svc, err = S22.NewServiceWithPassword(*name, *password, 60, handler{}, nil)
				impl = svc
			}
		} else {
			var svc *shadowaead.MultiService[int]
			svc, err = shadowaead.NewMultiService[int](*name, 60, handler{})
			if err == nil {
				err = svc.UpdateUsersWithPasswords([]int{1}, []string{*password})
			}
			impl = svc
		}
		if err != nil {
			return err
		}
		if closer, ok := impl.(io.Closer); ok {
			defer closer.Close()
		}
		listener, err := net.Listen("tcp", *server)
		if err != nil {
			return err
		}
		defer listener.Close()
		socket, err := net.ListenPacket("udp", listener.Addr().String())
		if err != nil {
			return err
		}
		defer socket.Close()
		packet := bufio.NewPacketConn(socket)
		go func() {
			for {
				c, err := listener.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					impl.NewConnection(ctx, c, M.Metadata{Source: M.SocksaddrFromNet(c.RemoteAddr())})
				}()
			}
		}()
		go func() {
			for {
				buffer := buf.NewSize(65535)
				source, err := packet.ReadPacket(buffer)
				if err != nil {
					buffer.Release()
					return
				}
				if err = impl.NewPacket(ctx, packet, buffer, M.Metadata{Source: source}); err != nil {
					buffer.Release()
				}
			}
		}()
		fmt.Println("READY", listener.Addr())
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
		defer signal.Stop(stop)
		select {
		case <-stop:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	for iteration := 0; iteration < 2; iteration++ {
		raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", *server)
		if err != nil {
			return err
		}
		raw.SetDeadline(time.Now().Add(10 * time.Second))
		conn := method.DialEarlyConn(raw, M.ParseSocksaddr(*tcpTarget))
		payload := make([]byte, 256<<10)
		for i := range payload {
			payload[i] = byte(i*197 + iteration*71)
		}
		sent := make(chan error, 1)
		go func() { _, err := conn.Write(payload); sent <- err }()
		reply := make([]byte, len(payload))
		_, err = io.ReadFull(conn, reply)
		if err == nil {
			err = <-sent
		}
		conn.Close()
		if err != nil {
			return err
		}
		if !bytes.Equal(payload, reply) {
			return fmt.Errorf("TCP mismatch")
		}
	}
	raw, err := net.Dial("udp", *server)
	if err != nil {
		return err
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(10 * time.Second))
	packet := method.DialPacketConn(raw)
	destination, err := net.ResolveUDPAddr("udp", *udpTarget)
	if err != nil {
		return err
	}
	for _, payload := range [][]byte{{}, []byte("UDP"), bytes.Repeat([]byte{79}, 8192)} {
		if _, err = packet.WriteTo(payload, destination); err != nil {
			return err
		}
		reply := make([]byte, 65535)
		n, source, err := packet.ReadFrom(reply)
		if err != nil {
			return err
		}
		if source.String() != destination.String() || !bytes.Equal(payload, reply[:n]) {
			return fmt.Errorf("UDP mismatch")
		}
	}
	if *testUot {
		for _, version := range []int{1, 2} {
			raw, err := net.Dial("tcp", *server)
			if err != nil {
				return err
			}
			raw.SetDeadline(time.Now().Add(10 * time.Second))
			magic := uot.MagicAddress
			if version == 1 {
				magic = uot.LegacyMagicAddress
			}
			conn, err := method.DialConn(raw, M.Socksaddr{Fqdn: magic})
			if err != nil {
				raw.Close()
				return err
			}
			request := uot.Request{Destination: M.ParseSocksaddr(*udpTarget)}
			if version == 2 {
				if err = uot.WriteRequest(conn, request); err != nil {
					return err
				}
			}
			packet := uot.NewConn(conn, request)
			for _, p := range [][]byte{{}, []byte("uot")} {
				if _, err = packet.WriteTo(p, destination); err != nil {
					return err
				}
				reply := make([]byte, 65535)
				n, _, err := packet.ReadFrom(reply)
				if err != nil || !bytes.Equal(p, reply[:n]) {
					return fmt.Errorf("UoT mismatch: %v", err)
				}
			}
			conn.Close()
		}
	}
	fmt.Println("Shadowsocks TCP/UDP passed", *name)
	return nil
}
