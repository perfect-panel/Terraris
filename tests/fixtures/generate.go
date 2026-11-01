// SPDX-License-Identifier: GPL-3.0-only

//go:build ignore

// Run from the PPanel backend checkout; see README.md in this directory.
package main

import (
	"os"
	"path/filepath"

	serverv1 "github.com/perfect-panel/server/api/server/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

func main() {
	if len(os.Args) != 2 {
		panic("expected fixture output directory")
	}
	const sid int64 = 9007199254740993
	plugin, err := structpb.NewValue(map[string]any{"mode": "websocket", "tls": true})
	if err != nil {
		panic(err)
	}
	messages := map[string]proto.Message{
		"config.pb": &serverv1.QueryServerProtocolConfigResponse{
			Code: 200, Message: "success", Data: &serverv1.QueryServerProtocolConfigData{
				PullInterval: 30, PushInterval: 60, TrafficReportThreshold: 1024, IpStrategy: "prefer_ipv4", Total: 1,
				Protocols: []*serverv1.ServerProtocol{{Type: "shadowsocks", Port: 8388, Enable: true,
					Cipher: "2022-blake3-aes-128-gcm", ServerKey: "fixture-server-key", PluginOptions: plugin, Ratio: 1}},
			},
		},
		"users.pb": &serverv1.GetServerUserListResponse{Code: 200, Message: "success",
			Data: &serverv1.ServerUserListData{Users: []*serverv1.ServerUser{{Id: sid, Uuid: "fixture-user-key", SpeedLimit: 100, DeviceLimit: 2}}}},
		"alive.pb": &serverv1.GetServerAliveListResponse{Code: 200, Message: "success",
			Data: &serverv1.ServerAliveListData{Alive: map[int64]int64{sid: 2}}},
		"device.pb": &serverv1.ClaimServerDeviceResponse{Code: 200, Message: "success",
			Data: &serverv1.ServerDeviceClaimData{Allowed: true, TtlSeconds: 300}},
		"ack.pb":             &serverv1.Result{Code: 200, Message: "success"},
		"traffic-request.pb": &serverv1.PushUserTrafficRequest{Traffic: []*serverv1.UserTraffic{{UserId: sid, Upload: 19, Download: 23}}},
		"online-request.pb":  &serverv1.PushOnlineUsersRequest{Users: []*serverv1.OnlineUser{{UserId: sid, Ip: "127.0.0.1"}}},
		"device-request.pb":  &serverv1.ClaimServerDeviceRequest{UserId: sid, Ip: "127.0.0.1"},
		"status-request.pb":  &serverv1.PushServerStatusRequest{Cpu: 1, Mem: 2, Disk: 3, UpdatedAt: 1800000000000},
	}
	for name, message := range messages {
		body, err := (proto.MarshalOptions{Deterministic: true}).Marshal(message)
		if err != nil {
			panic(err)
		}
		if err := os.WriteFile(filepath.Join(os.Args[1], name), body, 0644); err != nil {
			panic(err)
		}
	}
}
