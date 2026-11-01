#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Local release-node benchmark using the pinned Polaris XHTTP client.

No real panel or credentials are used. The node, client and echo share the host;
this is a repeatable pressure check, not a production capacity estimate.
"""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import threading
import time

UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"


def free_port(udp=False):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def rss_mib(process):
    value = subprocess.check_output(["ps", "-o", "rss=", "-p", str(process.pid)], text=True)
    return int(value.strip()) / 1024


def run(args):
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        raise ValueError("benchmark output directory must be empty")
    output.mkdir(parents=True, exist_ok=True)
    repository = Path(__file__).resolve().parents[3]
    results = []
    config = {}
    children = []
    logs = []

    class Panel(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def respond(self, value):
            body = json.dumps(value).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if "/v2/server/" in self.path:
                self.respond(config)
            elif "/user" in self.path:
                self.respond({"users": [{"id": 1, "uuid": UUID, "speed_limit": 0, "device_limit": 0}]})
            else:
                self.respond({"alivelist": []})

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            self.respond({"code": 200, "msg": "success"})

    panel = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Panel)
    threading.Thread(target=panel.serve_forever, daemon=True).start()
    try:
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(output / "key.pem"), "-out", str(output / "cert.pem"),
            "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        echo = subprocess.Popen([str(args.polaris), "-role", "echo"], stdout=subprocess.PIPE, text=True)
        children.append(echo)
        if not select.select([echo.stdout], [], [], 10)[0]:
            raise RuntimeError("echo readiness timeout")
        ready = echo.stdout.readline().strip()
        if not ready.startswith("READY "):
            raise RuntimeError("echo did not start: " + ready)
        target = ready.removeprefix("READY ")
        metadata = {
            "node_sha256": hashlib.sha256(args.node.read_bytes()).hexdigest(),
            "client_sha256": hashlib.sha256(args.polaris.read_bytes()).hexdigest(),
            "client_source": "Polaris 56d52fb44958ef3cc2a7fb841cd240f8206234b2",
            "node_source": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repository, text=True).strip(),
            "source_patch_sha256": hashlib.sha256(subprocess.check_output(["git", "diff", "--binary"], cwd=repository)).hexdigest(),
            "topology": "Polaris client -> Terraris VLESS/XHTTP with direct egress -> TCP echo, IPv4 loopback",
            "mode": "packet-up", "xhttp_extra": {}, "verified_tls": True,
            "single_seconds": args.single_seconds, "concurrent_seconds": args.seconds,
            "concurrency": args.connections, "rounds": args.rounds, "warmup_seconds": 1,
            "throughput": "received application bytes only, decimal Gbit/s; not upload+download sum",
            "rss": "Terraris only; ps every 200ms, MiB; sampled peak, excludes client and echo",
            "validity": "zero unexpected I/O errors/corrupt reads; all flows receive; no 5-second stall",
            "default_limits": {"memory_bytes": 67108864, "buffer_slots": 16384,
                               "connection_memory_bytes": 4194304, "connection_buffer_slots": 256},
            "test_overrides": "loopback, synthetic panel/user/TLS; drain 1s/shutdown 3s for teardown",
            "environment": "shared host, no CPU pinning or network impairment",
        }
        (output / "metadata.json").write_text(json.dumps(metadata, indent=2))
        for repetition in range(args.rounds):
            for alpn in args.alpn:
                port = free_port(alpn == "h3")
                config.clear()
                config.update({"code": 200, "data": {
                    "pull_interval": 300, "push_interval": 300, "traffic_report_threshold": 1048576,
                    "ip_strategy": "prefer_ipv4", "dns": [], "block": [], "outbound": [], "total": 1,
                    "protocols": [{"type": "vless", "enable": True, "port": port, "network": "xhttp",
                                   "security": "tls", "cert_mode": "file", "sni": "localhost", "alpn": [alpn],
                                   "host": "localhost", "path": "/relay", "xhttp_mode": "packet-up", "xhttp_extra": "{}"}],
                }})
                node_config = output / "node.toml"
                node_config.write_text(
                    f"[panel]\nbase_url='http://127.0.0.1:{panel.server_port}'\nserver_id=7\n"
                    "secret_env='TERRARIS_BENCH_SECRET'\nwire_format='json'\n[node]\nlisten='127.0.0.1'\n"
                    "drain_timeout_seconds=1\nshutdown_timeout_seconds=3\n[tls]\n"
                    f"cert_file='{output}/cert.pem'\nkey_file='{output}/key.pem'\n"
                )
                node_log = output / f"{alpn}-{repetition}-node.log"
                log = node_log.open("w")
                logs.append(log)
                node = subprocess.Popen([str(args.node), "run", "--config", str(node_config)],
                                        env={**os.environ, "TERRARIS_BENCH_SECRET": "benchmark-fixture"},
                                        stdout=log, stderr=log)
                children.append(node)
                for _ in range(200):
                    if node.poll() is not None:
                        raise RuntimeError("node failed: " + node_log.read_text())
                    if "Node configuration applied" in node_log.read_text():
                        break
                    time.sleep(0.05)
                else:
                    raise RuntimeError("node readiness timeout")
                time.sleep(0.5)
                idle = rss_mib(node)
                for connections in [1, args.connections]:
                    duration = args.single_seconds if connections == 1 else args.seconds
                    client = subprocess.Popen([
                        str(args.polaris), "-role", "client", "-server", f"127.0.0.1:{port}",
                        "-target", target, "-alpn", alpn, "-cert", str(output / "cert.pem"),
                        "-mode", "packet-up", "-extra", "{}", "-concurrency", str(connections),
                        "-duration", f"{duration}s",
                    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    children.append(client)
                    samples = []
                    started = time.monotonic()
                    while client.poll() is None:
                        if time.monotonic() - started > duration + 25:
                            raise RuntimeError("benchmark timeout")
                        samples.append(rss_mib(node))
                        time.sleep(0.2)
                    stdout, stderr = client.communicate()
                    if client.returncode:
                        raise RuntimeError("benchmark client failed: " + stderr)
                    result = json.loads(stdout.splitlines()[-1])
                    result.update(transport=f"xhttp-{alpn}", repetition=repetition,
                                  idle_rss_mib=idle, peak_rss_mib=max(samples))
                    time.sleep(0.5)
                    result["after_rss_mib"] = rss_mib(node)
                    result["valid"] = (result["unexpected_io_errors"] == 0 and result["corrupt_reads"] == 0
                                       and all(result["flow_received_bytes"]) and result["max_no_progress_seconds"] < 5)
                    results.append(result)
                    (output / "results.json").write_text(json.dumps(results, indent=2))
                    print(json.dumps(result), flush=True)
                    if not result["valid"]:
                        raise RuntimeError("unstable measurement: " + alpn)
                stop(node)
                log.close()
    finally:
        for child in reversed(children):
            stop(child)
        for log in logs:
            log.close()
        panel.shutdown()
        (output / "results.json").write_text(json.dumps(results, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--polaris", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--single-seconds", type=int, default=15)
    parser.add_argument("--connections", type=int, default=16)
    parser.add_argument("--rounds", type=int, default=2)
    parser.add_argument("--alpn", nargs="+", choices=["h2", "h3"], default=["h3", "h2"])
    options = parser.parse_args()
    if not (1 <= options.connections <= 128 and 1 <= options.rounds <= 10
            and 1 <= options.seconds <= 3600 and 1 <= options.single_seconds <= 3600):
        parser.error("invalid benchmark limits")
    options.node = options.node.resolve()
    options.polaris = options.polaris.resolve()
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
    run(options)
