#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Server-side: Network test + UDP IPv6 -> IPv4 forwarder.

Flow:
1. Load config from server_config.json (auto-create default if missing)
2. Auto-detect local global IPv6 address for listening
3. Test IPv4 public network connectivity
4. Test IPv6 public network connectivity
5. If both pass, start UDP IPv6 -> IPv4 forwarder
"""

import socket
import select
import time
import sys
import json
import os
import urllib.request
from datetime import datetime

# ============================================================
# Hardcoded network test targets (domestic CN nodes, stable)
# ============================================================
IPV4_TEST_URL = "https://www.baidu.com"
IPV6_TEST_URL = "https://www.taobao.com"

# ============================================================
# Forwarder defaults
# ============================================================
DEFAULT_TARGET_IPV4 = "127.0.0.1"   # forward to local IPv4 service by default
DEFAULT_BUFFER_SIZE = 65535
DEFAULT_SESSION_TIMEOUT = 60
DEFAULT_CLEANUP_INTERVAL = 10

# ============================================================
# Default server config (used when server_config.json is missing)
# Format: [external_port]  OR  [external_port, local_port]
#         OR  [external_port, local_ipv4, local_port]
# ============================================================
DEFAULT_SERVER_CONFIG = {
    "port_mappings": [
        [25565],
        [19132],
    ],
}

# When packaged with PyInstaller (--onefile), __file__ points to a temp
# extraction dir. Use sys.executable's dir so the config sits next to the exe.
if getattr(sys, "frozen", False):
    SCRIPT_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SERVER_CONFIG_PATH = os.path.join(SCRIPT_DIR, "server_config.json")


def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def load_or_create_config(path, default_config):
    """Load JSON config; if file missing, create it with defaults and return it."""
    if not os.path.exists(path):
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(default_config, f, indent=4, ensure_ascii=False)
            log(f"[cfg] Created default config: {path}")
        except OSError as e:
            log(f"[cfg] Cannot create {path}: {e}, using in-memory defaults")
        return dict(default_config)
    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        return {k: v for k, v in cfg.items() if not k.startswith("_")}
    except (OSError, json.JSONDecodeError) as e:
        log(f"[cfg] Cannot parse {path}: {e}, using in-memory defaults")
        return dict(default_config)


def normalize_port_mappings(raw_mappings, default_target_ipv4):
    """Normalize flexible port mapping format to (listen_port, target_ipv4, target_port).

    Accepted forms:
      [external_port]
      [external_port, local_port]
      [external_port, local_ipv4, local_port]
    """
    result = []
    for entry in raw_mappings:
        if not isinstance(entry, list) or len(entry) < 1:
            log(f"[cfg] Skip invalid entry: {entry}")
            continue
        try:
            external_port = int(entry[0])
            if len(entry) == 1:
                local_ipv4 = default_target_ipv4
                local_port = external_port
            elif len(entry) == 2:
                local_ipv4 = default_target_ipv4
                local_port = int(entry[1])
            else:
                local_ipv4 = str(entry[1])
                local_port = int(entry[2])
            result.append((external_port, local_ipv4, local_port))
        except (ValueError, IndexError) as e:
            log(f"[cfg] Skip invalid entry {entry}: {e}")
    return result


def detect_local_global_ipv6():
    """Auto-detect local global IPv6 address (2000::/3, non-link-local)."""
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.connect(("2606:4700:4700::1111", 53))
        addr = s.getsockname()[0]
        s.close()
        if addr.startswith("2"):
            return addr
    except OSError:
        pass
    # Fallback: enumerate interfaces
    try:
        hostname = socket.gethostname()
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET6)
        for info in infos:
            addr = info[4][0]
            if addr.startswith("2") and not addr.startswith("fe80"):
                return addr.split("%")[0]
    except OSError:
        pass
    return None


def test_ipv4():
    """Test IPv4 public connectivity."""
    try:
        req = urllib.request.Request(IPV4_TEST_URL, method="HEAD")
        orig_getaddrinfo = socket.getaddrinfo
        def ipv4_only(host, port, family=0, type=0, proto=0, flags=0):
            return orig_getaddrinfo(host, port, socket.AF_INET, type, proto, flags)
        socket.getaddrinfo = ipv4_only
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                code = resp.status
        finally:
            socket.getaddrinfo = orig_getaddrinfo
        if 200 <= code < 400:
            log(f"  [OK]   IPv4 -> {IPV4_TEST_URL}  (HTTP {code})")
            return True
        log(f"  [FAIL] IPv4 -> {IPV4_TEST_URL}  (HTTP {code})")
        return False
    except Exception as e:
        log(f"  [FAIL] IPv4 test error: {e}")
        return False


def test_ipv6():
    """Test IPv6 public connectivity."""
    try:
        req = urllib.request.Request(IPV6_TEST_URL, method="HEAD")
        orig_getaddrinfo = socket.getaddrinfo
        def ipv6_only(host, port, family=0, type=0, proto=0, flags=0):
            return orig_getaddrinfo(host, port, socket.AF_INET6, type, proto, flags)
        socket.getaddrinfo = ipv6_only
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                code = resp.status
        finally:
            socket.getaddrinfo = orig_getaddrinfo
        if 200 <= code < 400:
            log(f"  [OK]   IPv6 -> {IPV6_TEST_URL}  (HTTP {code})")
            return True
        log(f"  [FAIL] IPv6 -> {IPV6_TEST_URL}  (HTTP {code})")
        return False
    except Exception as e:
        log(f"  [FAIL] IPv6 test error: {e}")
        return False


def run_network_tests():
    log("=" * 60)
    log("Network connectivity test")
    log("=" * 60)
    v4_ok = test_ipv4()
    v6_ok = test_ipv6()
    log("-" * 60)
    if v4_ok and v6_ok:
        log("[PASS] Both IPv4 and IPv6 are available.")
        return True
    if v4_ok:
        log("[WARN] Only IPv4 is available. IPv6 is required for this server.")
    elif v6_ok:
        log("[WARN] Only IPv6 is available. IPv4 is required to reach local service.")
    else:
        log("[FAIL] No public network access. Check your connection.")
    log("-" * 60)
    return False


def run_forwarder(port_mappings):
    log("=" * 60)
    log("Starting UDP IPv6 -> IPv4 forwarder")
    log("=" * 60)

    listen_ipv6 = "::"
    buffer_size = DEFAULT_BUFFER_SIZE
    session_timeout = DEFAULT_SESSION_TIMEOUT
    cleanup_interval = DEFAULT_CLEANUP_INTERVAL

    v6_to_config = {}
    v4_to_session = {}
    client_to_v4 = {}
    v6_sockets = []

    for external_port, target_ipv4, target_port in port_mappings:
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            sock.bind((listen_ipv6, external_port))
            sock.setblocking(False)
            v6_to_config[sock] = (external_port, target_ipv4, target_port)
            v6_sockets.append(sock)
            log(f"[OK]   IPv6 :{external_port}  ->  {target_ipv4}:{target_port}")
        except OSError as e:
            log(f"[FAIL] Cannot bind IPv6 :{external_port}  ->  {e}")

    if not v6_sockets:
        log("No listening sockets. Exiting.")
        return 1

    log(f"Forwarder running. {len(v6_sockets)} port(s). Ctrl+C to stop.")
    log("-" * 60)

    last_cleanup = time.time()
    try:
        while True:
            all_readable = v6_sockets + list(v4_to_session.keys())
            r, _, _ = select.select(all_readable, [], [], 1)
            now = time.time()

            for sock in r:
                if sock in v6_to_config:
                    listen_port, target_ipv4, target_port = v6_to_config[sock]
                    try:
                        data, client_addr = sock.recvfrom(buffer_size)
                    except OSError:
                        continue
                    key = (listen_port, client_addr)
                    v4_sock = client_to_v4.get(key)
                    if v4_sock is None:
                        v4_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        v4_sock.setblocking(False)
                        v4_to_session[v4_sock] = {
                            "client_addr": client_addr,
                            "v6_sock": sock,
                            "listen_port": listen_port,
                            "target": (target_ipv4, target_port),
                            "last_seen": now,
                        }
                        client_to_v4[key] = v4_sock
                        log(f"[new]   {client_addr[0]}:{client_addr[1]}  ->  port {listen_port}")
                    else:
                        v4_to_session[v4_sock]["last_seen"] = now
                    try:
                        v4_sock.sendto(data, (target_ipv4, target_port))
                    except OSError as e:
                        log(f"[err]   forward to {target_ipv4}:{target_port} failed: {e}")
                else:
                    session = v4_to_session.get(sock)
                    if session is None:
                        continue
                    try:
                        data, _ = sock.recvfrom(buffer_size)
                    except OSError:
                        continue
                    session["last_seen"] = now
                    try:
                        session["v6_sock"].sendto(data, session["client_addr"])
                    except OSError as e:
                        log(f"[err]   reply to {session['client_addr']} failed: {e}")

            if now - last_cleanup > cleanup_interval:
                last_cleanup = now
                expired = [s for s, sess in v4_to_session.items()
                           if now - sess["last_seen"] > session_timeout]
                for s in expired:
                    sess = v4_to_session.pop(s)
                    key = (sess["listen_port"], sess["client_addr"])
                    if client_to_v4.get(key) is s:
                        del client_to_v4[key]
                    s.close()
                    log(f"[idle]  {sess['client_addr'][0]}:{sess['client_addr'][1]}  on port {sess['listen_port']} closed")
    except KeyboardInterrupt:
        log("-" * 60)
        log("Stopping...")
        for sock in v6_sockets:
            sock.close()
        for sock in list(v4_to_session.keys()):
            sock.close()
        log("Stopped.")
    return 0


def main():
    log("=" * 60)
    log("Server: loading config")
    log("=" * 60)
    cfg = load_or_create_config(SERVER_CONFIG_PATH, DEFAULT_SERVER_CONFIG)
    port_mappings = normalize_port_mappings(cfg.get("port_mappings", []), DEFAULT_TARGET_IPV4)

    log(f"[cfg] server_config.json: {len(port_mappings)} port mapping(s)")
    for ext, ipv4, port in port_mappings:
        log(f"       {ext}  ->  {ipv4}:{port}")

    log("-" * 60)
    log("Detecting local global IPv6 address...")
    local_v6 = detect_local_global_ipv6()
    if local_v6:
        log(f"[OK]   Local IPv6: {local_v6}")
        log(f"       External clients should connect to: [{local_v6}]:<port>")
    else:
        log("[WARN] No global IPv6 address detected. Will still listen on '::'.")
    log("-" * 60)

    if not run_network_tests():
        log("Aborting: network tests failed.")
        return 1
    return run_forwarder(port_mappings)


if __name__ == "__main__":
    sys.exit(main())
