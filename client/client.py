#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Client-side: Network test + UDP IPv4 -> IPv6 forwarder.

Flow:
1. Load config from client_config.json (auto-create default if missing)
2. Test IPv4 public network connectivity
3. Test IPv6 public network connectivity
4. If both pass, start UDP IPv4 -> IPv6 forwarder
"""

import socket
import select
import time
import sys
import json
import os
import subprocess
import urllib.request
from datetime import datetime

# ============================================================
# Network connectivity test targets
# ------------------------------------------------------------
# We use raw TCP socket connect (NOT HTTP/urllib) to bypass system
# HTTP proxies. A TCP connect to port 443 on well-known anycast IPs
# verifies real bidirectional reachability:
#   - HTTP/SOCKS proxies configured at application level are bypassed
#   - Full-tunnel VPNs (WARP, WireGuard TUN, etc.) are NOT bypassed,
#     but that's correct: if the VPN has no IPv6 exit, the forwarder
#     truly can't work either.
#   - Game accelerators typically hook specific game ports (25565/19132),
#     not port 443, so we get the true connectivity picture.
# ============================================================
IPV4_PROBE_TARGETS = (
    ("223.5.5.5", 443),           # Alibaba DNS (China, fast)
    ("119.29.29.29", 443),        # Tencent DNS (China)
    ("8.8.8.8", 443),             # Google DNS (fallback)
    ("1.1.1.1", 443),             # Cloudflare DNS (fallback)
)

IPV6_PROBE_TARGETS = (
    ("2606:4700:4700::1111", 443),  # Cloudflare DNS
    ("2001:4860:4860::8888", 443),  # Google DNS
    ("240c::6666", 443),            # CERNET2 (China, if reachable)
)

# ============================================================
# Forwarder defaults
# ============================================================
DEFAULT_LISTEN_IPV4 = "127.0.0.1"   # listen on local loopback by default
DEFAULT_BUFFER_SIZE = 65535
DEFAULT_SESSION_TIMEOUT = 60
DEFAULT_CLEANUP_INTERVAL = 10

# ============================================================
# VPN / proxy / game accelerator detection
# ------------------------------------------------------------
# Matched as substrings (lowercase) against running process names.
# False positives are acceptable - the list is only used to print a
# WARNING when network tests fail, never to block startup.
# ============================================================
VPN_PROCESS_PATTERNS = (
    # Generic proxies
    "clash", "mihomo", "v2ray", "v2rayn", "xray", "sing-box",
    "shadowsocks", "shadowsocksr", "ssr", "trojan", "naive",
    # Tunneling protocols / clients
    "warp", "wireguard", "wg", "tailscale", "openvpn", "ovpn",
    "hamachi", "zerotier", "zerotier-one",
    # Commercial VPN clients
    "nordvpn", "expressvpn", "mullvad", "surfshark", "protonvpn",
    "cyberghost", "pia-", "privatevpn",
    # China-specific
    "surgemac", "quantumult", "shadowrocket", "peclash",
)

ACCELERATOR_PROCESS_PATTERNS = (
    # 网易UU加速器
    "uu.exe", "uu_", "uuacc",
    # 迅游加速器
    "xunyou", "xyacc",
    # 雷神加速器
    "leigod", "leidianacc", "leidian",
    # BiuBiu加速器
    "biubiu",
    # 腾讯加速器 / TGP
    "tgpacc", "txgameaccelerator", "qqacc",
    # 迅雷加速器
    "xunleiacc",
    # 海豚加速器
    "haitunacc", "haitun",
    # 27加速器
    "27acc",
    # 浅蓝加速器
    "qianlanacc",
    # 雷云 / UU网游加速器
    "uu网游", "uu加速",
    # 通用关键词（Chinese names may appear as UTF-8 in process list）
    "加速器",
)

# Virtual / tunnel interface name fragments (lowercase match)
TUNNEL_INTERFACE_PATTERNS = (
    # Windows
    "wintun", "tap-windows", "tap0", "openvpn",
    "cloudflare", "warp",
    "wireguard", "tailscale", "zerotier", "hamachi",
    "nord", "express", "mullvad", "surfshark",
    # Linux
    "tun", "tap", "wg", "ppp", "ovpn", "ipsec",
    # macOS
    "utun",
)

# ============================================================
# Default client config (used when client_config.json is missing)
# Format: [local_port, remote_ipv6, remote_port]
#
# Optional keys:
#   "skip_network_test": true   - skip the IPv4/IPv6 connectivity test at
#                                 startup. Useful when you are behind a VPN
#                                 or game accelerator that breaks the HTTP
#                                 probe but you know UDP forwarding will
#                                 still work. Default: false.
# ============================================================
DEFAULT_CLIENT_CONFIG = {
    "port_mappings": [
        [25565, "2001:4860:4860::8888", 25565],
        [19132, "2001:4860:4860::8888", 19132],
    ],
    "skip_network_test": False,
}

# When packaged with PyInstaller (--onefile), __file__ points to a temp
# extraction dir. Use sys.executable's dir so the config sits next to the exe.
if getattr(sys, "frozen", False):
    SCRIPT_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CLIENT_CONFIG_PATH = os.path.join(SCRIPT_DIR, "client_config.json")


def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


# ============================================================
# VPN / proxy / game accelerator detection
# ============================================================
def _list_process_names():
    """Return a list of running process names (best-effort, cross-platform).

    Uses psutil if available; otherwise falls back to platform-specific
    commands (tasklist on Windows, ps on Unix). Never raises.
    """
    # psutil path
    try:
        import psutil  # type: ignore
        names = []
        for p in psutil.process_iter(["name"]):
            try:
                n = p.info.get("name")
                if n:
                    names.append(n)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        if names:
            return names
    except (ImportError, Exception):
        pass

    # Platform fallback
    if sys.platform == "win32":
        try:
            res = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True, timeout=5,
                # tasklist uses the OEM codepage (CP936/GBK on Chinese Windows),
                # NOT UTF-8. Use errors='replace' so decode failures don't
                # crash us - we only match ASCII patterns anyway.
                encoding="utf-8", errors="replace",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            stdout = res.stdout or ""
            names = []
            for line in stdout.splitlines():
                line = line.strip()
                if line.startswith('"'):
                    # CSV: "name.exe","pid",...
                    name = line.split('","', 1)[0].strip('"')
                    if name:
                        names.append(name)
            return names
        except (OSError, subprocess.SubprocessError):
            return []
    else:
        # Linux / macOS: ps -e -o comm=
        try:
            res = subprocess.run(
                ["ps", "-e", "-o", "comm="],
                capture_output=True, text=True, timeout=5,
                errors="replace",
            )
            stdout = res.stdout or ""
            return [l.strip() for l in stdout.splitlines() if l.strip()]
        except (OSError, subprocess.SubprocessError):
            return []


def _list_tunnel_interfaces():
    """Return list of virtual/tunnel network adapter names (best-effort)."""
    # psutil path
    try:
        import psutil  # type: ignore
        result = []
        try:
            stats = psutil.net_if_stats()
        except Exception:
            stats = {}
        try:
            addrs = psutil.net_if_addrs()
        except Exception:
            addrs = {}
        for ifname in addrs.keys():
            if _is_tunnel_interface(ifname):
                result.append(ifname)
        return result
    except (ImportError, Exception):
        pass

    # Platform fallback
    if sys.platform == "win32":
        try:
            res = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-NetAdapter | Select-Object -ExpandProperty Name"],
                capture_output=True, timeout=5,
                encoding="utf-8", errors="replace",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            stdout = res.stdout or ""
            return [l.strip() for l in stdout.splitlines()
                    if l.strip() and _is_tunnel_interface(l.strip())]
        except (OSError, subprocess.SubprocessError):
            pass
    elif os.path.exists("/proc/net/dev"):
        try:
            with open("/proc/net/dev", "r") as f:
                result = []
                for line in f:
                    name = line.split(":", 1)[0].strip()
                    if name and _is_tunnel_interface(name):
                        result.append(name)
                return result
        except OSError:
            pass
    return []


def _is_tunnel_interface(name):
    """Check if interface name matches known VPN/tunnel patterns."""
    if not name:
        return False
    low = name.lower()
    return any(hint in low for hint in TUNNEL_INTERFACE_PATTERNS)


def _get_system_proxy():
    """Return first system proxy URL, or None if no proxy is configured."""
    try:
        proxies = urllib.request.getproxies()
    except Exception:
        return None
    if not proxies:
        return None
    # Prefer http/https, fall back to any
    for key in ("http", "https", "ftp", "all"):
        if key in proxies:
            return proxies[key]
    # Return any value
    return next(iter(proxies.values()))


def detect_vpn_and_accelerators():
    """Detect VPN / proxy / game accelerator presence on this host.

    Returns a dict:
      {
        "system_proxy":        "http://127.0.0.1:7890" or None,
        "vpn_processes":       ["clash.exe", ...],
        "accelerator_processes": ["uu.exe", ...],
        "tunnel_interfaces":   ["wintun", "CloudflareWARP", ...],
        "default_v6_route_if": "wintun" or None,  # only if different from physical
      }

    Best-effort: never raises, returns partial info if some sources fail.
    """
    findings = {
        "system_proxy": None,
        "vpn_processes": [],
        "accelerator_processes": [],
        "tunnel_interfaces": [],
        "default_v6_route_if": None,
    }

    # 1. System proxy
    findings["system_proxy"] = _get_system_proxy()

    # 2. Process scan
    procs = _list_process_names()
    seen_vpn = set()
    seen_acc = set()
    for name in procs:
        low = name.lower()
        for pat in VPN_PROCESS_PATTERNS:
            if pat in low and name not in seen_vpn:
                seen_vpn.add(name)
                break
        for pat in ACCELERATOR_PROCESS_PATTERNS:
            if pat in low and name not in seen_acc:
                seen_acc.add(name)
                break
    findings["vpn_processes"] = sorted(seen_vpn)
    findings["accelerator_processes"] = sorted(seen_acc)

    # 3. Tunnel interfaces
    findings["tunnel_interfaces"] = _list_tunnel_interfaces()

    # 4. Default IPv6 route interface (best-effort; helps detect full-tunnel VPN)
    findings["default_v6_route_if"] = _get_default_ipv6_route_interface()

    return findings


def _get_default_ipv6_route_interface():
    """Return the interface name for the default IPv6 route (::/0).

    On Windows uses `Get-NetRoute`. On Linux reads /proc/net/ipv6_route.
    Returns None if the route cannot be determined or the command fails.
    """
    if sys.platform == "win32":
        try:
            res = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-NetRoute -DestinationPrefix '::/0' -ErrorAction SilentlyContinue "
                 "| Select-Object -First 1 -ExpandProperty InterfaceAlias"],
                capture_output=True, timeout=5,
                encoding="utf-8", errors="replace",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            out = (res.stdout or "").strip()
            if out:
                return out
        except (OSError, subprocess.SubprocessError):
            pass
        return None
    elif os.path.exists("/proc/net/ipv6_route"):
        # Format: dest_prefix next_hop prefix metric ref use flags ifindex ifname
        # Default route: dest_prefix = "00000000000000000000000000000000" and prefix = "00"
        try:
            with open("/proc/net/ipv6_route", "r") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) < 10:
                        continue
                    if parts[0] == "0" * 32 and parts[1] == "00":
                        # parts[9] is ifname
                        return parts[9]
        except OSError:
            pass
        return None
    return None


def has_vpn_like_setup(findings):
    """True if any VPN / proxy / accelerator indicator was found."""
    return bool(
        findings.get("system_proxy")
        or findings.get("vpn_processes")
        or findings.get("accelerator_processes")
        or findings.get("tunnel_interfaces")
    )


def print_vpn_warning(findings):
    """Print a multi-line Chinese warning summarising detected VPN/accelerator items.

    Only prints if something was detected. Intended to be called when a
    network test fails, so the operator knows interference is plausible.
    """
    if not has_vpn_like_setup(findings):
        return
    log("=" * 60)
    log("[警告] 检测到 VPN / 代理 / 游戏加速器，可能干扰转发：")
    if findings.get("system_proxy"):
        log(f"       - 系统代理        : {findings['system_proxy']}")
        log("         (系统代理会劫持 HTTP 测试流量，可能导致网络测试误报失败。")
        log("          已改用 TCP 直连方式检测，可绕过 HTTP 代理干扰。)")
    if findings.get("vpn_processes"):
        log(f"       - VPN 客户端进程  : {', '.join(findings['vpn_processes'])}")
        log("         (全隧道 VPN 会劫持出站 IPv6 流量，发往远端 IPv6 的数据包")
        log("          可能无法到达服务端。建议在 VPN 中将远端 IPv6 加入绕过/直连列表。)")
    if findings.get("accelerator_processes"):
        log(f"       - 游戏加速器进程  : {', '.join(findings['accelerator_processes'])}")
        log("         (加速器通常劫持特定游戏端口 (25565/19132 等)，可能导致")
        log("          转发流量被加速节点拦截。建议在加速器中将远端 IPv6 加入直连列表，")
        log("          或直接关闭加速器。)")
    if findings.get("tunnel_interfaces"):
        log(f"       - 隧道网卡        : {', '.join(findings['tunnel_interfaces'])}")
    if findings.get("default_v6_route_if") and \
            _is_tunnel_interface(findings["default_v6_route_if"]):
        log(f"       - 默认 IPv6 路由出口: {findings['default_v6_route_if']}")
        log("         (该网卡承载所有出站 IPv6 流量。如果是 VPN 隧道，")
        log("          转发器将无法直接到达 IPv6 服务端，需配置绕过路由。)")
    log("       建议：")
    log("         1. 将远端 IPv6 地址加入 VPN/加速器的直连/绕过列表。")
    log("         2. 或在 client_config.json 中设置 \"skip_network_test\": true")
    log("            跳过连通性测试直接启动转发器。")
    log("=" * 60)


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


def normalize_port_mappings(raw_mappings):
    """Normalize port mapping format to (listen_port, remote_ipv6, remote_port).

    Accepted form:
      [local_port, remote_ipv6, remote_port]
    """
    result = []
    for entry in raw_mappings:
        if not isinstance(entry, list) or len(entry) < 3:
            log(f"[cfg] Skip invalid entry (need [local_port, remote_ipv6, remote_port]): {entry}")
            continue
        try:
            local_port = int(entry[0])
            remote_ipv6 = str(entry[1])
            remote_port = int(entry[2])
            result.append((local_port, remote_ipv6, remote_port))
        except (ValueError, IndexError) as e:
            log(f"[cfg] Skip invalid entry {entry}: {e}")
    return result


def test_ipv4():
    """Test IPv4 public connectivity via raw TCP socket connect.

    Uses TCP connect to port 443 on well-known anycast IPs. This bypasses
    HTTP/SOCKS application-level proxies that break the old urllib approach.
    If TCP fails (firewall may block 443), falls back to a DNS-over-UDP
    query, which is closer to what the forwarder actually does.
    """
    # Try TCP first - fast and reliable when it works
    for host, port in IPV4_PROBE_TARGETS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            try:
                s.connect((host, port))
            finally:
                s.close()
            log(f"  [OK]   IPv4 -> {host}:{port}  (TCP connect)")
            return True
        except OSError:
            continue
    # Fallback: DNS query via UDP (port 53). This verifies real
    # bidirectional UDP reachability - same protocol as the forwarder.
    for host, _port in IPV4_PROBE_TARGETS:
        if _dns_udp_probe(host, socket.AF_INET):
            log(f"  [OK]   IPv4 -> {host}  (DNS UDP)")
            return True
    log(f"  [FAIL] IPv4 -> all targets failed (TCP + UDP DNS)")
    return False


def test_ipv6():
    """Test IPv6 public connectivity via raw TCP socket connect.

    Same strategy as test_ipv4(): TCP 443 first, DNS-over-UDP fallback.
    The UDP fallback is important because many firewalls allow UDP but
    block outbound TCP to non-standard ports.
    """
    # Try TCP first
    for host, port in IPV6_PROBE_TARGETS:
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s.settimeout(5)
            try:
                s.connect((host, port))
            finally:
                s.close()
            log(f"  [OK]   IPv6 -> [{host}]:{port}  (TCP connect)")
            return True
        except OSError:
            continue
    # Fallback: DNS query via UDP
    for host, _port in IPV6_PROBE_TARGETS:
        if _dns_udp_probe(host, socket.AF_INET6):
            log(f"  [OK]   IPv6 -> [{host}]  (DNS UDP)")
            return True
    log(f"  [FAIL] IPv6 -> all targets failed (TCP + UDP DNS)")
    return False


def _dns_udp_probe(host, family):
    """Send a minimal DNS query to `host`:53 and check for any response.

    Returns True if a DNS response packet is received within 3 seconds.
    This verifies real bidirectional connectivity using UDP, which is the
    same protocol the forwarder uses.
    """
    # Minimal DNS query: A record for "a.com" (0x01 0x00 0x00 0x00...)
    # Header: ID=0x1234, flags=0x0100 (standard query, recursion desired),
    #         QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    # Question: "a.com" type A class IN
    query = (
        b"\x12\x34"   # ID
        b"\x01\x00"   # flags: standard query, recursion desired
        b"\x00\x01"   # QDCOUNT = 1
        b"\x00\x00"   # ANCOUNT = 0
        b"\x00\x00"   # NSCOUNT = 0
        b"\x00\x00"   # ARCOUNT = 0
        b"\x01a"      # QNAME: "a" (1 char)
        b"\x03com"    # QNAME: "com" (3 chars)
        b"\x00"       # QNAME: root (null terminator)
        b"\x00\x01"   # QTYPE = A (1)
        b"\x00\x01"   # QCLASS = IN (1)
    )
    try:
        s = socket.socket(family, socket.SOCK_DGRAM)
        s.settimeout(3)
        try:
            s.sendto(query, (host, 53))
            data, _ = s.recvfrom(512)
            # A valid DNS response has at least 12 bytes (header) and
            # the response flag (QR bit) set
            return len(data) >= 12 and (data[2] & 0x80) != 0
        finally:
            s.close()
    except OSError:
        return False


def test_remote_ipv6_reachable(remote_ipv6, remote_port):
    """Quick probe: can the kernel route to remote_ipv6?

    Uses a connected UDP socket (no packets actually sent) to verify
    that a source address can be selected for the target. Catches
    'no route to host' before the forwarder starts.
    """
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.settimeout(3)
        try:
            s.connect((remote_ipv6, remote_port))
            src = s.getsockname()[0]
        finally:
            s.close()
        return True, src
    except OSError as e:
        return False, str(e)


def check_ports_available(port_mappings, listen_ip):
    """Pre-check port availability before starting the forwarder.

    Returns list of (local_port, error_message) for ports that CANNOT
    be bound. Empty list means all ports are available.
    """
    conflicts = []
    for local_port, _remote_ipv6, _remote_port in port_mappings:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            except OSError:
                pass
            try:
                s.bind((listen_ip, local_port))
            finally:
                s.close()
        except OSError as e:
            conflicts.append((local_port, str(e)))
    return conflicts


def run_network_tests(skip=False, vpn_findings=None):
    """Step 2: test IPv4 + IPv6 connectivity.

    If skip=True, skip the actual test but still log. The caller should
    have already run VPN detection (step 1) and pass findings here so
    we can annotate the result.
    """
    log("=" * 60)
    log("步骤 2/4：检测网络连通性")
    log("=" * 60)

    if skip:
        log("[SKIP] 已跳过网络连通性测试 (skip_network_test=true)")
        log("       转发器将在不验证网络的情况下启动。")
        log("       仅在你确信网络正常但因 VPN/加速器干扰导致测试误报时使用。")
        log("-" * 60)
        return True

    v4_ok = test_ipv4()
    v6_ok = test_ipv6()
    log("-" * 60)
    all_ok = v4_ok and v6_ok
    if all_ok:
        log("[PASS] IPv4 和 IPv6 均可用。")
    elif v4_ok:
        log("[WARN] 仅 IPv4 可用。需要 IPv6 才能连接远端 IPv6 服务。")
    elif v6_ok:
        log("[WARN] 仅 IPv6 可用。需要 IPv4 供本地客户端连接。")
    else:
        log("[FAIL] 无法连接公网，请检查网络。")

    # If failed AND we already detected VPN/accelerator, remind the user
    # that interference is the likely cause.
    if not all_ok and vpn_findings and has_vpn_like_setup(vpn_findings):
        log("[HINT] 已检测到 VPN/代理/加速器（见上方步骤 1），")
        log("       网络测试失败很可能是干扰导致，而非真实网络故障。")
        log("       解决方法：将远端 IPv6 地址加入 VPN/加速器的直连/绕过列表，")
        log("       或在配置中设置 \"skip_network_test\": true 跳过测试。")

    log("-" * 60)
    return all_ok


def run_forwarder(port_mappings):
    log("=" * 60)
    log("启动 UDP IPv4 -> IPv6 转发器")
    log("=" * 60)

    listen_ipv4 = DEFAULT_LISTEN_IPV4
    buffer_size = DEFAULT_BUFFER_SIZE
    session_timeout = DEFAULT_SESSION_TIMEOUT
    cleanup_interval = DEFAULT_CLEANUP_INTERVAL

    v4_to_config = {}
    v6_to_session = {}
    client_to_v6 = {}
    v4_sockets = []

    for local_port, remote_ipv6, remote_port in port_mappings:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((listen_ipv4, local_port))
            sock.setblocking(False)
            v4_to_config[sock] = (local_port, remote_ipv6, remote_port)
            v4_sockets.append(sock)
            log(f"[OK]   IPv4 {listen_ipv4}:{local_port}  ->  [{remote_ipv6}]:{remote_port}")
        except OSError as e:
            log(f"[错误] 无法绑定 IPv4 :{local_port}  ->  {e}")

    if not v4_sockets:
        log("[错误] 没有可用的监听端口，退出。")
        return 1

    log(f"转发器已启动，共 {len(v4_sockets)} 个端口。按 Ctrl+C 停止。")
    log("-" * 60)

    last_cleanup = time.time()
    try:
        while True:
            all_readable = v4_sockets + list(v6_to_session.keys())
            r, _, _ = select.select(all_readable, [], [], 1)
            now = time.time()

            for sock in r:
                if sock in v4_to_config:
                    listen_port, remote_ipv6, remote_port = v4_to_config[sock]
                    try:
                        data, client_addr = sock.recvfrom(buffer_size)
                    except OSError:
                        continue
                    key = (listen_port, client_addr)
                    v6_sock = client_to_v6.get(key)
                    if v6_sock is None:
                        v6_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                        v6_sock.setblocking(False)
                        v6_to_session[v6_sock] = {
                            "client_addr": client_addr,
                            "v4_sock": sock,
                            "listen_port": listen_port,
                            "remote": (remote_ipv6, remote_port),
                            "last_seen": now,
                        }
                        client_to_v6[key] = v6_sock
                        log(f"[新连接] {client_addr[0]}:{client_addr[1]}  ->  端口 {listen_port}  ->  [{remote_ipv6}]:{remote_port}")
                    else:
                        v6_to_session[v6_sock]["last_seen"] = now
                    try:
                        v6_sock.sendto(data, (remote_ipv6, remote_port))
                    except OSError as e:
                        log(f"[错误] 转发到 [{remote_ipv6}]:{remote_port} 失败: {e}")
                else:
                    session = v6_to_session.get(sock)
                    if session is None:
                        continue
                    try:
                        data, _ = sock.recvfrom(buffer_size)
                    except OSError:
                        continue
                    session["last_seen"] = now
                    try:
                        session["v4_sock"].sendto(data, session["client_addr"])
                    except OSError as e:
                        log(f"[错误] 回复 {session['client_addr']} 失败: {e}")

            if now - last_cleanup > cleanup_interval:
                last_cleanup = now
                expired = [s for s, sess in v6_to_session.items()
                           if now - sess["last_seen"] > session_timeout]
                for s in expired:
                    sess = v6_to_session.pop(s)
                    key = (sess["listen_port"], sess["client_addr"])
                    if client_to_v6.get(key) is s:
                        del client_to_v6[key]
                    s.close()
                    log(f"[超时] {sess['client_addr'][0]}:{sess['client_addr'][1]}  端口 {sess['listen_port']} 的连接已关闭")
    except KeyboardInterrupt:
        log("-" * 60)
        log("正在停止...")
        for sock in v4_sockets:
            sock.close()
        for sock in list(v6_to_session.keys()):
            sock.close()
        log("已停止。")
    return 0


def main():
    # ============================================================
    # 配置加载
    # ============================================================
    log("=" * 60)
    log("客户端：加载配置")
    log("=" * 60)
    cfg = load_or_create_config(CLIENT_CONFIG_PATH, DEFAULT_CLIENT_CONFIG)
    port_mappings = normalize_port_mappings(cfg.get("port_mappings", []))
    skip_network_test = bool(cfg.get("skip_network_test", False))

    if not port_mappings:
        log("[错误] 没有有效的端口映射，请检查 client_config.json")
        return 1

    log(f"[配置] 端口映射数: {len(port_mappings)}")
    for local_port, remote_ipv6, remote_port in port_mappings:
        log(f"       {DEFAULT_LISTEN_IPV4}:{local_port}  ->  [{remote_ipv6}]:{remote_port}")
    if skip_network_test:
        log("[配置] skip_network_test = true（将跳过网络连通性测试）")
    log("-" * 60)

    # ============================================================
    # 步骤 1/4：检测 VPN / 代理 / 游戏加速器
    # ============================================================
    log("步骤 1/4：检测 VPN / 代理 / 游戏加速器...")
    vpn_findings = None
    try:
        vpn_findings = detect_vpn_and_accelerators()
        if has_vpn_like_setup(vpn_findings):
            print_vpn_warning(vpn_findings)
        else:
            log("  [OK] 未检测到 VPN / 代理 / 游戏加速器")
    except Exception as e:
        log(f"  [WARN] VPN/加速器检测失败: {e}")
    log("-" * 60)

    # ============================================================
    # 步骤 2/4：检测网络连通性 (IPv4 + IPv6)
    # ============================================================
    if not run_network_tests(skip=skip_network_test, vpn_findings=vpn_findings):
        log("[错误] 网络测试失败，终止启动。")
        log("       (如果你确信网络正常但被 VPN/加速器干扰，可在")
        log("        client_config.json 中设置 \"skip_network_test\": true 跳过测试。)")
        return 1

    # ============================================================
    # 步骤 3/4：检测远端可达性 + 端口占用
    # ============================================================
    log("=" * 60)
    log("步骤 3/4：检测远端可达性和本地端口占用...")
    log("=" * 60)

    # 3a. 远端 IPv6 可达性预检（UDP connect，不发实际包）
    remote_unreachable = []
    for local_port, remote_ipv6, remote_port in port_mappings:
        ok, info = test_remote_ipv6_reachable(remote_ipv6, remote_port)
        if ok:
            log(f"  [OK]   远端可达: [{remote_ipv6}]:{remote_port}  (源地址: {info})")
        else:
            log(f"  [错误] 远端不可达: [{remote_ipv6}]:{remote_port}  ({info})")
            remote_unreachable.append((local_port, remote_ipv6, remote_port))
    if remote_unreachable:
        log("-" * 60)
        log("[错误] 远端 IPv6 不可达，无法转发。")
        log("       可能原因：")
        log("         1. 远端 IPv6 地址配错")
        log("         2. 本机路由表无到达该地址的路径（VPN/防火墙拦截）")
        log("         3. 远端服务端未启动")
        return 1

    # 3b. 本地端口占用检测
    conflicts = check_ports_available(port_mappings, DEFAULT_LISTEN_IPV4)
    if conflicts:
        for local_port, err in conflicts:
            log(f"  [错误] 端口 {local_port} 已被占用: {err}")
        log("-" * 60)
        log("[错误] 端口被占用，无法启动转发。")
        log("       请关闭占用该端口的程序，或修改 client_config.json 中的 local_port。")
        return 1
    log("  [OK]   所有本地端口可用")
    log("-" * 60)

    # ============================================================
    # 步骤 4/4：启动转发
    # ============================================================
    log("=" * 60)
    log("步骤 4/4：启动转发...")
    log("=" * 60)
    return run_forwarder(port_mappings)


if __name__ == "__main__":
    sys.exit(main())
