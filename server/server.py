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
import subprocess
import urllib.request
from datetime import datetime

# ============================================================
# Network connectivity test targets
# ------------------------------------------------------------
# Raw TCP socket connect to port 443 on well-known anycast IPs.
# Bypasses HTTP/SOCKS application-level proxies. See client.py
# for the full rationale.
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
DEFAULT_TARGET_IPV4 = "127.0.0.1"   # forward to local IPv4 service by default
DEFAULT_BUFFER_SIZE = 65535
DEFAULT_SESSION_TIMEOUT = 60
DEFAULT_CLEANUP_INTERVAL = 10

# ============================================================
# VPN / proxy / game accelerator detection
# ------------------------------------------------------------
# Same patterns as client.py. Kept duplicated (not shared) so the
# server can run standalone without importing the client module.
# ============================================================
VPN_PROCESS_PATTERNS = (
    "clash", "mihomo", "v2ray", "v2rayn", "xray", "sing-box",
    "shadowsocks", "shadowsocksr", "ssr", "trojan", "naive",
    "warp", "wireguard", "wg", "tailscale", "openvpn", "ovpn",
    "hamachi", "zerotier", "zerotier-one",
    "nordvpn", "expressvpn", "mullvad", "surfshark", "protonvpn",
    "cyberghost", "pia-", "privatevpn",
    "surgemac", "quantumult", "shadowrocket", "peclash",
)

ACCELERATOR_PROCESS_PATTERNS = (
    "uu.exe", "uu_", "uuacc",
    "xunyou", "xyacc",
    "leigod", "leidianacc", "leidian",
    "biubiu",
    "tgpacc", "txgameaccelerator", "qqacc",
    "xunleiacc",
    "haitunacc", "haitun",
    "27acc",
    "qianlanacc",
    "uu网游", "uu加速",
    "加速器",
)

# ============================================================
# IPv6 auto-detection tuning
# ------------------------------------------------------------
# Special-use prefixes INSIDE 2000::/3 that should be treated as
# "virtual" and excluded when picking the listening address:
#   - 2001:0::/32  : Teredo tunnel (Windows often enables by default)
#   - 2002::/16    : 6to4 tunnel (auto-derived from public IPv4)
# Also excluded (outside 2000::/3, listed for clarity):
#   - fe80::/10    : link-local
#   - fc00::/7     : ULA (Unique Local Address)
# ============================================================
EXCLUDED_IPV6_PREFIXES = (
    "2001:0:",     "2001:0000:",   # Teredo  2001:0::/32
    "2002:",                        # 6to4    2002::/16
)

# Multiple public IPv6 targets for source-address probing.
# Probing several targets makes the result robust against single-route
# quirks. NOTE: probe results are *cross-checked* against interface names
# before being trusted - a probe source that lives on a virtual interface
# (e.g. CloudflareWARP hijacking 2606:4700::/32 traffic) is rejected and
# we fall back to interface enumeration. So it is safe to include
# Cloudflare DNS here even when WARP might be running.
PROBE_IPV6_TARGETS = (
    "2606:4700:4700::1111",   # Cloudflare DNS primary
    "2606:4700:4700::1001",   # Cloudflare DNS secondary
    "2001:4860:4860::8888",   # Google DNS primary
    "2001:4860:4860::8844",   # Google DNS secondary
)

# Heuristic: interface name fragments that indicate a virtual / tunnel /
# loopback adapter. Used to RANK candidates - addresses on such interfaces
# are only picked when no physical NIC address is available.
VIRTUAL_INTERFACE_HINTS = (
    # Loopback / pseudo
    "loopback", "pseudo", "lo",
    # Windows transition / virtual
    "teredo", "isatap", "6to4", "vethernet", "hyper-v", "wsl",
    # Container / bridge
    "docker", "veth", "br-", "bridge", "cni", "flannel",
    # Tunnel / VPN devices (generic + named services)
    "tun", "tap", "wg", "utun", "ppp", "ovpn", "ipsec",
    "warp", "cloudflare", "tailscale", "zerotier", "hamachi",
    "nord", "express", "mullvad", "surfshark", "protonvpn",
    # Hurricane Electric tunnel broker
    "he-ipv6", "he-tunnel", "sit",
    # Generic
    "virtual",
)

# ============================================================
# Default server config (used when server_config.json is missing)
# Format: [external_port]  OR  [external_port, local_port]
#         OR  [external_port, local_ipv4, local_port]
#
# Optional keys:
#   "listen_ipv6": "<addr>"   - skip auto-detection and use this IPv6.
#                               Set this if auto-detection picks a virtual
#                               adapter (Teredo / 6to4 / Hyper-V / WSL /
#                               Docker / VPN) on a multi-NIC host.
# ============================================================
DEFAULT_SERVER_CONFIG = {
    "port_mappings": [
        [25565],
        [19132],
    ],
    "listen_ipv6": "",  # leave empty for auto-detection
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


# ============================================================
# VPN / proxy / game accelerator detection (server-side)
# ============================================================
def _list_process_names():
    """Return a list of running process names (best-effort, cross-platform)."""
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

    if sys.platform == "win32":
        try:
            res = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True, timeout=5,
                encoding="utf-8", errors="replace",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            stdout = res.stdout or ""
            names = []
            for line in stdout.splitlines():
                line = line.strip()
                if line.startswith('"'):
                    name = line.split('","', 1)[0].strip('"')
                    if name:
                        names.append(name)
            return names
        except (OSError, subprocess.SubprocessError):
            return []
    else:
        try:
            res = subprocess.run(
                ["ps", "-e", "-o", "comm="],
                capture_output=True, timeout=5,
                errors="replace",
            )
            stdout = res.stdout or ""
            return [l.strip() for l in stdout.splitlines() if l.strip()]
        except (OSError, subprocess.SubprocessError):
            return []


def _get_system_proxy():
    """Return first system proxy URL, or None if no proxy is configured."""
    try:
        proxies = urllib.request.getproxies()
    except Exception:
        return None
    if not proxies:
        return None
    for key in ("http", "https", "ftp", "all"):
        if key in proxies:
            return proxies[key]
    return next(iter(proxies.values()))


def detect_vpn_and_accelerators():
    """Detect VPN / proxy / game accelerator presence on this host.

    Returns a dict with system_proxy, vpn_processes, accelerator_processes.
    Best-effort: never raises.
    """
    findings = {
        "system_proxy": None,
        "vpn_processes": [],
        "accelerator_processes": [],
    }

    findings["system_proxy"] = _get_system_proxy()

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

    return findings


def has_vpn_like_setup(findings):
    """True if any VPN / proxy / accelerator indicator was found."""
    return bool(
        findings.get("system_proxy")
        or findings.get("vpn_processes")
        or findings.get("accelerator_processes")
    )


def print_vpn_warning(findings):
    """Print a multi-line Chinese warning for detected VPN/accelerator items."""
    if not has_vpn_like_setup(findings):
        return
    log("=" * 60)
    log("[警告] 检测到 VPN / 代理 / 游戏加速器，可能干扰服务端：")
    if findings.get("system_proxy"):
        log(f"       - 系统代理        : {findings['system_proxy']}")
        log("         (系统代理不影响 UDP 转发，但可能影响 HTTP 测试。)")
    if findings.get("vpn_processes"):
        log(f"       - VPN 客户端进程  : {', '.join(findings['vpn_processes'])}")
        log("         (全隧道 VPN 可能导致自动检测到错误的 IPv6 地址，")
        log("          或使外部客户端无法路由到本机。建议在配置中手动指定 listen_ipv6。)")
    if findings.get("accelerator_processes"):
        log(f"       - 游戏加速器进程  : {', '.join(findings['accelerator_processes'])}")
        log("         (加速器可能劫持特定端口，影响外部客户端连接。)")
    log("       建议：")
    log("         1. 在 server_config.json 中设置 \"listen_ipv6\" 手动指定正确的 IPv6 地址。")
    log("         2. 或关闭 VPN/加速器后重新启动。")
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


def _is_real_global_ipv6(addr):
    """True if `addr` is a real (non-virtual) global unicast IPv6 address.

    Excludes:
      - Link-local (fe80::/10)
      - ULA (fc00::/7)
      - Teredo tunnel (2001:0::/32)
      - 6to4 tunnel (2002::/16)

    Accepts addresses with a zone-id suffix (e.g. "fe80::1%eth0").
    """
    if not addr:
        return False
    raw = addr.split("%")[0].lower().strip()
    if not raw:
        return False
    # Must be a global unicast address (2000::/3)
    if not raw.startswith("2"):
        return False
    # Reject known virtual / transition prefixes inside 2000::/3
    for prefix in EXCLUDED_IPV6_PREFIXES:
        if raw.startswith(prefix):
            return False
    return True


def _canonical_ipv6(addr):
    """Normalize an IPv6 address to canonical lowercase form (no zone-id).

    Uses ipaddress.IPv6Address for canonicalization so that "2408:8256:87B::1"
    and "2408:8256:087b:0000:0000:0000:0000:0001" compare equal.
    Returns None on parse failure.
    """
    if not addr:
        return None
    raw = addr.split("%")[0].strip()
    try:
        import ipaddress
        return str(ipaddress.IPv6Address(raw))
    except (ValueError, ImportError):
        return raw.lower() if raw else None


def _is_virtual_interface(ifname):
    """Heuristic: does `ifname` look like a virtual / loopback adapter?"""
    if not ifname:
        return False
    low = ifname.lower()
    return any(hint in low for hint in VIRTUAL_INTERFACE_HINTS)


def _probe_source_ipv6(target):
    """Return the local source IPv6 address that would be used to reach `target`.

    Uses a connected UDP socket (no packets are actually sent) and reads the
    source address the kernel chose. Returns None on any error.
    """
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.settimeout(2)
        try:
            s.connect((target, 53))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return None


def _parse_proc_net_if_inet6():
    """Parse /proc/net/if_inet6 (Linux only). Returns [(canonical_addr, ifname)].

    File format (one row per address):
      <addr_hex_32> <ifindex_hex> <prefix_hex> <scope_hex> <flags_hex> <ifname>
    scope 00 == global. Address is 32 hex chars, no colons.

    This gives us interface names WITHOUT depending on psutil, which is the
    key to filtering CloudflareWARP / Tailscale / etc. on minimal servers.
    """
    result = []
    try:
        with open("/proc/net/if_inet6", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 6:
                    continue
                addr_hex, _ifindex, _prefix, scope, _flags, ifname = parts[:6]
                if len(addr_hex) != 32 or scope != "00":
                    continue
                # Group hex into 8 x 4 chars, join with ":"
                groups = [addr_hex[i:i + 4] for i in range(0, 32, 4)]
                addr_str = ":".join(groups)
                canon = _canonical_ipv6(addr_str)
                if canon:
                    result.append((canon, ifname))
    except (OSError, IOError):
        pass
    return result


def _enumerate_global_ipv6():
    """List all real global IPv6 addresses on the host.

    Returns a list of (canonical_addr, ifname) tuples. `ifname` is None when
    no source could provide it. Sources are tried in order:
      1. psutil (cross-platform, includes link state)
      2. /proc/net/if_inet6 (Linux only, no extra deps)
      3. getaddrinfo (cross-platform, no interface names)
    """
    results = []

    # Path 1: psutil - gives per-interface addresses + link state
    try:
        import psutil  # type: ignore
        try:
            stats = psutil.net_if_stats()
        except Exception:
            stats = {}
        try:
            addrs_by_if = psutil.net_if_addrs()
        except Exception:
            addrs_by_if = {}
        for ifname, addrs in addrs_by_if.items():
            # Skip interfaces that are down (avoids picking stale addresses)
            st = stats.get(ifname)
            if st is not None and not st.isup:
                continue
            for a in addrs:
                if a.family == socket.AF_INET6 and _is_real_global_ipv6(a.address):
                    canon = _canonical_ipv6(a.address) or a.address.split("%")[0]
                    results.append((canon, ifname))
        if results:
            return results
    except ImportError:
        pass

    # Path 2: /proc/net/if_inet6 (Linux). No external deps required.
    if os.path.exists("/proc/net/if_inet6"):
        for addr, ifname in _parse_proc_net_if_inet6():
            if _is_real_global_ipv6(addr):
                results.append((addr, ifname))
        if results:
            return results

    # Path 3: getaddrinfo fallback (returns hostname-bound addresses only,
    # no interface names - we lose the ability to filter by interface).
    try:
        hostname = socket.gethostname()
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET6)
        for info in infos:
            addr = info[4][0]
            if _is_real_global_ipv6(addr):
                canon = _canonical_ipv6(addr) or addr.split("%")[0]
                results.append((canon, None))
    except OSError:
        pass
    return results


def detect_local_global_ipv6():
    """Auto-detect the best local global IPv6 address for listening.

    Multi-NIC + VPN safe strategy. The critical insight is that probe-based
    detection alone is NOT enough: VPN tunnels (CloudflareWARP, Tailscale,
    full-tunnel OpenVPN, ...) hijack the kernel's source-address selection,
    so probe results often point at the tunnel address rather than the
    physical NIC. We therefore cross-check probe sources against interface
    names and prefer physical adapters.

    Strategy:
      1. Probe several public IPv6 targets, collect source addresses + counts.
      2. Enumerate all interfaces (psutil / /proc/net/if_inet6 / getaddrinfo).
         Build addr -> ifname map.
      3. If any probe source lives on a PHYSICAL interface, pick the most
         frequently probed such address. This is the best case - we have
         both reachability confirmation and a real NIC.
      4. Otherwise, fall back to interface enumeration: pick the first real
         GUA on a physical adapter. If only virtual adapters exist (e.g.
         everything is behind a VPN), use the first virtual one as a
         last resort so we still return *something* usable.
      5. If interface enumeration also yields nothing, return any probe
         result we managed to collect (last resort, no interface info).
      6. Return None if nothing qualifies.
    """
    # ---- Step 1: probe-based source discovery -----------------------
    probe_counts = {}  # canonical_addr -> count
    for target in PROBE_IPV6_TARGETS:
        src = _probe_source_ipv6(target)
        if not src:
            continue
        canon = _canonical_ipv6(src)
        if canon and _is_real_global_ipv6(canon):
            probe_counts[canon] = probe_counts.get(canon, 0) + 1

    # ---- Step 2: interface enumeration -----------------------------
    iface_candidates = _enumerate_global_ipv6()  # [(canonical_addr, ifname)]
    addr_to_ifname = {a: i for a, i in iface_candidates}

    # ---- Step 3: probe results on physical interfaces --------------
    if probe_counts and addr_to_ifname:
        physical_probe = []   # [(addr, count)]
        for addr, count in probe_counts.items():
            ifname = addr_to_ifname.get(addr)
            # Only trust probe sources we can attribute to a physical NIC.
            # If the address is on a known virtual interface (CloudflareWARP,
            # docker0, veth*, tun*, ...) we skip it and let Step 4 handle it.
            if ifname and not _is_virtual_interface(ifname):
                physical_probe.append((addr, count))
        if physical_probe:
            # Most frequently observed physical source address wins
            return max(physical_probe, key=lambda x: x[1])[0]

    # ---- Step 4: physical NIC from interface enumeration ------------
    if iface_candidates:
        physical = [(a, i) for a, i in iface_candidates
                    if not _is_virtual_interface(i)]
        if physical:
            # If we also have probe results, prefer physical addresses
            # that were probed (cross-validated reachability).
            if probe_counts:
                physical_probed = [(a, i) for a, i in physical
                                   if a in probe_counts]
                if physical_probed:
                    return physical_probed[0][0]
            # Otherwise just take the first physical GUA
            return physical[0][0]
        # Only virtual adapters available (e.g. fully behind WARP).
        # Use the first one as a last resort - the user can still override
        # via listen_ipv6 in config.
        return iface_candidates[0][0]

    # ---- Step 5: probe results without interface info ---------------
    # (e.g. psutil missing AND not Linux AND getaddrinfo returned nothing)
    if probe_counts:
        return max(probe_counts.items(), key=lambda kv: kv[1])[0]

    # ---- Step 6: nothing usable -------------------------------------
    return None


def list_local_global_ipv6_candidates():
    """Return a list of (canonical_addr, ifname_or_probe) for logging.

    Lets the operator see every candidate with its source, so they can spot
    a wrong auto-pick and pin the right one via `listen_ipv6` in config.
    """
    seen = {}  # canonical_addr -> (ifname_or_"probe", is_virtual)

    # Probe results
    for target in PROBE_IPV6_TARGETS:
        src = _probe_source_ipv6(target)
        if src and _is_real_global_ipv6(src):
            canon = _canonical_ipv6(src)
            if canon:
                seen.setdefault(canon, ("probe", False))

    # Interface enumeration - may upgrade existing entries with ifname
    for addr, ifname in _enumerate_global_ipv6():
        is_virt = _is_virtual_interface(ifname) if ifname else False
        if addr not in seen:
            seen[addr] = (ifname or "iface", is_virt)
        else:
            # Upgrade: replace "probe" label with actual interface name
            seen[addr] = (ifname or "probe", is_virt)

    return [(addr, label, is_virt) for addr, (label, is_virt) in seen.items()]


def test_ipv4():
    """Test IPv4 public connectivity via raw TCP socket connect.

    Uses TCP connect to port 443 on well-known anycast IPs. This bypasses
    HTTP/SOCKS application-level proxies that break the old urllib approach.
    Falls back to DNS-over-UDP query if TCP fails.
    """
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
    for host, _port in IPV4_PROBE_TARGETS:
        if _dns_udp_probe(host, socket.AF_INET):
            log(f"  [OK]   IPv4 -> {host}  (DNS UDP)")
            return True
    log(f"  [FAIL] IPv4 -> all targets failed (TCP + UDP DNS)")
    return False


def test_ipv6():
    """Test IPv6 public connectivity via raw TCP socket connect."""
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
    for host, _port in IPV6_PROBE_TARGETS:
        if _dns_udp_probe(host, socket.AF_INET6):
            log(f"  [OK]   IPv6 -> [{host}]  (DNS UDP)")
            return True
    log(f"  [FAIL] IPv6 -> all targets failed (TCP + UDP DNS)")
    return False


def _dns_udp_probe(host, family):
    """Send a minimal DNS query to `host`:53 and check for any response.

    Returns True if a DNS response packet is received within 3 seconds.
    """
    query = (
        b"\x12\x34"
        b"\x01\x00"
        b"\x00\x01"
        b"\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x01a"
        b"\x03com"
        b"\x00"
        b"\x00\x01"
        b"\x00\x01"
    )
    try:
        s = socket.socket(family, socket.SOCK_DGRAM)
        s.settimeout(3)
        try:
            s.sendto(query, (host, 53))
            data, _ = s.recvfrom(512)
            return len(data) >= 12 and (data[2] & 0x80) != 0
        finally:
            s.close()
    except OSError:
        return False


def check_ports_available(port_mappings, listen_ipv6):
    """Pre-check port availability before starting the forwarder.

    Returns list of (external_port, error_message) for ports that CANNOT
    be bound. Empty list means all ports are available.
    """
    conflicts = []
    for external_port, _target_ipv4, _target_port in port_mappings:
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            try:
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            except OSError:
                pass
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            except OSError:
                pass
            try:
                s.bind((listen_ipv6, external_port))
            finally:
                s.close()
        except OSError as e:
            conflicts.append((external_port, str(e)))
    return conflicts


def run_network_tests(vpn_findings=None):
    """Step 2: test IPv4 + IPv6 connectivity. Chinese output."""
    log("=" * 60)
    log("步骤 2/4：检测网络连通性")
    log("=" * 60)
    v4_ok = test_ipv4()
    v6_ok = test_ipv6()
    log("-" * 60)
    all_ok = v4_ok and v6_ok
    if all_ok:
        log("[PASS] IPv4 和 IPv6 均可用。")
    elif v4_ok:
        log("[WARN] 仅 IPv4 可用。服务端需要 IPv6 供外部客户端连接。")
    elif v6_ok:
        log("[WARN] 仅 IPv6 可用。服务端需要 IPv4 才能转发到本地服务。")
    else:
        log("[FAIL] 无法连接公网，请检查网络。")

    if not all_ok and vpn_findings and has_vpn_like_setup(vpn_findings):
        log("[HINT] 已检测到 VPN/代理/加速器（见上方步骤 1），")
        log("       网络测试失败可能是干扰导致。")
    log("-" * 60)
    return all_ok


def run_forwarder(port_mappings, listen_ipv6="::"):
    log(f"监听地址: [{listen_ipv6}]")

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
            # IPv6-only listener. This forwarder's purpose is to accept IPv6
            # clients and bridge them to an IPv4 local service. Setting
            # V6ONLY=1 (instead of 0) is important for two reasons:
            #   1. It avoids "Address already in use" when external_port ==
            #      local_port and the local IPv4 service is bound to
            #      127.0.0.1:<port> or 0.0.0.0:<port> (dual-stack wildcard
            #      would collide on the IPv4 side).
            #   2. It also avoids the local forwarder receiving its own
            #      forwarded packets (IPv4 loopback) and creating loops.
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            # Allow quick restart / coexist with other sockets in edge cases.
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            except OSError:
                pass
            sock.bind((listen_ipv6, external_port))
            sock.setblocking(False)
            v6_to_config[sock] = (external_port, target_ipv4, target_port)
            v6_sockets.append(sock)
            log(f"[OK]   IPv6 :{external_port}  ->  {target_ipv4}:{target_port}")
        except OSError as e:
            log(f"[错误] 无法绑定 IPv6 :{external_port}  ->  {e}")

    if not v6_sockets:
        log("[错误] 没有可用的监听端口，退出。")
        return 1

    log(f"转发器已启动，共 {len(v6_sockets)} 个端口。按 Ctrl+C 停止。")
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
                        log(f"[新连接] {client_addr[0]}:{client_addr[1]}  ->  端口 {listen_port}")
                    else:
                        v4_to_session[v4_sock]["last_seen"] = now
                    try:
                        v4_sock.sendto(data, (target_ipv4, target_port))
                    except OSError as e:
                        log(f"[错误] 转发到 {target_ipv4}:{target_port} 失败: {e}")
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
                        log(f"[错误] 回复 {session['client_addr']} 失败: {e}")

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
                    log(f"[超时] {sess['client_addr'][0]}:{sess['client_addr'][1]}  端口 {sess['listen_port']} 的连接已关闭")
    except KeyboardInterrupt:
        log("-" * 60)
        log("正在停止...")
        for sock in v6_sockets:
            sock.close()
        for sock in list(v4_to_session.keys()):
            sock.close()
        log("已停止。")
    return 0


def main():
    # ============================================================
    # 配置加载
    # ============================================================
    log("=" * 60)
    log("服务端：加载配置")
    log("=" * 60)
    cfg = load_or_create_config(SERVER_CONFIG_PATH, DEFAULT_SERVER_CONFIG)
    port_mappings = normalize_port_mappings(cfg.get("port_mappings", []), DEFAULT_TARGET_IPV4)

    if not port_mappings:
        log("[错误] 没有有效的端口映射，请检查 server_config.json")
        return 1

    log(f"[配置] 端口映射数: {len(port_mappings)}")
    for ext, ipv4, port in port_mappings:
        log(f"       {ext}  ->  {ipv4}:{port}")

    # Manual override: listen_ipv6
    manual_ipv6 = cfg.get("listen_ipv6")
    if isinstance(manual_ipv6, str):
        manual_ipv6 = manual_ipv6.strip()
    if manual_ipv6:
        log(f"[配置] listen_ipv6 手动指定: {manual_ipv6}")
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
    if not run_network_tests(vpn_findings=vpn_findings):
        log("[错误] 网络测试失败，终止启动。")
        return 1

    # ============================================================
    # 步骤 3/4：检测 IPv6 地址 + 端口占用
    # ============================================================
    log("=" * 60)
    log("步骤 3/4：检测 IPv6 地址和端口占用...")
    log("=" * 60)

    if manual_ipv6:
        listen_ipv6 = manual_ipv6
        log(f"  [OK]   使用手动指定的 IPv6: {listen_ipv6}")
    else:
        local_v6 = detect_local_global_ipv6()
        if local_v6:
            listen_ipv6 = local_v6
            log(f"  [OK]   自动检测到 IPv6: {listen_ipv6}")
            # Show candidates if multiple or if selected is virtual
            try:
                candidates = list_local_global_ipv6_candidates()
            except Exception:
                candidates = []
            selected_is_virtual = False
            for addr, _src, is_virt in candidates:
                if addr == local_v6 and is_virt:
                    selected_is_virtual = True
                    break
            if selected_is_virtual:
                log("  [WARN] 自动选择的地址位于虚拟/隧道网卡上。")
                log("         这通常意味着没有找到带真实公网 IPv6 的物理网卡")
                log("         (例如主机完全在 VPN 后面)。")
                log("         建议在配置中通过 listen_ipv6 手动指定正确地址。")
            if len(candidates) > 1 or selected_is_virtual:
                log(f"         IPv6 候选地址 ({len(candidates)} 个):")
                for addr, src, is_virt in candidates:
                    virt_tag = " [虚拟]" if is_virt else ""
                    sel_tag = "" if addr == local_v6 else "  (未选中)"
                    log(f"           - {addr}   [来源: {src}{virt_tag}]{sel_tag}")
                log("         如果选中的地址不对，请在 server_config.json")
                log("         中设置 \"listen_ipv6\": \"<addr>\" 手动指定。")
        else:
            listen_ipv6 = "::"
            log("  [WARN] 未检测到全局 IPv6 地址，将监听 '::'。")
            log("         可通过 \"listen_ipv6\" 在配置中手动指定。")

    # Port pre-check
    conflicts = check_ports_available(port_mappings, listen_ipv6)
    if conflicts:
        for ext_port, err in conflicts:
            log(f"  [错误] 端口 {ext_port} 已被占用: {err}")
        log("-" * 60)
        log("[错误] 端口被占用，无法启动转发。")
        log("       请关闭占用该端口的程序，或修改 server_config.json 中的端口。")
        return 1
    log(f"  [OK]   所有端口可用")
    log(f"  [INFO] 外部客户端应连接到: [{listen_ipv6}]:<端口>")
    log("-" * 60)

    # ============================================================
    # 步骤 4/4：启动转发
    # ============================================================
    log("=" * 60)
    log("步骤 4/4：启动转发...")
    log("=" * 60)
    return run_forwarder(port_mappings, listen_ipv6=listen_ipv6)


if __name__ == "__main__":
    sys.exit(main())
