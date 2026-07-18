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
# quirks (e.g. when the OS routing table sends one target through a
# virtual tunnel but the real NIC is the correct egress for others).
PROBE_IPV6_TARGETS = (
    "2606:4700:4700::1111",   # Cloudflare DNS primary
    "2606:4700:4700::1001",   # Cloudflare DNS secondary
    "2001:4860:4860::8888",   # Google DNS primary
    "2001:4860:4860::8844",   # Google DNS secondary
)

# Heuristic: interface name fragments that indicate a virtual adapter.
# Used only to RANK candidates (never to silently drop a working address).
VIRTUAL_INTERFACE_HINTS = (
    "loopback", "pseudo",
    "teredo", "isatap", "6to4",
    "vethernet", "docker", "veth", "br-",
    "tun", "tap", "wg", "utun", "bridge",
    "wsl", "hyper-v", "virtual",
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


def _enumerate_global_ipv6():
    """List all real global IPv6 addresses on the host.

    Returns a list of (addr, ifname) tuples. `ifname` is None when psutil is
    unavailable. Tries psutil first (gives interface names + filters downed
    interfaces), falls back to getaddrinfo (hostname-bound addresses only).
    """
    results = []

    # Preferred path: psutil gives per-interface addresses + link state
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
                    results.append((a.address.split("%")[0], ifname))
        if results:
            return results
    except ImportError:
        pass

    # Fallback: getaddrinfo (returns addresses bound to the hostname)
    try:
        hostname = socket.gethostname()
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET6)
        for info in infos:
            addr = info[4][0]
            if _is_real_global_ipv6(addr):
                results.append((addr.split("%")[0], None))
    except OSError:
        pass
    return results


def detect_local_global_ipv6():
    """Auto-detect the best local global IPv6 address for listening.

    Multi-NIC safe strategy (in order):
      1. Probe several public IPv6 targets via UDP connect and collect the
         source addresses the kernel actually uses for outbound traffic.
         Keep only real GUAs (filters Teredo / 6to4). Pick the one that
         appears most often - this is the egress interface external clients
         will most likely reach us through.
      2. If probing yields nothing usable, enumerate all interfaces and
         return the first real GUA on a non-virtual adapter.
      3. Return None if nothing qualifies.

    The detection is logged by the caller via the return value plus the
    companion `list_local_global_ipv6_candidates()` helper.
    """
    # ---- Strategy 1: probe-based source discovery -------------------
    source_counts = {}
    for target in PROBE_IPV6_TARGETS:
        src = _probe_source_ipv6(target)
        if not src:
            continue
        src_clean = src.split("%")[0].lower()
        if _is_real_global_ipv6(src_clean):
            source_counts[src_clean] = source_counts.get(src_clean, 0) + 1
    if source_counts:
        # Most frequently observed real source address wins
        return max(source_counts.items(), key=lambda kv: kv[1])[0]

    # ---- Strategy 2: enumerate interfaces ---------------------------
    candidates = _enumerate_global_ipv6()
    if not candidates:
        return None
    # Prefer addresses on physical (non-virtual) interfaces
    physical = [(a, i) for a, i in candidates if not _is_virtual_interface(i)]
    chosen = physical[0] if physical else candidates[0]
    return chosen[0]


def list_local_global_ipv6_candidates():
    """Return a human-readable list of all real global IPv6 candidates.

    Used for logging so the operator can see what was found and, if needed,
    manually pin one via the `listen_ipv6` config key.
    """
    seen = {}
    # Include probe results
    for target in PROBE_IPV6_TARGETS:
        src = _probe_source_ipv6(target)
        if src and _is_real_global_ipv6(src):
            clean = src.split("%")[0].lower()
            seen.setdefault(clean, "probe")
    # Include interface enumeration
    for addr, ifname in _enumerate_global_ipv6():
        seen.setdefault(addr, ifname or "iface")
    return list(seen.items())


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

    # Manual override: if the operator pinned an IPv6 in config, use it as-is.
    # Accepts both the bare address and a [addr] form; case-insensitive.
    manual_ipv6 = cfg.get("listen_ipv6")
    if isinstance(manual_ipv6, str):
        manual_ipv6 = manual_ipv6.strip()
    if manual_ipv6:
        log(f"[cfg] listen_ipv6 override: {manual_ipv6}")
        log(f"[OK]   Local IPv6: {manual_ipv6}")
        log(f"       External clients should connect to: [{manual_ipv6}]:<port>")
        log("-" * 60)
    else:
        log("Detecting local global IPv6 address...")
        local_v6 = detect_local_global_ipv6()
        if local_v6:
            log(f"[OK]   Local IPv6: {local_v6}")
            log(f"       External clients should connect to: [{local_v6}]:<port>")
            # Show all candidates so the operator can spot a wrong pick and
            # pin the right one via listen_ipv6 in config.
            try:
                candidates = list_local_global_ipv6_candidates()
            except Exception:
                candidates = []
            if len(candidates) > 1:
                log(f"       Multiple IPv6 candidates detected ({len(candidates)}):")
                for addr, src in candidates:
                    tag = "" if addr == local_v6 else "  (not selected)"
                    log(f"         - {addr}   [via {src}]{tag}")
                log("       If the selected address is wrong, pin the correct")
                log("       one by adding \"listen_ipv6\": \"<addr>\" to server_config.json.")
        else:
            log("[WARN] No global IPv6 address detected. Will still listen on '::'.")
            log("       You can pin one manually via \"listen_ipv6\" in server_config.json.")
        log("-" * 60)

    if not run_network_tests():
        log("Aborting: network tests failed.")
        return 1
    return run_forwarder(port_mappings)


if __name__ == "__main__":
    sys.exit(main())
