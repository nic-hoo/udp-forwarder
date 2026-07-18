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
            # Always show the candidate list when there's more than one, or
            # when the selected address is on a virtual interface (so the
            # operator is warned and can override).
            selected_is_virtual = False
            for addr, _src, is_virt in candidates:
                if addr == local_v6 and is_virt:
                    selected_is_virtual = True
                    break
            if selected_is_virtual:
                log("[WARN] Auto-picked address is on a virtual/tunnel adapter.")
                log("       This usually means no physical NIC with a real public")
                log("       IPv6 was found (e.g. the host is fully behind a VPN).")
                log("       Consider pinning the correct address via listen_ipv6.")
            if len(candidates) > 1 or selected_is_virtual:
                log(f"       IPv6 candidates detected ({len(candidates)}):")
                for addr, src, is_virt in candidates:
                    virt_tag = " [virtual]" if is_virt else ""
                    sel_tag = "" if addr == local_v6 else "  (not selected)"
                    log(f"         - {addr}   [via {src}{virt_tag}]{sel_tag}")
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
