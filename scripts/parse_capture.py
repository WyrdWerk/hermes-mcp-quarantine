#!/usr/bin/env python3
"""parse_capture.py PCAP STRACE OUT [META] — turn a capture into facts.

Runs on the audit machine (needs tshark). Emits one JSON object:

  hosts[]   one row per host: name (DNS/SNI) or IP, bytes out/in, how it was
            named, and the addresses seen behind that name
  dns[]     every qname the target asked for
  files     read/written counts and paths from the strace log
  meta      exit code, wall time, packet count

Attribution order for a packet: TLS SNI for its TCP stream, else the DNS answer
that named its destination IP, else the bare IP. Nothing here inspects payload
contents; only names, addresses and byte counts.
"""

import json
import subprocess
import sys
from collections import defaultdict

NETNS_PREFIX = "10.200.0."
FIELDS = [
    "frame.len", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "dns.qry.name", "dns.flags.response", "dns.a", "dns.aaaa",
    "tls.handshake.extensions_server_name", "tcp.stream", "udp.stream",
    "tcp.dstport", "udp.dstport", "ip.proto",
]


def tshark(path):
    cmd = ["tshark", "-r", path, "-T", "json"]
    for f in FIELDS:
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit(f"tshark failed: {out.stderr[-500:]}")
    return json.loads(out.stdout or "[]")


def first(layer, key):
    v = layer.get(key)
    if isinstance(v, list):
        return v[0] if v else None
    return v


def parse_packets(packets):
    stream_name = {}
    ip_name = {}
    dns_names = []
    rows = []

    for p in packets:
        layers = p.get("_source", {}).get("layers", {})
        try:
            length = int(first(layers, "frame.len") or 0)
        except ValueError:
            length = 0
        src = first(layers, "ip.src") or first(layers, "ipv6.src") or ""
        dst = first(layers, "ip.dst") or first(layers, "ipv6.dst") or ""
        sni = first(layers, "tls.handshake.extensions_server_name")
        tcp = first(layers, "tcp.stream")
        udp = first(layers, "udp.stream")
        proto = "tcp" if tcp is not None else ("udp" if udp is not None else "")
        stream = tcp if tcp is not None else udp
        qname = first(layers, "dns.qry.name")
        is_dns = "dns.qry.name" in layers or "dns.flags.response" in layers
        if sni and stream is not None:
            stream_name[(proto, stream)] = sni
        if qname:
            qname = qname.rstrip(".")
            if qname not in dns_names:
                dns_names.append(qname)
            for key in ("dns.a", "dns.aaaa"):
                for addr in layers.get(key) or []:
                    ip_name.setdefault(addr, qname)
        rows.append((src, dst, length, proto, stream, qname, is_dns))

    hosts = defaultdict(lambda: {
        "out": 0, "in": 0, "ips": set(), "named_by": None, "dns_only": True,
    })
    for src, dst, length, proto, stream, qname, is_dns in rows:
        if not src or not dst:
            continue
        outbound = src.startswith(NETNS_PREFIX)
        peer = dst if outbound else src
        if peer.startswith(NETNS_PREFIX):
            continue
        if peer.startswith(("ff02:", "fe80:", "224.0.0.", "239.255.")):
            continue
        name = stream_name.get((proto, stream)) if stream is not None else None
        named_by = "sni" if name else None
        if not name and peer in ip_name:
            name, named_by = ip_name[peer], "dns"
        key = name or peer
        h = hosts[key]
        h["out" if outbound else "in"] += length
        h["ips"].add(peer)
        if not is_dns:
            h["dns_only"] = False
        if named_by and not h["named_by"]:
            h["named_by"] = named_by

    out_hosts = []
    for key, h in hosts.items():
        out_hosts.append({
            "host": key,
            "out": h["out"],
            "in": h["in"],
            "ips": sorted(h["ips"]),
            "named": h["named_by"] is not None,
            "named_by": h["named_by"],
            "role": "resolver" if (h["dns_only"] and h["named_by"] is None) else "peer",
        })
    out_hosts.sort(key=lambda r: -(r["out"] + r["in"]))
    return out_hosts, dns_names, len(packets)


def parse_pcap(path):
    return parse_packets(tshark(path))


WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "O_TRUNC")


def parse_strace(path):
    reads, writes = set(), set()
    try:
        with open(path, "r", errors="replace") as fh:
            for line in fh:
                if "openat(" not in line and "open(" not in line:
                    continue
                q1 = line.find('"')
                q2 = line.find('"', q1 + 1)
                if q1 < 0 or q2 < 0:
                    continue
                target = line[q1 + 1:q2]
                if not target.startswith("/"):
                    continue
                tail = line[q2:]
                if any(flag in tail for flag in WRITE_FLAGS):
                    writes.add(target)
                else:
                    reads.add(target)
    except FileNotFoundError:
        pass
    noise = (
        "/dev/", "/proc/", "/sys/", "/etc/profile", "/etc/bash.bashrc",
        "/etc/ld.so.cache", "/etc/ssl/", "/data/tmp/node-compile-cache",
        "/lib/", "/lib64/", "/usr/lib/", "/opt/npm/",
    )
    own = ("/tmp/work", "/usr/lib/node_modules", "/tmp/cap")
    return {
        "read": len(reads),
        "written": len(writes),
        "read_outside": sorted(
            p for p in reads
            if not p.startswith(own) and not p.startswith(noise)
        )[:40],
        "written_paths": sorted(writes)[:40],
        "read_sample": sorted(reads)[:40],
    }


def main():
    pcap, strace_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
    meta_path = sys.argv[4] if len(sys.argv) > 4 else None
    hosts, dns, count = parse_pcap(pcap)
    result = {
        "hosts": hosts,
        "dns": dns,
        "packets": count,
        "files": parse_strace(strace_path),
        "meta": {},
    }
    if meta_path:
        try:
            with open(meta_path) as fh:
                result["meta"] = json.load(fh)
        except FileNotFoundError:
            pass
    with open(out_path, "w") as fh:
        json.dump(result, fh, indent=1)
    print(f"packets={count} hosts={len(hosts)} dns={len(dns)}")


if __name__ == "__main__":
    main()
