"""Report rendering — plain text, no verdict.

The report is facts only: who was contacted, how much went each way, how the
host was named, what files were touched, what the MCP server said about itself.
"""

from __future__ import annotations

import datetime


def human(n):
    n = float(n or 0)
    for unit in ("B", "kB", "MB", "GB"):
        if n < 1000 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1000
    return f"{n:.1f} GB"


def _host_rows(hosts):
    rows = [("host", "out", "in", "named by")]
    for h in hosts:
        how = h.get("named_by") or (
            "DNS resolver" if h.get("role") == "resolver" else "IP only"
        )
        rows.append((h["host"][:44], human(h["out"]), human(h["in"]), how))
    widths = [max(len(r[i]) for r in rows) for i in range(4)]
    return "\n".join(
        "  " + "  ".join(c.ljust(widths[i]) for i, c in enumerate(r)).rstrip()
        for r in rows
    )


def report(facts):
    t = facts.get("target", {})
    m = facts.get("machine", {})
    timings = facts.get("timings", {})
    run = facts.get("run", {}) or {}
    install = facts.get("install", {}) or {}
    lines = []

    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines.append(f"MCP quarantine audit — {stamp}")
    lines.append(f"target   {t.get('kind')}  {t.get('spec')}")
    if t.get("install"):
        lines.append(f"install  {t['install']}")
    if t.get("call"):
        lines.append(f"call     {t['call']}")
    src = m.get("snapshot") or m.get("template") or "?"
    lines.append(f"machine  {m.get('id') or m.get('name')} (from {src})")
    cleanup = facts.get("cleanup") or {}
    lines.append(
        f"cleanup  {'deleted' if cleanup.get('deleted') else cleanup.get('error', 'kept')}"
    )

    for phase, data in (("install", install), ("run", run)):
        hosts = data.get("hosts") or []
        meta = data.get("meta") or {}
        if not hosts and not meta and not data.get("packets"):
            continue
        lines.append("")
        lines.append(
            f"{phase} phase — {meta.get('wall_ms', 0)} ms, "
            f"{data.get('packets', 0)} packets, "
            f"exit {meta.get('exit', '?')}, "
            f"+{meta.get('idle_seconds', 0)} s idle"
        )
        if hosts:
            lines.append(_host_rows(hosts))
        else:
            lines.append("  no packets")
        dns = data.get("dns") or []
        if dns:
            lines.append("  DNS: " + ", ".join(dns[:20]))

    files = run.get("files") or {}
    if files:
        lines.append("")
        lines.append(
            f"files    {files.get('read', 0)} read, {files.get('written', 0)} written"
        )
        outside = files.get("read_outside") or []
        if outside:
            lines.append(
                "  read outside the target's own tree: " + ", ".join(outside[:8])
            )
        written = files.get("written_paths") or []
        if written:
            lines.append("  written: " + ", ".join(written[:8]))

    mcp = facts.get("mcp")
    if mcp:
        lines.append("")
        server = mcp.get("server") or {}
        count = mcp.get("tools_count")
        label = f"{server.get('name', 'server')} {server.get('version', '')}".strip()
        lines.append(
            f"mcp      {label}, tools/list: "
            f"{count if count is not None else 'no reply'}"
        )
        names = mcp.get("tool_names") or []
        if names:
            lines.append(
                "  tools: "
                + ", ".join(names[:20])
                + (" …" if len(names) > 20 else "")
            )
        if mcp.get("call"):
            c = mcp["call"]
            lines.append(
                f"  tools/call: isError={c.get('is_error')}"
                + (f" ({c.get('error')})" if c.get("error") else "")
            )
        for err in mcp.get("errors") or []:
            lines.append(f"  error: {err}")

    lines.append("")
    lines.append(
        "timing   create {create_ms} ms, netns {netns_ms} ms, total {total_ms} ms".format(
            create_ms=timings.get("create_ms", 0),
            netns_ms=timings.get("netns_ms", 0),
            total_ms=timings.get("total_ms", 0),
        )
    )
    lines.append(
        "note     observes only — DNS names, TLS SNI, byte counts, file paths. "
        "No payload inspection, no verdict."
    )
    return "\n".join(lines)
