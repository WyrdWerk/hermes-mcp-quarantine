"""Audit orchestration — host side.

One audit is: create a throwaway InstaBox machine, push the capture scripts,
build the network namespace, run the install phase and the run phase under
tcpdump + strace, parse the capture on the machine, pull the facts back, and
delete the machine. Nothing here interprets the result.
"""

from __future__ import annotations

import base64
import json
import os
import time
import uuid

from . import ibx
from . import render

SCRIPT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts")
GUEST_BIN = "/opt/hermes-audit/bin"
GUEST_CAP = "/tmp/cap"

MCP_HOLD_SECONDS = 12
DEFAULT_TIMEOUT = 120
MAX_TIMEOUT = 600
HEAVY_NPM = ("wrangler",)


def _script(name):
    with open(os.path.join(SCRIPT_DIR, name), "rb") as fh:
        return base64.b64encode(fh.read()).decode()


def _b64write(path, b64):
    return (
        f"sudo -n mkdir -p {os.path.dirname(path)} && "
        f"echo {b64} | base64 -d | sudo -n tee {path} >/dev/null && "
        f"sudo -n chmod 755 {path}"
    )


def _rpc_lines(call=None):
    """The JSON-RPC conversation an MCP stdio server should answer.

    Each line is a complete request. `id` values are distinct so replies can be
    matched without relying on ordering.
    """
    lines = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "hermes-mcp-quarantine", "version": "0.1.0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    ]
    if call:
        name, _, args = call.partition(" ")
        try:
            parsed = json.loads(args) if args.strip() else {}
        except json.JSONDecodeError:
            parsed = {}
        lines.append(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": name.strip(), "arguments": parsed},
            }
        )
    return "\n".join(json.dumps(line) for line in lines) + "\n"


def _install_cmd(kind, install):
    if not install:
        return None
    if kind == "pip":
        return (
            "python3 -m venv /tmp/work/venv && "
            "/tmp/work/venv/bin/pip -q install --disable-pip-version-check "
            f"{install}"
        )
    return install


def _run_cmd(kind, target, hold=MCP_HOLD_SECONDS):
    if kind != "mcp":
        return target
    return f"{{ sleep 1; cat /tmp/work/rpc.jsonl; sleep {hold}; }} | {target}"


def parse_mcp_output(text):
    """Pull serverInfo, the tool list and the tools/call verdict out of stdout."""
    info, tools, call_result, errors = None, None, None, []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("id") == 1 and "result" in msg:
            info = msg["result"].get("serverInfo")
        elif msg.get("id") == 2:
            if "result" in msg:
                tools = msg["result"].get("tools") or []
            elif "error" in msg:
                errors.append(f"tools/list: {msg['error'].get('message')}")
        elif msg.get("id") == 3:
            if "result" in msg:
                call_result = {
                    "is_error": bool(msg["result"].get("isError")),
                    "chars": len(json.dumps(msg["result"].get("content") or [])),
                }
            elif "error" in msg:
                call_result = {
                    "is_error": True,
                    "chars": 0,
                    "error": msg["error"].get("message"),
                }
    return {
        "server": info,
        "tools_count": len(tools) if tools is not None else None,
        "tool_names": [t.get("name") for t in (tools or [])][:60],
        "call": call_result,
        "errors": errors,
    }


def refuse(kind, target, timeout):
    """Return an error string if the request is out of policy, else None."""
    if kind not in ("mcp", "npm", "pip"):
        return f"Unknown kind {kind!r}; use mcp, npm or pip."
    if not (target or "").strip():
        return "target is required"
    if timeout < 1 or timeout > MAX_TIMEOUT:
        return f"timeout_seconds must be between 1 and {MAX_TIMEOUT}"
    lowered = target.lower()
    if kind == "npm" and any(name in lowered for name in HEAVY_NPM):
        return (
            f"Refusing {target!r}: this npm package pulled ~78 MB in the Nov 5 "
            "spike. Pick a smaller target for v0.1."
        )
    return None


def run(
    api_key,
    kind,
    target,
    install=None,
    call=None,
    timeout=DEFAULT_TIMEOUT,
    snapshot_id="",
    template_id="agent-browser",
    idle_seconds=8,
    keep_machine=False,
    progress=None,
    client=None,
):
    """Run one audit and return (report_text, facts_dict)."""
    say = progress or (lambda _text: None)
    timeout = int(timeout or DEFAULT_TIMEOUT)
    reason = refuse(kind, target, timeout)
    if reason:
        raise ValueError(reason)

    client = client or ibx.Client(api_key)
    name = f"audit-{kind}-{int(time.time())}-{uuid.uuid4().hex[:4]}"
    started = time.time()
    facts = {
        "target": {
            "kind": kind,
            "spec": target,
            "install": install,
            "call": call,
        },
        "machine": {"name": name},
        "timings": {},
    }
    machine_id = None
    try:
        say(f"Booting audit machine `{name}`")
        t0 = time.time()
        machine_id, _op = client.create_machine(
            name,
            snapshot_id=snapshot_id or None,
            template_id=template_id,
            archive_seconds=max(900, timeout * 6),
        )
        client.wait_ready(machine_id)
        facts["machine"].update(
            id=machine_id,
            snapshot=snapshot_id or None,
            template=None if snapshot_id else template_id,
        )
        facts["timings"]["create_ms"] = int((time.time() - t0) * 1000)
        say(
            f"Machine `{machine_id}` ready in {facts['timings']['create_ms']} ms"
        )

        say("Placing capture scripts")
        setup = " && ".join(
            [
                _b64write(f"{GUEST_BIN}/netns-up.sh", _script("netns-up.sh")),
                _b64write(f"{GUEST_BIN}/run-target.sh", _script("run-target.sh")),
                _b64write(
                    f"{GUEST_BIN}/parse_capture.py", _script("parse_capture.py")
                ),
                "mkdir -p /tmp/work /tmp/cap",
                'sudo -n chown -R "$(id -u):$(id -g)" /tmp/work /tmp/cap 2>/dev/null || true',
            ]
        )
        r = client.exec(machine_id, setup, timeout=120)
        if r.get("exitCode"):
            raise ibx.InstaBoxError(0, "setup_failed", r.get("stderr", "")[-800:])

        say("Building the isolated network namespace")
        t1 = time.time()
        r = client.exec(machine_id, f"bash {GUEST_BIN}/netns-up.sh", timeout=180)
        if r.get("exitCode"):
            raise ibx.InstaBoxError(
                0,
                "netns_failed",
                (r.get("stdout", "") + r.get("stderr", ""))[-800:],
            )
        facts["timings"]["netns_ms"] = int((time.time() - t1) * 1000)

        if kind == "mcp":
            payload = base64.b64encode(_rpc_lines(call).encode()).decode()
            client.exec(
                machine_id,
                f"echo {payload} | base64 -d > /tmp/work/rpc.jsonl",
                timeout=60,
            )

        phases = []
        install_cmd = _install_cmd(kind, install)
        if install_cmd:
            say("Capturing the install phase")
            r = client.exec(
                machine_id,
                f"bash {GUEST_BIN}/run-target.sh install {idle_seconds} "
                f"{json.dumps(install_cmd)}",
                timeout=min(MAX_TIMEOUT, timeout + 120),
            )
            phases.append(
                {
                    "name": "install",
                    "exit": r.get("exitCode"),
                    "stdout_tail": (r.get("stdout") or "")[-400:],
                }
            )
        say("Capturing the run phase")
        r = client.exec(
            machine_id,
            f"bash {GUEST_BIN}/run-target.sh run {idle_seconds} "
            f"{json.dumps(_run_cmd(kind, target))}",
            timeout=min(MAX_TIMEOUT, timeout + 180),
        )
        phases.append(
            {
                "name": "run",
                "exit": r.get("exitCode"),
                "stdout_tail": (r.get("stdout") or "")[-400:],
            }
        )

        say("Parsing the capture")
        parsed = client.exec(
            machine_id,
            f"python3 {GUEST_BIN}/parse_capture.py {GUEST_CAP}/run.pcap "
            f"{GUEST_CAP}/run.strace {GUEST_CAP}/run.json {GUEST_CAP}/run.meta",
            timeout=300,
        )
        if parsed.get("exitCode"):
            raise ibx.InstaBoxError(
                0,
                "parse_failed",
                (parsed.get("stdout") or "") + (parsed.get("stderr") or ""),
            )
        if install_cmd:
            client.exec(
                machine_id,
                f"python3 {GUEST_BIN}/parse_capture.py {GUEST_CAP}/install.pcap "
                f"{GUEST_CAP}/install.strace {GUEST_CAP}/install.json "
                f"{GUEST_CAP}/install.meta",
                timeout=300,
            )

        got = client.exec(
            machine_id,
            f"cat {GUEST_CAP}/run.json; echo '---8<---'; "
            + (
                f"cat {GUEST_CAP}/install.json; echo '---8<---'; "
                if install_cmd
                else "echo '{}'; echo '---8<---'; "
            )
            + f"tail -c 200000 {GUEST_CAP}/run.out",
            timeout=120,
        )
        parts = (got.get("stdout") or "").split("---8<---")
        if len(parts) < 3 or not parts[0].strip():
            raise ibx.InstaBoxError(
                0,
                "collect_failed",
                "capture artifacts missing: " + (got.get("stderr") or "")[-500:],
            )
        run_facts = json.loads(parts[0])
        install_facts = json.loads(parts[1]) if install_cmd else {}
        stdout_text = parts[2]

        facts["phases"] = phases
        facts["install"] = install_facts
        facts["run"] = run_facts
        facts["mcp"] = parse_mcp_output(stdout_text) if kind == "mcp" else None
        facts["stdout_tail"] = stdout_text[-1500:]
    finally:
        if machine_id and not keep_machine:
            say("Deleting the audit machine")
            try:
                client.delete_machine(machine_id)
                facts["cleanup"] = {"deleted": True}
            except ibx.InstaBoxError as e:
                facts["cleanup"] = {"deleted": False, "error": str(e)}
        elif machine_id:
            facts["cleanup"] = {"deleted": False, "error": "kept"}

    facts["timings"]["total_ms"] = int((time.time() - started) * 1000)
    return render.report(facts), facts
