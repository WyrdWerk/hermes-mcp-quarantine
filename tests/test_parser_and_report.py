"""Fixture tests for parse_capture, MCP JSON-RPC, and the report.

These do not call InstaBox. They check the parts that would hide a wrong
implementation: SNI vs DNS vs IP-only naming, zero-traffic rendering, and
the absence of verdict words.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG = "mcp_quarantine_audit"


def _load_package():
    if PKG in sys.modules and hasattr(sys.modules[PKG], "audit"):
        return sys.modules[PKG]
    pkg = types.ModuleType(PKG)
    pkg.__path__ = [str(ROOT)]
    pkg.__file__ = str(ROOT / "__init__.py")
    sys.modules[PKG] = pkg

    def load(modname, rel):
        spec = importlib.util.spec_from_file_location(
            f"{PKG}.{modname}", ROOT / rel
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules[f"{PKG}.{modname}"] = mod
        spec.loader.exec_module(mod)
        setattr(pkg, modname, mod)
        return mod

    load("ibx", "ibx.py")
    load("render", "render.py")
    load("schemas", "schemas.py")
    load("audit", "audit.py")
    parse_spec = importlib.util.spec_from_file_location(
        "parse_capture", ROOT / "scripts" / "parse_capture.py"
    )
    parse_mod = importlib.util.module_from_spec(parse_spec)
    sys.modules["parse_capture"] = parse_mod
    parse_spec.loader.exec_module(parse_mod)
    pkg.parse_capture = parse_mod
    return pkg


pkg = _load_package()
parse_capture = pkg.parse_capture
audit = pkg.audit
render = pkg.render
ibx = pkg.ibx

VERDICT_WORDS = (
    "safe",
    "malicious",
    "telemetry",
    "benign",
    "suspicious",
    "malware",
    "trusted",
)


def _pkt(
    src,
    dst,
    length,
    *,
    sni=None,
    stream=None,
    proto="tcp",
    qname=None,
    answers=None,
    dns_response=False,
):
    layers = {
        "frame.len": str(length),
        "ip.src": src,
        "ip.dst": dst,
    }
    if proto == "tcp" and stream is not None:
        layers["tcp.stream"] = str(stream)
    if proto == "udp" and stream is not None:
        layers["udp.stream"] = str(stream)
    if sni:
        layers["tls.handshake.extensions_server_name"] = sni
    if qname:
        layers["dns.qry.name"] = qname
        if dns_response:
            layers["dns.flags.response"] = "1"
            if answers:
                layers["dns.a"] = answers
    return {"_source": {"layers": layers}}


class ParserTests(unittest.TestCase):
    def test_sni_dns_and_ip_only(self):
        packets = [
            _pkt(
                "10.200.0.2",
                "1.1.1.1",
                80,
                proto="udp",
                stream=0,
                qname="example.com",
            ),
            _pkt(
                "1.1.1.1",
                "10.200.0.2",
                120,
                proto="udp",
                stream=0,
                qname="example.com",
                answers=["93.184.216.34"],
                dns_response=True,
            ),
            _pkt(
                "10.200.0.2",
                "93.184.216.34",
                1600,
                proto="tcp",
                stream=1,
                sni="example.com",
            ),
            _pkt("93.184.216.34", "10.200.0.2", 4000, proto="tcp", stream=1),
            _pkt("10.200.0.2", "203.0.113.9", 500, proto="tcp", stream=2),
            _pkt("203.0.113.9", "10.200.0.2", 40, proto="tcp", stream=2),
        ]
        hosts, dns, count = parse_capture.parse_packets(packets)
        self.assertEqual(count, 6)
        self.assertIn("example.com", dns)
        by_host = {h["host"]: h for h in hosts}
        self.assertEqual(by_host["example.com"]["named_by"], "sni")
        self.assertEqual(by_host["example.com"]["out"], 1600)
        self.assertEqual(by_host["example.com"]["in"], 4000)
        self.assertEqual(by_host["1.1.1.1"]["role"], "resolver")
        self.assertIsNone(by_host["1.1.1.1"]["named_by"])
        self.assertEqual(by_host["203.0.113.9"]["named_by"], None)
        self.assertEqual(by_host["203.0.113.9"]["role"], "peer")
        self.assertEqual(by_host["203.0.113.9"]["out"], 500)

    def test_dns_name_without_sni(self):
        packets = [
            _pkt(
                "1.1.1.1",
                "10.200.0.2",
                90,
                proto="udp",
                stream=0,
                qname="registry.npmjs.org",
                answers=["104.16.0.1"],
                dns_response=True,
            ),
            _pkt("10.200.0.2", "104.16.0.1", 200, proto="tcp", stream=3),
        ]
        hosts, dns, _ = parse_capture.parse_packets(packets)
        by_host = {h["host"]: h for h in hosts}
        self.assertIn("registry.npmjs.org", dns)
        self.assertEqual(by_host["registry.npmjs.org"]["named_by"], "dns")
        self.assertEqual(by_host["registry.npmjs.org"]["out"], 200)

    def test_zero_packets(self):
        hosts, dns, count = parse_capture.parse_packets([])
        self.assertEqual(hosts, [])
        self.assertEqual(dns, [])
        self.assertEqual(count, 0)


class RpcAndReportTests(unittest.TestCase):
    def test_rpc_lines_are_valid_json_with_ids_1_2_3(self):
        text = audit._rpc_lines('fetch {"url":"https://example.com"}')
        msgs = [json.loads(line) for line in text.strip().splitlines()]
        ids = [m.get("id") for m in msgs if "id" in m]
        self.assertEqual(ids, [1, 2, 3])
        self.assertEqual(msgs[0]["method"], "initialize")
        self.assertEqual(msgs[2]["method"], "tools/list")
        self.assertEqual(msgs[3]["method"], "tools/call")
        self.assertEqual(msgs[3]["params"]["name"], "fetch")

    def test_parse_mcp_output_counts_tools(self):
        stdout = "\n".join(
            [
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "serverInfo": {
                                "name": "secure-filesystem-server",
                                "version": "2.2.0",
                            }
                        },
                    }
                ),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "result": {
                            "tools": [
                                {"name": "read_file"},
                                {"name": "write_file"},
                            ]
                        },
                    }
                ),
            ]
        )
        parsed = audit.parse_mcp_output(stdout)
        self.assertEqual(parsed["tools_count"], 2)
        self.assertEqual(parsed["server"]["name"], "secure-filesystem-server")

    def test_zero_traffic_report_says_no_packets(self):
        facts = {
            "target": {"kind": "mcp", "spec": "npx filesystem"},
            "machine": {"id": "m_test", "snapshot": "sn_test"},
            "cleanup": {"deleted": True},
            "timings": {"create_ms": 1, "netns_ms": 1, "total_ms": 2},
            "run": {
                "hosts": [],
                "packets": 0,
                "meta": {"wall_ms": 13, "exit": 0, "idle_seconds": 8},
            },
            "install": {},
            "mcp": {
                "server": {
                    "name": "secure-filesystem-server",
                    "version": "2.2.0",
                },
                "tools_count": 16,
                "tool_names": ["read_file"],
            },
        }
        text = render.report(facts)
        self.assertIn("no packets", text)
        self.assertIn("cleanup  deleted", text)
        self.assertIn("observes only", text)
        lowered = text.lower()
        for word in VERDICT_WORDS:
            self.assertNotIn(word, lowered)

    def test_networked_report_has_sni_row_and_no_verdict(self):
        facts = {
            "target": {
                "kind": "mcp",
                "spec": "mcp-server-fetch",
                "call": 'fetch {"url":"https://example.com"}',
            },
            "machine": {"id": "m_fetch", "snapshot": "sn_test"},
            "cleanup": {"deleted": True},
            "timings": {"create_ms": 10, "netns_ms": 10, "total_ms": 20},
            "run": {
                "packets": 12,
                "meta": {"wall_ms": 4000, "exit": 0, "idle_seconds": 8},
                "hosts": [
                    {
                        "host": "example.com",
                        "out": 6235,
                        "in": 15699,
                        "named_by": "sni",
                        "role": "peer",
                    }
                ],
                "dns": ["example.com"],
            },
            "install": {},
            "mcp": {
                "server": {"name": "mcp-server-fetch", "version": "2026.11.4"},
                "tools_count": 1,
                "tool_names": ["fetch"],
                "call": {"is_error": False, "chars": 80},
            },
        }
        text = render.report(facts)
        self.assertIn("example.com", text)
        self.assertIn("sni", text)
        self.assertIn("isError=False", text)
        lowered = text.lower()
        for word in VERDICT_WORDS:
            self.assertNotIn(word, lowered)

    def test_refuse_wrangler_and_bad_kind(self):
        self.assertIn("wrangler", audit.refuse("npm", "wrangler@4", 120) or "")
        self.assertIn("Unknown kind", audit.refuse("go", "x", 120) or "")
        self.assertIsNone(audit.refuse("mcp", "npx filesystem", 120))

    def test_run_target_drops_root_before_the_command(self):
        script = (ROOT / "scripts" / "run-target.sh").read_text()
        self.assertIn("setpriv", script)
        self.assertIn("--reuid=", script)
        self.assertIn("--no-new-privs", script)
        self.assertNotRegex(
            script,
            r"sudo -n ip netns exec audit strace",
            "target must not be strace'd as root inside the netns",
        )

    def test_netns_blocks_metadata_and_private_ranges(self):
        script = (ROOT / "scripts" / "netns-up.sh").read_text()
        for cidr in (
            "169.254.0.0/16",
            "172.16.0.0/12",
            "10.0.0.0/8",
            "192.168.0.0/16",
        ):
            self.assertIn(cidr, script)
        self.assertIn("INPUT -i veth-h -j DROP", script)
        self.assertIn("nameserver 1.1.1.1", script)


class FakeClient:
    def __init__(self, fail_at="netns"):
        self.fail_at = fail_at
        self.created = []
        self.deleted = []
        self.execs = []
        self.ready = True

    def create_machine(self, name, snapshot_id=None, template_id=None, **_kw):
        mid = "m_fake_1"
        self.created.append({"name": name, "id": mid, "snapshot": snapshot_id})
        if self.fail_at == "create":
            raise ibx.InstaBoxError(400, "bad_snapshot", "unknown snapshot")
        return mid, "op_fake"

    def wait_ready(self, machine_id, deadline_s=180):
        return {
            "id": machine_id,
            "state": "running",
            "runtime": {"ready": True},
            "operationId": None,
        }

    def exec(self, machine_id, cmd, timeout=300, **_kw):
        self.execs.append(cmd)
        if self.fail_at == "netns" and "netns-up.sh" in cmd:
            raise ibx.InstaBoxError(0, "netns_failed", "no default route")
        return {"exitCode": 0, "stdout": "", "stderr": ""}

    def delete_machine(self, machine_id, confirm_gone_s=30):
        self.deleted.append(machine_id)
        return True


class LifecycleTests(unittest.TestCase):
    def test_failed_audit_still_deletes_the_machine(self):
        client = FakeClient(fail_at="netns")
        with self.assertRaises(ibx.InstaBoxError):
            audit.run(
                api_key="ibk_test",
                kind="mcp",
                target="npx -y @modelcontextprotocol/server-filesystem@2.2.0 /tmp/work",
                client=client,
                snapshot_id="sn_test",
            )
        self.assertEqual(client.created[0]["id"], "m_fake_1")
        self.assertEqual(client.deleted, ["m_fake_1"])

    def test_create_failure_leaves_no_machine(self):
        client = FakeClient(fail_at="create")
        with self.assertRaises(ibx.InstaBoxError):
            audit.run(
                api_key="ibk_test",
                kind="mcp",
                target="npx filesystem",
                client=client,
                snapshot_id="sn_missing",
            )
        self.assertEqual(client.deleted, [])
        self.assertEqual(len(client.created), 1)


if __name__ == "__main__":
    unittest.main()
