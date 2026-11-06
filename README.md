# MCP quarantine audit (Hermes plugin)

`/audit <mcp|npm|pip> <target>` boots a throwaway InstaBox machine, runs the
target inside an isolated network namespace with outbound NAT, and reports what
it did: hosts (DNS name and TLS SNI), bytes out and in per host, files read and
written, and IP-only connections it could not name. The machine is deleted
afterwards.

It observes; it does not contain, inspect payloads, or give a verdict.

## Disclosure (catalog rule 13)

- Network calls to `api.instabox.sh`.
- Creates and deletes a cloud machine (2 vCPU / 4 GiB, auto-archive ≥ 15 min).
- Runs `apt-get`, `ip`, `iptables`, `tcpdump`, and `strace` as root on that
  machine (via `sudo -n` from the exec user) to set up capture. The **target
  itself** is then dropped to the unprivileged exec user (`setpriv --reuid`,
  no capabilities, `--no-new-privs`) inside the netns.
- The netns has outbound NAT to the public internet. Forwarding to link-local
  metadata (`169.254.0.0/16`), RFC1918, CGNAT, and host `INPUT` on the veth is
  dropped. DNS in the netns is 1.1.1.1 / 8.8.8.8, not the host resolver.
- This is **not containment**. The guest kernel and world-readable files on
  the machine are still visible to the target. Treat the machine as disposable
  and keep credentials off the snapshot.
- Reads and writes only under `/tmp` on that machine (`/tmp/work`, `/tmp/cap`)
  plus `/opt/hermes-audit/bin` for the capture scripts.
- No telemetry. No credentials stored. The InstaBox key is read through
  `agent.secret_scope.get_secret("INSTABOX_API_KEY")` and is never sent to the
  box.

## What it touches

- **InstaBox API** (`api.instabox.sh`) with the key from Hermes. One machine per
  audit, deleted at the end.
- **The audit machine**: `apt-get` when the configured snapshot lacks the
  tools, `ip`/`iptables` for the namespace, `tcpdump` (root, host veth) for
  packets, `strace` as the unprivileged exec user for file and connect
  syscalls.
- **Nothing on your machine** except this plugin's own directory.

## Requirements

- A snapshot with `iproute2`, `iptables`, `procps`, `tcpdump`, `strace` and
  `tshark` (see `docs/build-snapshot.md`). Without one, the plugin bootstraps
  from the `agent-browser` template and adds ~60 s.
- `INSTABOX_API_KEY` in the profile Hermes runs in.

The WYRD1 snapshot used in the Nov 5 spike is `hermes-audit-base-v1`
(`sn_agq2wmqlugavt3pjz5e2jtscr4`). It is account-private.

## Settings

`snapshot_id`, `template_id`, `idle_seconds` (default 8, catches telemetry that
fires after the target exits), `keep_machine` (slash command only; the tool
path always deletes).

## Safety caps

- One machine per audit, never in parallel.
- Target timeout 120 s by default, 600 s at most.
- At most 3 audits per hour.
- Refuses anything that is not `mcp`, `npm`, or `pip`.
- Refuses very heavy npm targets (`wrangler`).

## From-scratch setup (Hermes on your machine)

You need Git, `uv`, and Python 3.11–3.14. Nothing else is assumed.

Pin used for catalog: `303f4cf448cd0ab5f63264c4052485ac102fc13b` (`v0.1.0`).
Hermes pin this was checked against: `c5f347ebe9b840c3dbe5ec99bbe8e36871f24393` (`>=0.22.0`).

Until this plugin is in the official catalog, a Git install of a community
source with a *caution* scan **blocks** unless you pass `--force`. After a
catalog merge, `hermes plugins install mcp-quarantine-audit` should accept
*caution* without `--force`.

```bash
# 1. Hermes (frozen install at the pin we used)
git clone https://github.com/NousResearch/hermes-agent.git
cd hermes-agent
git checkout c5f347ebe9b840c3dbe5ec99bbe8e36871f24393
uv sync --frozen
export PATH="$PWD/.venv/bin:$PATH"
hermes --version

# 2. Optional: clone this plugin only if you want to validate the tree locally
git clone https://github.com/WyrdWerk/hermes-mcp-quarantine.git
cd hermes-mcp-quarantine
git checkout 303f4cf448cd0ab5f63264c4052485ac102fc13b
hermes plugins validate . --install-deps
hermes plugins doctor . --ci

# 3. Install the exact pin from GitHub (no local clone required)
hermes plugins install WyrdWerk/hermes-mcp-quarantine \
  --ref 303f4cf448cd0ab5f63264c4052485ac102fc13b \
  --enable --yes-deps --force

hermes plugins list --plain --no-bundled   # mcp-quarantine-audit enabled, pinned@303f4cf
hermes plugins doctor mcp-quarantine-audit --ci
```

Put `INSTABOX_API_KEY` in the Hermes profile this session uses (catalog rule 11:
`agent.secret_scope.get_secret`, not a `.env` file the plugin reads).

Optional plugin settings: `snapshot_id` (WYRD1: `sn_agq2wmqlugavt3pjz5e2jtscr4`),
`template_id` (`agent-browser` if the snapshot is missing), `idle_seconds` (8).

```text
/auditcheck
/audit mcp npx -y @modelcontextprotocol/server-filesystem@2.2.0 /tmp/work
```

Expect ~50–60 s, a report with hosts/bytes/files, `tools/list` for MCP, and
`cleanup deleted`. `npx -y` without a separate `install=` downloads during the
**run** phase (registry.npmjs.org by SNI), which is not a silent 0-packet
handshake.

Progress: `/auditcheck` posts and edits from a worker. Classic CLI has been
seen to accept the API with **no visible line**. Prefer Telegram or Desktop
for a demo.

## Licence

MIT.
