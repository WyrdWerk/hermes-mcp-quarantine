# Building `hermes-audit-base-v1`

The plugin boots from an InstaBox snapshot so each audit does not pay for
`apt-get` and a Hermes install. The Nov 5 spike snapshot:

- **Name:** `hermes-audit-base-v1`
- **ID:** `sn_agq2wmqlugavt3pjz5e2jtscr4`
- **State:** ready, 20 GiB logical
- **Base template:** `agent-browser`, 2 vCPU / 4 GiB
- **Hermes pin:** `c5f347ebe9b840c3dbe5ec99bbe8e36871f24393`
  (`v0.22.7+368.gc5f347e`)
- **Install:** `uv sync --frozen` (plain `uv pip install` fails on a pillow pin)

## Packages on the box

```
iproute2 iptables procps tcpdump strace tshark jq git curl unzip xz-utils python3-venv util-linux
```

`util-linux` provides `setpriv`, which drops the target to the exec user inside the netns. Without it, `run-target.sh` refuses to start.

Node 22.23.3 / npm 10.9.9 were already on `agent-browser`.

## Do not bake

- `auth.json` or any API key
- npm cache under `/data/tmp` (the Nov 5 snapshot accidentally includes this;
  `run-target.sh` overrides `npm_config_cache=/tmp/work/.npm-cache` inside
  `bash -lc` so a repeat install is still visible)

## Recreate

1. Create a machine from `agent-browser`.
2. Wait until `state=running`, `runtime.ready=true`, and `operationId` is null.
3. Install the packages above and Hermes at the pin under
   `/data/home/.hermes/hermes-agent`.
4. Copy this plugin to `~/.hermes/plugins/mcp-quarantine-audit`.
5. Remove credentials. Snapshot. Delete the machine.
6. Confirm GET of the machine returns 404.

Canonical source of the plugin is this directory (or a future public GitHub
repo), not the copy baked into the snapshot.
