"""Tool schemas — what the model sees."""

AUDIT_TARGET = {
    "name": "audit_target",
    "description": (
        "Run an MCP stdio server or an npm/pip CLI on a throwaway InstaBox "
        "machine inside an isolated network namespace with outbound NAT, and "
        "report what it did: hosts contacted (DNS name and TLS SNI), bytes out "
        "and in per host, files read and written, and IP-only connections that "
        "could not be named. The machine is deleted afterwards. This observes "
        "behaviour; it does not contain the target, inspect payloads, or give a "
        "verdict."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "kind": {
                "type": "string",
                "enum": ["mcp", "npm", "pip"],
                "description": (
                    "mcp: run an installed MCP stdio server and speak JSON-RPC "
                    "to it. npm/pip: run a CLI from the registry."
                ),
            },
            "target": {
                "type": "string",
                "description": (
                    "For mcp: the server command, e.g. 'npx -y "
                    "@modelcontextprotocol/server-filesystem@2.2.0 /work'. "
                    "For npm: a package spec, e.g. 'cowsay@1'. "
                    "For pip: a package spec, e.g. 'mcp-server-fetch'."
                ),
            },
            "install": {
                "type": "string",
                "description": (
                    "Optional install command, run in its own captured phase "
                    "before the target, e.g. 'npm install "
                    "@modelcontextprotocol/server-filesystem@2.2.0'."
                ),
            },
            "call": {
                "type": "string",
                "description": (
                    "Optional MCP tool to invoke after tools/list, as "
                    "'tool_name {json args}', e.g. 'fetch {\"url\":\"https://example.com\"}'."
                ),
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Wall-clock cap for the target run (default 120, max 600).",
            },
        },
        "required": ["kind", "target"],
    },
}
