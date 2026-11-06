"""mcp-quarantine-audit — registration.

Surfaces used:
  ctx.register_tool     audit_target
  ctx.register_command  /audit, /auditcheck
  ctx.post_message      live progress, edited in place
  agent.secret_scope.get_secret("INSTABOX_API_KEY")
"""

from __future__ import annotations

import contextvars
import json
import logging
import threading
import time

from . import audit, schemas

logger = logging.getLogger(__name__)

SECRET_NAME = "INSTABOX_API_KEY"
TITLE = "MCP quarantine audit"

_audit_lock = threading.Lock()
_recent_starts = []
_MAX_AUDITS_PER_HOUR = 3


def _secret(name):
    # Catalog rule 11: credentials come through Hermes, never from files.
    from agent.secret_scope import get_secret

    return get_secret(name)


def _settings(ctx):
    try:
        raw = ctx.get_config() or {}
    except Exception:
        raw = {}
    return raw if isinstance(raw, dict) else {}


class Progress:
    """Posts one message and rewrites it. Never raises.

    Hermes binds the message to the session in the calling context, so the
    handle must be created on the caller's thread and only `.edit()` is used
    from the worker.
    """

    def __init__(self, ctx, text):
        self._handle = None
        try:
            self._handle = ctx.post_message(text)
        except Exception:
            logger.debug("post_message unavailable", exc_info=True)
        self._lines = [text]
        self.results = []

    def __call__(self, text):
        self._lines.append(text)
        if self._handle is None:
            return
        try:
            self.results.append(self._handle.edit("\n".join(self._lines[-8:])))
        except Exception as exc:
            self.results.append({"ok": False, "exception": str(exc)})


def _run_in_context(fn):
    """Run fn on a worker thread that carries the caller's contextvars."""
    copied = contextvars.copy_context()
    box = {}

    def target():
        try:
            box["value"] = copied.run(fn)
        except BaseException as exc:
            box["error"] = exc

    thread = threading.Thread(target=target, name="mcp-quarantine-audit", daemon=True)
    thread.start()
    thread.join()
    if "error" in box:
        raise box["error"]
    return box.get("value")


def _rate_limit():
    now = time.time()
    cutoff = now - 3600
    while _recent_starts and _recent_starts[0] < cutoff:
        _recent_starts.pop(0)
    if len(_recent_starts) >= _MAX_AUDITS_PER_HOUR:
        raise RuntimeError(
            f"Policy cap: at most {_MAX_AUDITS_PER_HOUR} audits per hour."
        )
    _recent_starts.append(now)


def _audit(ctx, kind, target, install=None, call=None, timeout=120, keep_machine=False):
    settings = _settings(ctx)
    progress = Progress(ctx, f"{TITLE}: {kind} {target[:60]}")
    api_key = _secret(SECRET_NAME)
    if not api_key:
        progress("No INSTABOX_API_KEY available to Hermes")
        raise RuntimeError(
            "INSTABOX_API_KEY is not available to Hermes; set it in the "
            "profile Hermes runs in"
        )

    allow_keep = bool(keep_machine and settings.get("keep_machine"))

    def work():
        return audit.run(
            api_key=api_key,
            kind=kind,
            target=target,
            install=install,
            call=call,
            timeout=int(timeout or 120),
            snapshot_id=str(settings.get("snapshot_id") or ""),
            template_id=str(settings.get("template_id") or "agent-browser"),
            idle_seconds=int(settings.get("idle_seconds") or 8),
            keep_machine=allow_keep,
            progress=progress,
        )

    if not _audit_lock.acquire(blocking=False):
        progress("Another audit is already running")
        raise RuntimeError("One audit at a time; wait for the current one to finish.")
    try:
        _rate_limit()
        text, facts = _run_in_context(work)
    except Exception as exc:
        progress(f"Audit failed: {exc}")
        raise
    finally:
        _audit_lock.release()
    progress("Audit finished")
    facts["report"] = text
    return text, facts


def _tool_audit_target(ctx, params, **_kwargs):
    kind = str(params.get("kind") or "mcp")
    target = str(params.get("target") or "").strip()
    if not target:
        return json.dumps({"success": False, "error": "target is required"})
    try:
        text, facts = _audit(
            ctx,
            kind,
            target,
            install=params.get("install"),
            call=params.get("call"),
            timeout=params.get("timeout_seconds") or 120,
            keep_machine=False,
        )
    except Exception as exc:
        return json.dumps({"success": False, "error": str(exc)})
    return json.dumps(
        {"success": True, "report": text, "cleanup": facts.get("cleanup")},
        indent=1,
    )


def _parse_command(raw):
    """`/audit <kind> <target>` with optional `install=` and `call=` parts."""
    words = raw.strip().split()
    if not words:
        return None
    kind = words[0]
    rest = raw.strip()[len(kind) :].strip()
    install, call = None, None
    for marker in ("install=", "call="):
        idx = rest.find(marker)
        if idx < 0:
            continue
        value = rest[idx + len(marker) :].strip()
        rest = rest[:idx].strip()
        if marker == "install=":
            install = value.strip().strip('"')
        else:
            call = value.strip().strip('"')
    return kind, rest, install, call


def _handle_audit(ctx, raw):
    parsed = _parse_command(raw)
    if not parsed:
        return (
            "Usage: /audit <mcp|npm|pip> <target> [install=<cmd>] [call=<tool> <json>]\n"
            "Example: /audit mcp 'npx -y @modelcontextprotocol/server-filesystem@2.2.0 /tmp/work'"
        )
    kind, target, install, call = parsed
    if kind not in ("mcp", "npm", "pip"):
        return f"Unknown kind {kind!r}; use mcp, npm or pip."
    text, _facts = _audit(
        ctx, kind, target, install=install, call=call, keep_machine=True
    )
    return text


def _handle_check(ctx, _raw):
    """Smoke test for the progress path on this surface."""
    out = {"posted": None, "edits": [], "worker_post": None, "errors": []}
    progress = Progress(ctx, f"{TITLE}: self-check")
    handle = progress._handle
    out["posted"] = {
        "ok": getattr(handle, "ok", None),
        "message_id": getattr(handle, "message_id", None),
        "error": getattr(handle, "error", None),
    }

    def work():
        for i in range(1, 4):
            progress(f"self-check step {i}/3")
        try:
            worker_handle = ctx.post_message(f"{TITLE}: posted from worker")
            out["worker_post"] = {
                "ok": getattr(worker_handle, "ok", None),
                "error": getattr(worker_handle, "error", None),
            }
        except Exception as exc:
            out["worker_post"] = {"exception": str(exc)}
        return "ok"

    try:
        _run_in_context(work)
    except Exception as exc:
        out["errors"].append(str(exc))
    progress("self-check finished")
    out["edits"] = progress.results
    return json.dumps(out, indent=1)


def register(ctx):
    ctx.register_tool(
        name="audit_target",
        toolset="mcp_audit",
        schema=schemas.AUDIT_TARGET,
        handler=lambda params, **kw: _tool_audit_target(ctx, params, **kw),
    )
    ctx.register_command(
        "audit",
        handler=lambda raw: _handle_audit(ctx, raw),
        description="Audit what an MCP server or npm/pip CLI does on a throwaway machine",
        args_hint="<mcp|npm|pip> <target>",
    )
    ctx.register_command(
        "auditcheck",
        handler=lambda raw: _handle_check(ctx, raw),
        description="Check that live progress messages work on this surface",
    )
