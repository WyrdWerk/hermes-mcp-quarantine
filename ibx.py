"""InstaBox API client — stdlib only, no third-party dependency.

Endpoints used (api.instabox.sh, /v1):
  POST   /machines                      create (Idempotency-Key)
  GET    /machines/{id}                 state / runtime.ready
  POST   /machines/{id}/exec            bash -lc, <=600 s, <=1 MiB per stream
  DELETE /machines/{id}                 delete (Idempotency-Key)

Create and delete are retried on transient failures because they carry an
Idempotency-Key. Exec is retried only on operation_conflict (rejected before
the command ran).
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
import uuid

API_BASE = "https://api.instabox.sh"
RETRY_STATUS = {429, 500, 502, 503, 504}


class InstaBoxError(RuntimeError):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(f"instabox {status} {code}: {message}")
        self.status = status
        self.code = code
        self.message = message


class Client:
    def __init__(self, api_key: str, base: str = API_BASE, timeout: float = 60.0):
        if not api_key:
            raise InstaBoxError(0, "no_api_key", "INSTABOX_API_KEY is not set")
        self._key = api_key
        self._base = base.rstrip("/")
        self._timeout = timeout

    def _request(self, method, path, body=None, idem=None, timeout=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self._base + path, data=data, method=method)
        req.add_header("X-API-Key", self._key)
        req.add_header("Content-Type", "application/json")
        if idem:
            req.add_header("Idempotency-Key", idem)
        try:
            with urllib.request.urlopen(req, timeout=timeout or self._timeout) as r:
                raw = r.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                err = json.loads(raw).get("error", {})
            except Exception:
                err = {}
            raise InstaBoxError(
                e.code,
                err.get("code", "http_error"),
                err.get("message", str(e)),
            ) from None
        except urllib.error.URLError as e:
            raise InstaBoxError(0, "transport", str(e.reason)) from None

    def _retrying(self, method, path, body=None, idem=None, attempts=4):
        delay = 1.0
        for i in range(attempts):
            try:
                return self._request(method, path, body, idem)
            except InstaBoxError as e:
                if e.status not in RETRY_STATUS or i == attempts - 1:
                    raise
                time.sleep(delay)
                delay = min(delay * 2, 8.0)

    def create_machine(
        self,
        name,
        snapshot_id=None,
        template_id=None,
        vcpus=2,
        mem_mib=4096,
        archive_seconds=900,
    ):
        body = {
            "name": name,
            "vcpus": vcpus,
            "memMiB": mem_mib,
            "archiveSeconds": archive_seconds,
            "desiredState": "running",
            "metadata": {"purpose": "hermes-mcp-quarantine-audit"},
        }
        if snapshot_id:
            body["snapshotId"] = snapshot_id
        else:
            body["templateId"] = template_id or "agent-browser"
        op = self._retrying(
            "POST", "/v1/machines", body, f"audit-create-{uuid.uuid4()}"
        )
        return op.get("machineId") or op.get("id"), op.get("id")

    def get_machine(self, machine_id):
        return self._request("GET", f"/v1/machines/{machine_id}")

    def wait_ready(self, machine_id, deadline_s=180):
        end = time.time() + deadline_s
        while time.time() < end:
            m = self.get_machine(machine_id)
            # runtime.ready flips before the create operation finishes; an exec
            # during that window is rejected with 409 operation_conflict.
            if (
                m.get("state") == "running"
                and (m.get("runtime") or {}).get("ready")
                and not m.get("operationId")
            ):
                return m
            if m.get("state") in ("error", "deleted"):
                raise InstaBoxError(0, "machine_failed", f"state={m.get('state')}")
            time.sleep(1.0)
        raise InstaBoxError(
            0, "ready_timeout", f"{machine_id} not ready in {deadline_s}s"
        )

    def exec(self, machine_id, cmd, timeout=300, envs=None, cwd=None):
        body = {"cmd": cmd, "timeoutSeconds": timeout}
        if envs:
            body["envs"] = envs
        if cwd:
            body["cwd"] = cwd
        delay = 2.0
        for attempt in range(5):
            try:
                return self._request(
                    "POST",
                    f"/v1/machines/{machine_id}/exec",
                    body,
                    timeout=timeout + 30,
                )
            except InstaBoxError as e:
                if e.code != "operation_conflict" or attempt == 4:
                    raise
                time.sleep(delay)
                delay = min(delay * 2, 10.0)

    def delete_machine(self, machine_id, confirm_gone_s=30):
        try:
            self._retrying(
                "DELETE",
                f"/v1/machines/{machine_id}",
                idem=f"audit-delete-{uuid.uuid4()}",
            )
        except InstaBoxError as e:
            if e.status != 404:
                raise
        end = time.time() + confirm_gone_s
        while time.time() < end:
            try:
                self.get_machine(machine_id)
            except InstaBoxError as e:
                if e.status == 404:
                    return True
                raise
            time.sleep(1.0)
        raise InstaBoxError(
            0, "delete_unconfirmed", f"{machine_id} still present after DELETE"
        )
