"""Small, dependency-free observability and control channel shared by the two apps."""
import hashlib
import json
import os
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path


def _now():
    return datetime.now(timezone.utc).isoformat()


class State:
    """Append-only events plus a current status snapshot in project storage."""

    def __init__(self, settings, initialize=True):
        self.directory = Path(settings.state_dir).expanduser()
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.events_path = self.directory / "events.jsonl"
        self.status_path = self.directory / "status.json"
        self.actions_path = self.directory / "actions.jsonl"
        self.lock = threading.Lock()
        if initialize:
            self.started_at = _now()
            self.status = {"status": "starting", "started_at": self.started_at, "maintenance": False}
            self._write_status()

    def _write_status(self):
        temporary = self.status_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(self.status, sort_keys=True) + "\n")
        os.replace(temporary, self.status_path)

    def update(self, **values):
        with self.lock:
            self.status.update(values, updated_at=_now())
            self._write_status()

    def event(self, event, **values):
        record = {"at": _now(), "event": event, **values}
        with self.lock:
            with self.events_path.open("a") as stream:
                stream.write(json.dumps(record, separators=(",", ":"), default=str) + "\n")
            self.status["last_event_at"] = record["at"]
            self._write_status()

    def snapshot(self):
        try:
            return json.loads(self.status_path.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {"status": "unknown"}

    def recent_events(self, limit=100):
        try:
            lines = self.events_path.read_text().splitlines()[-max(1, min(limit, 500)):]
            return [json.loads(line) for line in lines if line.strip()]
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def queue(self, action, requested_by):
        command = {"id": str(uuid.uuid4()), "action": action, "requested_by": requested_by, "at": _now()}
        with self.lock:
            with self.actions_path.open("a") as stream:
                stream.write(json.dumps(command, separators=(",", ":")) + "\n")
        return command


class ControlLoop:
    """Consumes only the narrowly scoped operational commands used by the UI."""

    def __init__(self, state, verifier, impala):
        self.state, self.verifier, self.impala = state, verifier, impala
        self.stop_event = threading.Event()
        self.offset = 0
        self.thread = threading.Thread(target=self._run, name="mcp-control", daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.stop_event.set()

    def _run(self):
        while not self.stop_event.wait(2):
            try:
                with self.state.actions_path.open() as stream:
                    stream.seek(self.offset)
                    while True:
                        line = stream.readline()
                        if not line:
                            break
                        self.offset = stream.tell()
                        if line.strip():
                            self._handle(json.loads(line))
            except FileNotFoundError:
                continue
            except Exception as exc:
                self.state.event("control_error", error=str(exc)[:300])

    def _handle(self, command):
        action = command.get("action")
        try:
            if action == "refresh_jwks":
                if self.verifier is None:
                    raise RuntimeError("JWKS is not enabled")
                kids = self.verifier.warm()
                self.state.update(jwks_kids=kids, jwks_checked_at=_now())
            elif action == "renew_kerberos":
                if self.impala.kerberos is None:
                    raise RuntimeError("Kerberos is not enabled")
                self.impala.kerberos.ensure(force=True)
                self.state.update(kerberos_checked_at=_now(), kerberos_status="ok")
            elif action in ("maintenance_on", "maintenance_off"):
                enabled = action == "maintenance_on"
                self.state.update(maintenance=enabled, status="maintenance" if enabled else "ready")
            else:
                raise ValueError("unsupported management action")
            self.state.event("control_succeeded", action=action, command_id=command.get("id"))
        except Exception as exc:
            self.state.event("control_failed", action=action, command_id=command.get("id"), error=str(exc)[:300])


def query_fingerprint(sql):
    return hashlib.sha256(sql.encode()).hexdigest()[:16]
