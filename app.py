"""Cloudera AI Workbench Application entrypoint for the Governed Iceberg MCP.

Workbench launches this file in an IPython kernel (so `__file__` may be undefined and the working directory is the
project home), sets CDSW_APP_PORT, and expects the application to listen on it. This launcher finds the package,
runs the server as a supervised child, relays its output into the application log and a file in project storage,
and on failure raises with the last lines so the cause shows in the Workbench UI without a terminal.
"""
import collections
import os
import signal
import socket
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

PACKAGE = Path("governed_iceberg_mcp") / "server.py"


def root():
    current = Path(__file__).resolve().parent if "__file__" in globals() else Path.cwd()
    candidates = [Path(os.environ["GOVERNED_MCP_ROOT"])] if os.getenv("GOVERNED_MCP_ROOT") else []
    candidates += [current, *current.parents]
    candidates += sorted(match.parents[1] for depth in ("*", "*/*", "*/*/*") for match in current.glob(f"{depth}/{PACKAGE}"))
    for candidate in candidates:
        if (candidate / PACKAGE).is_file():
            return candidate
    raise RuntimeError(f"Cannot find {PACKAGE} from {current}; set GOVERNED_MCP_ROOT to the Standalone directory")


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def supervise(command, cwd):
    log_dir = Path(os.getenv("MCP_LOG_DIR", Path.home() / ".governed-mcp" / "logs"))
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / "server.log"
    if log_path.exists():
        log_path.replace(log_dir / "server.previous.log")
    tail = collections.deque(maxlen=40)
    banner = f"=== Governed Iceberg MCP starting at {now()}: host {socket.gethostname()}, launcher pid {os.getpid()}, python {sys.executable} ==="
    print(banner, flush=True)
    environment = {**os.environ, "PYTHONPATH": str(cwd) + os.pathsep + os.environ.get("PYTHONPATH", ""), "PYTHONUNBUFFERED": "1"}
    process = subprocess.Popen(command, cwd=cwd, env=environment, start_new_session=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace", bufsize=1)

    def relay():
        with log_path.open("w") as log:
            log.write(banner + "\n")
            for line in process.stdout:
                tail.append(line.rstrip())
                log.write(line)
                log.flush()
                print(line, end="", flush=True)

    reader = threading.Thread(target=relay, daemon=True)
    reader.start()
    try:
        signal.signal(signal.SIGTERM, lambda *_: os.killpg(process.pid, signal.SIGTERM))
        code = process.wait()
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        reader.join(timeout=5)
    if code:
        raise RuntimeError(f"Governed Iceberg MCP exited with status {code} at {now()} (host {socket.gethostname()}). "
            f"Last output (full log: {log_path}):\n" + "\n".join(tail))


os.environ["CDSW_APP_PORT"]  # Required: never silently bind a default Workbench port.
supervise([sys.executable, "-m", "governed_iceberg_mcp"], root())
