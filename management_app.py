"""Cloudera AI Workbench management application for the standalone MCP server."""
import os
import sys
from collections import Counter
from pathlib import Path

import uvicorn
from starlette.applications import Starlette
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route


def project_root():
    current = Path(__file__).resolve().parent if "__file__" in globals() else Path.cwd()
    candidates = []
    if os.getenv("GOVERNED_MCP_ROOT"):
        candidates.append(Path(os.environ["GOVERNED_MCP_ROOT"]))
    candidates.extend([current, *current.parents])
    for candidate in candidates:
        if (candidate / "governed_iceberg_mcp" / "__init__.py").is_file():
            return candidate
    raise RuntimeError(
        "Cannot find governed_iceberg_mcp from "
        f"{current}; set GOVERNED_MCP_ROOT to the project directory"
    )


sys.path.insert(0, str(project_root()))

from governed_iceberg_mcp.observability import State  # noqa: E402
from governed_iceberg_mcp.settings import Settings  # noqa: E402


PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>Governed MCP Operations</title>
<style>
body{font:15px system-ui,sans-serif;background:#f5f7fb;color:#172033;max-width:1200px;margin:32px auto;padding:0 20px}
h1{margin-bottom:4px}.muted{color:#667085}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px;margin:20px 0}
section,.card{background:white;border:1px solid #dfe5ee;border-radius:10px;padding:16px;box-shadow:0 1px 2px #0000000d}
.value{font-size:26px;font-weight:700;margin-top:6px}.ok{color:#067647}.bad{color:#b42318}.warn{color:#b54708}
button{border:0;border-radius:6px;padding:9px 12px;margin:4px;background:#175cd3;color:white;cursor:pointer}button.secondary{background:#667085}
table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:8px;border-bottom:1px solid #eaecf0;font-size:13px}code{font-size:12px}
</style></head><body>
<h1>Governed MCP Operations</h1><div class="muted">Cloudera Workbench management console · refreshes every 5 seconds</div>
<div id="cards" class="grid"></div>
<section><h2>Operations</h2><button onclick="action('refresh_jwks')">Refresh JWKS</button><button onclick="action('renew_kerberos')">Renew Kerberos</button><button onclick="action('maintenance_on')">Enter maintenance</button><button class="secondary" onclick="action('maintenance_off')">Exit maintenance</button><span id="message" class="muted"></span></section>
<section><h2>Recent activity</h2><table><thead><tr><th>Time</th><th>Event</th><th>User</th><th>Details</th></tr></thead><tbody id="events"></tbody></table></section>
<script>
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function refresh(){let r=await fetch('/api/status');let d=await r.json();let s=d.status||{};let c=d.counts||{};
document.querySelector('#cards').innerHTML=[['Service',s.status||'unknown',s.status==='ready'?'ok':'warn'],['Started',s.started_at||'—',''],['Queries',c.query_succeeded||0,''],['Query failures',c.query_failed||0,c.query_failed?'bad':''],['Auth rejects',c.auth_rejected||0,c.auth_rejected?'warn':''],['Kerberos',s.kerberos_status||'not checked',s.kerberos_status==='ok'?'ok':'']].map(x=>`<div class="card"><div class="muted">${x[0]}</div><div class="value ${x[2]}">${esc(x[1])}</div></div>`).join('');
document.querySelector('#events').innerHTML=(d.events||[]).reverse().map(e=>`<tr><td>${esc(e.at)}</td><td>${esc(e.event)}</td><td>${esc(e.user||e.requested_by||'')}</td><td><code>${esc(JSON.stringify(e))}</code></td></tr>`).join('');}
async function action(a){let r=await fetch('/api/actions/'+a,{method:'POST'});let d=await r.json();document.querySelector('#message').textContent=d.message||d.error||r.status;setTimeout(refresh,500);}
refresh();setInterval(refresh,5000);
</script></body></html>"""


def _identity(request):
    user = request.headers.get("remote-user", "")
    permission = request.headers.get("remote-user-perm", "").upper()
    if not user and os.getenv("MANAGEMENT_ALLOW_LOCAL", "false").lower() in ("1", "true", "yes"):
        return "local", "RW"
    return user, permission


def _can_manage(request):
    user, permission = _identity(request)
    allowlist = {u.strip() for u in os.getenv("MANAGEMENT_ADMIN_USERS", "").split(",") if u.strip()}
    return bool(user) and (user in allowlist or permission in ("RW", "ADMIN"))


def build_app(settings=None):
    settings = settings or Settings()
    state = State(settings, initialize=False)

    async def home(request):
        user, _ = _identity(request)
        if not user:
            return JSONResponse({"error": "Workbench authentication is required"}, status_code=401)
        return HTMLResponse(PAGE)

    async def status(request):
        user, permission = _identity(request)
        if not user:
            return JSONResponse({"error": "Workbench authentication is required"}, status_code=401)
        events = state.recent_events(500)
        counts = Counter(event.get("event") for event in events)
        return JSONResponse({"viewer": user, "permission": permission, "status": state.snapshot(),
            "counts": counts, "events": events[-100:]})

    async def action(request):
        if not _can_manage(request):
            return JSONResponse({"error": "RW project permission or MANAGEMENT_ADMIN_USERS membership is required"}, status_code=403)
        name = request.path_params["name"]
        if name not in {"refresh_jwks", "renew_kerberos", "maintenance_on", "maintenance_off"}:
            return JSONResponse({"error": "unsupported action"}, status_code=400)
        command = state.queue(name, _identity(request)[0])
        return JSONResponse({"message": f"Queued {name}", "command_id": command["id"]})

    return Starlette(routes=[Route("/", home), Route("/api/status", status), Route("/api/actions/{name}", action, methods=["POST"])])


if __name__ == "__main__":
    settings = Settings()
    uvicorn.run(build_app(settings), host=settings.bind, port=settings.port, log_level="info")
