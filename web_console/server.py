import asyncio
import queue
import threading
import uuid

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from starlette.websockets import WebSocketState

from web_console.runner import run_agent

app = FastAPI(title="AI-PTA Web Console")

# Active session tracking
active_sessions: dict[str, dict] = {}


@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(HTML_TEMPLATE)


@app.websocket("/ws/{session_id}")
async def websocket_endpoint(websocket: WebSocket, session_id: str):
    await websocket.accept()

    try:
        # Wait for start command
        data = await websocket.receive_json()
        if data.get("action") != "start":
            await websocket.send_json({"type": "error", "message": "expected start action"})
            return

        target = data.get("target", "")
        task = data.get("task", f"对目标 {target} 进行全量端口扫描、漏洞分析和安全审计。")

        # Create event bridge: thread-safe queue -> asyncio queue
        thread_queue: queue.Queue = queue.Queue()
        async_queue: asyncio.Queue = asyncio.Queue()
        loop = asyncio.get_event_loop()

        # Start agent in background thread
        session = {
            "target": target,
            "thread": None,
            "running": True,
        }
        active_sessions[session_id] = session

        def _run():
            """Run in background thread, bridge events to async queue."""
            try:
                run_agent(target, task, thread_queue, session_id=session_id[:8])
            finally:
                loop.call_soon_threadsafe(async_queue.put_nowait, {"type": "_stream_end"})

        def _bridge():
            """Daemon thread: move events from thread_queue -> async_queue."""
            while session.get("running", True):
                try:
                    event = thread_queue.get(timeout=0.5)
                    loop.call_soon_threadsafe(async_queue.put_nowait, event)
                except queue.Empty:
                    continue

        session["thread"] = threading.Thread(target=_run, daemon=True)
        bridge_thread = threading.Thread(target=_bridge, daemon=True)
        session["thread"].start()
        bridge_thread.start()

        # Stream events to WebSocket
        while True:
            event = await async_queue.get()
            if event.get("type") == "_stream_end":
                break
            if websocket.client_state == WebSocketState.DISCONNECTED:
                break
            try:
                await websocket.send_json(event)
            except Exception:
                break

    except WebSocketDisconnect:
        pass
    finally:
        if session_id in active_sessions:
            active_sessions[session_id]["running"] = False
            del active_sessions[session_id]


@app.get("/api/sessions")
async def list_sessions():
    return {"sessions": list(active_sessions.keys())}


# ---------------------------------------------------------------------------
# HTML Dashboard (single-page, dark theme, no build step)
# ---------------------------------------------------------------------------
HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AI-PTA 控制台</title>
<style>
  :root {
    --bg: #0d1117;
    --surface: #161b22;
    --border: #30363d;
    --text: #e6edf3;
    --text-dim: #8b949e;
    --accent: #58a6ff;
    --green: #3fb950;
    --orange: #d29922;
    --red: #f85149;
    --purple: #bc8cff;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', monospace;
    background: var(--bg); color: var(--text); font-size: 14px;
    height: 100vh; display: flex; flex-direction: column;
  }
  /* Header */
  .header {
    background: var(--surface); border-bottom: 1px solid var(--border);
    padding: 12px 20px; display: flex; align-items: center; gap: 16px;
    flex-wrap: wrap;
  }
  .header h1 { font-size: 18px; color: var(--accent); white-space: nowrap; }
  .header .status-dot {
    width: 10px; height: 10px; border-radius: 50%; display: inline-block;
    background: var(--text-dim); flex-shrink: 0;
  }
  .header .status-dot.running { background: var(--green); animation: pulse 1.5s infinite; }
  .header .status-dot.done { background: var(--green); }
  .header .status-dot.error { background: var(--red); }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
  .header .phase-badge {
    background: var(--border); padding: 2px 10px; border-radius: 12px;
    font-size: 12px; color: var(--text-dim); flex-shrink: 0;
  }
  .header .phase-badge.active { background: var(--accent); color: #fff; }
  .input-row {
    display: flex; align-items: center; gap: 8px; flex: 1; min-width: 300px;
  }
  .input-row input {
    flex: 1; background: var(--bg); border: 1px solid var(--border);
    color: var(--text); padding: 6px 12px; border-radius: 6px;
    font-family: monospace; font-size: 13px;
  }
  .btn {
    background: var(--accent); color: #fff; border: none; padding: 6px 18px;
    border-radius: 6px; cursor: pointer; font-size: 13px; font-weight: 600;
  }
  .btn:hover { opacity: 0.85; }
  .btn:disabled { opacity: 0.4; cursor: not-allowed; }
  .btn-danger { background: var(--red); }
  /* Main layout */
  .main { display: flex; flex: 1; overflow: hidden; }
  .log-panel {
    flex: 1; display: flex; flex-direction: column; min-width: 0;
    border-right: 1px solid var(--border);
  }
  .side-panel {
    width: 380px; display: flex; flex-direction: column; flex-shrink: 0;
  }
  .panel-title {
    padding: 8px 16px; font-size: 12px; font-weight: 600; text-transform: uppercase;
    color: var(--text-dim); border-bottom: 1px solid var(--border);
    background: var(--surface); flex-shrink: 0;
  }
  .panel-content { flex: 1; overflow-y: auto; padding: 8px; }
  /* Log entries */
  .log-container { flex: 1; overflow-y: auto; padding: 8px; font-size: 13px; line-height: 1.5; }
  .log-entry { padding: 2px 4px; border-left: 3px solid transparent; margin-bottom: 1px; }
  .log-entry:hover { background: rgba(255,255,255,0.03); }
  .log-entry .time { color: var(--text-dim); margin-right: 8px; font-size: 11px; }
  .log-entry.recon { border-color: var(--accent); }
  .log-entry.analysis { border-color: var(--orange); }
  .log-entry.verification { border-color: var(--purple); }
  .log-entry.reporting { border-color: var(--green); }
  .log-entry.tool_call { border-color: var(--text-dim); }
  .log-entry.tool_result { border-color: var(--green); }
  .log-entry.error { border-color: var(--red); background: rgba(248,81,73,0.08); }
  .log-entry.done { border-color: var(--green); }
  .log-entry .tag {
    display: inline-block; font-size: 10px; padding: 0 6px; border-radius: 3px;
    margin-right: 6px; font-weight: 600;
  }
  .tag.recon { background: rgba(88,166,255,0.2); color: var(--accent); }
  .tag.analysis { background: rgba(210,153,34,0.2); color: var(--orange); }
  .tag.verification { background: rgba(188,140,255,0.2); color: var(--purple); }
  .tag.reporting { background: rgba(63,185,80,0.2); color: var(--green); }
  .tag.tool { background: rgba(139,148,158,0.2); color: var(--text-dim); }
  .tag.error { background: rgba(248,81,73,0.2); color: var(--red); }
  .tag.system { background: rgba(139,148,158,0.2); color: var(--accent); }
  /* Asset cards */
  .asset-card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 6px; padding: 8px 12px; margin-bottom: 6px;
  }
  .asset-card .ip { color: var(--accent); font-weight: 600; }
  .asset-card .meta { color: var(--text-dim); font-size: 12px; }
  .asset-card .ports { margin-top: 4px; display: flex; flex-wrap: wrap; gap: 4px; }
  .asset-card .port-badge {
    background: var(--bg); border: 1px solid var(--border);
    padding: 1px 8px; border-radius: 10px; font-size: 11px;
  }
  /* Vuln cards */
  .vuln-card {
    background: var(--surface); border: 1px solid var(--border);
    border-left: 3px solid var(--orange);
    border-radius: 6px; padding: 8px 12px; margin-bottom: 6px;
  }
  .vuln-card.critical { border-left-color: var(--red); }
  .vuln-card.high { border-left-color: var(--orange); }
  .vuln-card .vuln-title { font-weight: 600; }
  .vuln-card .vuln-meta { color: var(--text-dim); font-size: 12px; }
  /* Scrollbar */
  ::-webkit-scrollbar { width: 6px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
  /* Responsive */
  @media (max-width: 768px) {
    .main { flex-direction: column; }
    .side-panel { width: 100%; height: 40vh; }
    .log-panel { height: 60vh; }
  }
</style>
</head>
<body>

<div class="header">
  <h1>◈ AI-PTA</h1>
  <span class="status-dot" id="statusDot"></span>
  <span class="phase-badge" id="phaseBadge">就绪</span>
  <div class="input-row">
    <input type="text" id="targetInput" placeholder="目标 IP，如 192.168.1.100" value="192.168.43.150">
    <button class="btn" id="startBtn" onclick="startScan()">启动</button>
    <button class="btn btn-danger" id="stopBtn" onclick="stopScan()" disabled>停止</button>
  </div>
</div>

<div class="main">
  <!-- Log panel -->
  <div class="log-panel">
    <div class="panel-title">执行日志</div>
    <div class="log-container" id="logContainer">
      <div class="log-entry system"><span class="tag system">系统</span>控制台已就绪，输入目标并点击"启动"开始审计</div>
    </div>
  </div>

  <!-- Side panel -->
  <div class="side-panel">
    <div class="panel-title">已发现资产</div>
    <div class="panel-content" id="assetPanel">
      <div style="color:var(--text-dim); font-size:12px;">等待扫描...</div>
    </div>
    <div class="panel-title" style="border-top:1px solid var(--border);">漏洞列表</div>
    <div class="panel-content" id="vulnPanel">
      <div style="color:var(--text-dim); font-size:12px;">等待分析...</div>
    </div>
  </div>
</div>

<script>
let ws = null;
let running = false;
let sessionId = null;

function log(tag, text, cls = '') {
  const el = document.getElementById('logContainer');
  const t = new Date().toLocaleTimeString();
  const div = document.createElement('div');
  div.className = 'log-entry ' + cls;
  div.innerHTML = `<span class="time">${t}</span><span class="tag ${tag}">${tag.toUpperCase()}</span>${text}`;
  el.appendChild(div);
  el.scrollTop = el.scrollHeight;
}

async function startScan() {
  const target = document.getElementById('targetInput').value.trim();
  if (!target) { alert('请输入目标 IP'); return; }

  // Clear previous
  document.getElementById('logContainer').innerHTML = '';
  document.getElementById('assetPanel').innerHTML = '';
  document.getElementById('vulnPanel').innerHTML = '';

  sessionId = 'session_' + Date.now();
  running = true;
  document.getElementById('startBtn').disabled = true;
  document.getElementById('stopBtn').disabled = false;
  document.getElementById('statusDot').className = 'status-dot running';
  document.getElementById('phaseBadge').textContent = '启动中...';

  log('system', `目标 ${target} 审计开始`, 'system');

  ws = new WebSocket(`ws://${location.host}/ws/${sessionId}`);

  ws.onopen = () => {
    ws.send(JSON.stringify({ action: 'start', target }));
  };

  ws.onmessage = (e) => {
    const data = JSON.parse(e.data);
    handleEvent(data);
  };

  ws.onclose = () => {
    if (running) {
      log('error', 'WebSocket 连接断开', 'error');
    }
    running = false;
    document.getElementById('startBtn').disabled = false;
    document.getElementById('stopBtn').disabled = true;
  };

  ws.onerror = () => {
    log('error', 'WebSocket 连接错误', 'error');
  };
}

function stopScan() {
  if (ws) {
    ws.close();
    running = false;
  }
  document.getElementById('startBtn').disabled = false;
  document.getElementById('stopBtn').disabled = true;
  document.getElementById('statusDot').className = 'status-dot';
  document.getElementById('phaseBadge').textContent = '已停止';
  log('system', '用户手动停止', 'system');
}

function handleEvent(data) {
  const phase = data.phase || data.node || '';

  switch (data.type) {
    case 'status':
      document.getElementById('phaseBadge').textContent = data.message || '';
      break;

    case 'phase_change':
      document.getElementById('phaseBadge').className = 'phase-badge active';
      document.getElementById('phaseBadge').textContent = data.message || data.phase || '';
      log('system', `🔄 ${data.message || data.phase}`, 'system');
      if (data.web_services) {
        log('system', `  发现 ${data.web_services.length} 个 Web 目标: ${data.web_services.join(', ')}`, 'system');
      }
      break;

    case 'llm_start':
      log(data.node || 'llm', '开始推理...', data.node || '');
      break;

    case 'llm_end':
      if (data.content) {
        const lines = data.content.split('\n').filter(l => l.trim());
        lines.slice(0, 3).forEach(line => {
          log('llm', line.substring(0, 120), data.node || '');
        });
        if (lines.length > 3) {
          log('llm', `  ... 还有 ${lines.length - 3} 行`, data.node || '');
        }
      }
      break;

    case 'tool_call':
      log('tool', `<strong>${data.name}</strong>(${data.args})`, 'tool_call');
      break;

    case 'tool_result':
      log('tool', `← ${data.content.substring(0, 100)}`, 'tool_result');
      break;

    case 'tool_observation':
      if (data.content) {
        log('tools', data.content.substring(0, 120), 'tool_result');
      }
      break;

    case 'node_output':
      if (data.content) {
        const lines = data.content.split('\n').filter(l => l.trim());
        lines.slice(0, 2).forEach(line => {
          log(data.node || 'node', line.substring(0, 150), data.node || '');
        });
      }
      break;

    case 'state_update':
      if (data.discovered_hosts) {
        renderAssets(data.discovered_hosts);
      }
      if (data.vulnerabilities) {
        renderVulns(data.vulnerabilities);
      }
      break;

    case 'error':
      log('error', data.message || '未知错误', 'error');
      break;

    case 'done':
      log('system', '✅ 审计任务完成', 'done');
      document.getElementById('statusDot').className = 'status-dot done';
      document.getElementById('phaseBadge').textContent = '完成';
      document.getElementById('startBtn').disabled = false;
      document.getElementById('stopBtn').disabled = true;
      running = false;
      break;
  }
}

function renderAssets(hosts) {
  const panel = document.getElementById('assetPanel');
  if (!hosts || hosts.length === 0) {
    panel.innerHTML = '<div style="color:var(--text-dim);font-size:12px;">未发现存活主机</div>';
    return;
  }
  panel.innerHTML = hosts.map(h => `
    <div class="asset-card">
      <div class="ip">${h.ip}</div>
      <div class="meta">${h.status || 'unknown'}${h.os ? ' · ' + h.os : ''}</div>
      <div class="ports">${(h.ports || []).map(p => `<span class="port-badge">${p}</span>`).join('')}</div>
    </div>
  `).join('');
}

function renderVulns(vulns) {
  const panel = document.getElementById('vulnPanel');
  if (!vulns || vulns.length === 0) {
    panel.innerHTML = '<div style="color:var(--text-dim);font-size:12px;">未发现漏洞</div>';
    return;
  }
  panel.innerHTML = vulns.map(v => `
    <div class="vuln-card critical">
      <div class="vuln-title">${typeof v === 'string' ? v : v.title || '漏洞'}</div>
      <div class="vuln-meta">${typeof v === 'string' ? '' : (v.target || '')}</div>
    </div>
  `).join('');
}
</script>
</body>
</html>"""


def run_server(host: str = "0.0.0.0", port: int = 8000):
    import uvicorn
    print(f"  → Web 控制台已启动: http://localhost:{port}")
    print(f"  → 按 Ctrl+C 停止服务")
    uvicorn.run(app, host=host, port=port, log_level="warning")
