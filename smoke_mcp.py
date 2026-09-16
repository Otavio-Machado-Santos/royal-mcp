#!/usr/bin/env python3
"""Smoke test do MCP via stdio. NÃO declara capability de elicitation →
valida que a faixa amarela é NEGADA por padrão (headless-deny)."""
import json
import os
import subprocess
import sys
import threading

proc = subprocess.Popen(
    ["./target/debug/royal-mcp"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    text=True,
    bufsize=1,
)

def send(obj):
    proc.stdin.write(json.dumps(obj) + "\n")
    proc.stdin.flush()

def read_result(want_id):
    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("id") == want_id:
            return msg
    return None

# 1) initialize (sem elicitation capability)
send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
      "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                 "clientInfo": {"name": "smoke", "version": "0"}}})
init = read_result(1)
print("initialize:", "ok" if init and "result" in init else init)

# notificação initialized
send({"jsonrpc": "2.0", "method": "notifications/initialized"})

# 2) tools/list
send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
tl = read_result(2)
tools = sorted(t["name"] for t in tl["result"]["tools"]) if tl else []
print("tools:", tools)

def call(cid, name, args):
    send({"jsonrpc": "2.0", "id": cid, "method": "tools/call",
          "params": {"name": name, "arguments": args}})
    r = read_result(cid)
    if not r or "result" not in r:
        return {"_error": r}
    # structuredContent contém o struct de retorno
    return r["result"].get("structuredContent", r["result"])

host = os.environ.get("ROYAL_MCP_SMOKE_HOST", "example-host")
print("\n-- query_hosts --");        print(call(3, "query_hosts", {}))
print("\n-- exec uptime (verde) --"); print(call(4, "exec", {"host": host, "command": "uptime"}))
print("\n-- exec rm (vermelho) --");  print(call(5, "exec", {"host": host, "command": "rm -rf /tmp/x"}))
print("\n-- exec systemctl restart (amarelo, headless→deny) --")
print(call(6, "exec", {"host": host, "command": "systemctl restart nginx"}))
print("\n-- file_get /etc/hostname --"); print(call(7, "file_get", {"host": host, "path": "/etc/hostname"}))
print("\n-- file_get /etc/shadow (denylist) --"); print(call(8, "file_get", {"host": host, "path": "/etc/shadow"}))
print("\n-- refresh_inventory --");   print(call(9, "refresh_inventory", {}))

proc.stdin.close()
proc.terminate()
