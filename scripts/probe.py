#!/usr/bin/env python3
"""Live probe of the bosun binary: modern-era discover, tools/list,
the legacy-initialize refusal, and the gate's behaviour end to end.
Fleet probe shape: every request carries params._meta with the
2026-07-28 protocol version."""
import json
import subprocess
import sys
import tempfile

BIN = "/home/phaedrus/.GH/Qompass/bosun/target/debug/bosun"
META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientCapabilities": {},
}

checks = []


def check(name, ok, detail=""):
    checks.append((name, ok, detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}")


def main():
    home = tempfile.mkdtemp(prefix="bosun-probe-")
    proc = subprocess.Popen(
        [BIN],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "BOSUN_HOME": home},
        text=True,
    )
    responses = {}

    def send(obj):
        proc.stdin.write(json.dumps(obj) + "\n")
        proc.stdin.flush()

    def read_until(want_ids, limit=40):
        for _ in range(limit):
            line = proc.stdout.readline()
            if not line:
                break
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "id" in msg:
                responses[msg["id"]] = msg
            if want_ids <= set(responses):
                return

    # 1. server/discover
    send({"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {"_meta": META}})
    # 2. tools/list
    send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {"_meta": META}})
    # 3. legacy initialize -> guard refusal -32022
    send({"jsonrpc": "2.0", "id": 3, "method": "initialize",
          "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "probe", "version": "0"}}})
    read_until({1, 2, 3})

    r1 = responses.get(1, {})
    result = r1.get("result", {})
    check("server/discover answers", bool(result), json.dumps(r1)[:160])
    check("discover era is 2026-07-28",
          result.get("supportedVersions") == ["2026-07-28"],
          str(result.get("supportedVersions")))
    server_info = result.get("_meta", {}).get("io.modelcontextprotocol/serverInfo", {})
    check("discover serverInfo is bosun 0.1.0",
          server_info.get("name") == "bosun" and server_info.get("version") == "0.1.0",
          json.dumps(server_info))

    tools = responses.get(2, {}).get("result", {}).get("tools", [])
    check("tools/list returns 12 tools", len(tools) == 12, f"got {len(tools)}")
    names = {t.get("name") for t in tools}
    check("mdm group present",
          {"bosun_mdm_enrollment_profile", "bosun_mdm_queue", "bosun_mdm_send_push"} <= names,
          str(sorted(n for n in names if "mdm" in n)))
    check("every tool annotated",
          all(t.get("annotations", {}).get("readOnlyHint") is not None for t in tools))
    check("every inputSchema has properties",
          all("properties" in t.get("inputSchema", {}) for t in tools))
    payload = json.dumps(tools)
    check("tools/list payload within 2500-token budget",
          len(payload) // 4 <= 2500, f"~{len(payload) // 4} tokens")

    r3 = responses.get(3, {})
    check("legacy initialize refused with -32022",
          r3.get("error", {}).get("code") == -32022,
          json.dumps(r3)[:160])

    # NOTE: requests are sent and awaited one at a time from here.
    # The server executes calls concurrently, so pipelining
    # dependent calls (list before/after a register) races.
    # 4. device list on the empty inventory
    send({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
          "params": {"name": "bosun_device_list", "arguments": {}, "_meta": META}})
    read_until({4})
    # 5. gate check without approval and without device
    send({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
          "params": {"name": "bosun_gate_check", "arguments": {"action": "package_install"}, "_meta": META}})
    read_until({5})
    # 6. register an android device WITH approval
    send({"jsonrpc": "2.0", "id": 6, "method": "tools/call",
          "params": {"name": "bosun_device_register",
                     "arguments": {"id": "flip7", "label": "Z Flip 7", "platform": "android",
                                   "transport": "100.100.21.122:5555",
                                   "operator_approval": {"approved_by": "probe"}},
                     "_meta": META}})
    read_until({6})

    def tool_body(resp_id):
        msg = responses.get(resp_id, {})
        content = msg.get("result", {}).get("content", [])
        if not content:
            return {}, msg.get("result", {}).get("isError", False)
        return json.loads(content[0]["text"]), msg.get("result", {}).get("isError", False)

    body, is_err = tool_body(4)
    check("device_list on empty inventory: total 0", body.get("total") == 0 and not is_err, json.dumps(body)[:120])
    body, _ = tool_body(5)
    check("gate_check without device denies device_required",
          body.get("decision") == "deny" and body.get("code") == "device_required", json.dumps(body)[:160])
    body, is_err = tool_body(6)
    check("register with approval succeeds", not is_err and body.get("id") == "flip7", json.dumps(body)[:160])

    # 7. install WITHOUT approval on the registered device -> gate denial, no backend
    send({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
          "params": {"name": "bosun_package_install",
                     "arguments": {"device_id": "flip7", "package": "x.apk"}, "_meta": META}})
    read_until({7})
    # 8. list again -> total 1
    send({"jsonrpc": "2.0", "id": 8, "method": "tools/call",
          "params": {"name": "bosun_device_list", "arguments": {}, "_meta": META}})
    read_until({8})
    body, is_err = tool_body(7)
    check("install without approval denied by gate",
          is_err and body.get("error", {}).get("code") == "operator_approval_required",
          json.dumps(body)[:160])
    body, _ = tool_body(8)
    check("device_list after register: total 1", body.get("total") == 1, json.dumps(body)[:120])

    # 9. register an iOS device (unenrolled by default)
    send({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
          "params": {"name": "bosun_device_register",
                     "arguments": {"id": "probe-iphone", "label": "Probe iPhone", "platform": "ios",
                                   "transport": "UDID-PROBE",
                                   "operator_approval": {"approved_by": "probe"}},
                     "_meta": META}})
    read_until({9})
    # 10. enrollment profile WITHOUT approval -> gate denial
    send({"jsonrpc": "2.0", "id": 10, "method": "tools/call",
          "params": {"name": "bosun_mdm_enrollment_profile",
                     "arguments": {"device_id": "probe-iphone", "enrollment": "enrolled_supervised"},
                     "_meta": META}})
    read_until({10})
    # 11. enrollment profile WITH approval -> session + profile
    send({"jsonrpc": "2.0", "id": 11, "method": "tools/call",
          "params": {"name": "bosun_mdm_enrollment_profile",
                     "arguments": {"device_id": "probe-iphone", "enrollment": "enrolled_supervised",
                                   "operator_approval": {"approved_by": "probe"}},
                     "_meta": META}})
    read_until({11})
    # 12. mdm queue readback (the session exists; no commands yet)
    send({"jsonrpc": "2.0", "id": 12, "method": "tools/call",
          "params": {"name": "bosun_mdm_queue", "arguments": {}, "_meta": META}})
    read_until({12})
    # 13. gate_check push_wake on the unenrolled device -> capability denial
    send({"jsonrpc": "2.0", "id": 13, "method": "tools/call",
          "params": {"name": "bosun_gate_check",
                     "arguments": {"action": "push_wake", "device_id": "probe-iphone",
                                   "operator_approval": {"approved_by": "probe"}},
                     "_meta": META}})
    read_until({13})
    body, is_err = tool_body(9)
    check("register ios succeeds as unenrolled",
          not is_err and body.get("enrollment") == "unenrolled", json.dumps(body)[:120])
    body, is_err = tool_body(10)
    check("enrollment profile without approval denied",
          is_err and body.get("error", {}).get("code") == "operator_approval_required",
          json.dumps(body)[:160])
    body, is_err = tool_body(11)
    check("enrollment profile with approval opens a session",
          not is_err and bool(body.get("session_token"))
          and "com.apple.mdm" in body.get("profile", ""),
          json.dumps(body)[:160])
    body, is_err = tool_body(12)
    check("mdm_queue reads back empty commands",
          not is_err and body.get("commands") == [] and body.get("devices") == [],
          json.dumps(body)[:120])
    body, _ = tool_body(13)
    check("gate_check push_wake on unenrolled denies capability",
          body.get("decision") == "deny" and body.get("code") == "capability_not_declared",
          json.dumps(body)[:160])

    proc.stdin.close()
    try:
        proc.wait(timeout=10)
        check("server exits cleanly on stdin EOF", proc.returncode == 0, f"rc={proc.returncode}")
    except subprocess.TimeoutExpired:
        check("server exits cleanly on stdin EOF", False, "still running 10s after EOF")
        proc.kill()
    failed = [c for c in checks if not c[1]]
    print(f"\n{len(checks) - len(failed)}/{len(checks)} probe checks passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
