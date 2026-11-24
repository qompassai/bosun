#!/usr/bin/env python3
"""Theodolite diagnostics probe for the bosun Stage 0 tree.

Follows the estate's Rust-route discipline (the 2026-11-10 cure):
the .bacon-locations producer runs BEFORE each bridge session,
because the bridge's bacon-ls route reads the locations file as
it stood when the session started.

Phase 1 (control): append a seeded E0308 function to a real crate
file (src/mdm.rs — a scratch file in src/ would not be compiled,
so it could never appear in locations), run the producer until
the error lands in .bacon-locations, and require the bridge to
report >= 1 severity-1 diagnostic for that file. A route that
reports zero for the control is vacuous and cannot gate.
Phase 2 (verdict): restore the file byte-for-byte (sha-checked),
re-run the producer, then require a diagnostics payload per real
file and count errors, in a fresh session whose first query is a
file the control never touched.

Usage: theo_probe.py WORKSPACE [relpath ...]
"""
import hashlib
import json
import os
import select
import subprocess
import sys
import time

BIN = os.path.expanduser("~/.local/bin/theodolite")
CONFIG = os.path.expanduser("~/.local/share/theodolite/bridge.toml")
WORKSPACE = sys.argv[1]
FILES = sys.argv[2:]
CONTROL_FILE = "src/mdm.rs"
SEED = '\npub fn theo_control_seed() -> u32 {\n    let x: u32 = "not a number";\n    x\n}\n'


def run_producer_until(marker, timeout_s=90):
    """Run bacon until .bacon-locations contains `marker`
    (or, for marker=None, until the file is rewritten), then stop it."""
    locations = os.path.join(WORKSPACE, ".bacon-locations")
    start_mtime = os.path.getmtime(locations) if os.path.exists(locations) else 0.0
    proc = subprocess.Popen(
        ["bacon", "--headless", "-j", "bacon-ls"],
        cwd=WORKSPACE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        end = time.time() + timeout_s
        while time.time() < end:
            time.sleep(2)
            try:
                with open(locations) as f:
                    content = f.read()
                mtime = os.path.getmtime(locations)
            except OSError:
                continue
            if marker is not None and marker in content:
                return True
            if marker is None and mtime > start_mtime:
                # Give the exporter a breath to finish the write.
                time.sleep(2)
                return True
        return False
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


class Session:
    def __init__(self):
        self.proc = subprocess.Popen(
            [BIN, "--config", CONFIG],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True,
        )
        self.counter = 0

    def send(self, obj):
        self.proc.stdin.write(json.dumps(obj) + "\n")
        self.proc.stdin.flush()

    def read_for(self, want_id, timeout_s):
        end = time.time() + timeout_s
        while time.time() < end:
            ready, _, _ = select.select(
                [self.proc.stdout], [], [], max(1.0, end - time.time()))
            if not ready:
                break
            line = self.proc.stdout.readline()
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except Exception:
                continue
            if msg.get("id") == want_id:
                return msg
        return None

    def initialize(self):
        self.counter = 1
        self.send({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2026-07-28",
                "capabilities": {},
                "clientInfo": {"name": "bosun-stage0-theodolite", "version": "1.0"},
                "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                          "io.modelcontextprotocol/clientCapabilities": {}},
            },
        })
        init = self.read_for(1, 60)
        if not init or "result" not in init:
            return False
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        return True

    def call(self, name, arguments, timeout_s):
        self.counter += 1
        call_id = self.counter
        self.send({
            "jsonrpc": "2.0", "id": call_id, "method": "tools/call",
            "params": {"name": name, "arguments": arguments,
                       "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                                 "io.modelcontextprotocol/clientCapabilities": {}}},
        })
        return self.read_for(call_id, timeout_s)

    def close(self):
        try:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


def diagnostics_of(resp):
    if not resp or "result" not in resp:
        return None
    for part in resp["result"].get("content") or []:
        text = part.get("text")
        if not text:
            continue
        try:
            payload = json.loads(text)
        except Exception:
            continue
        if isinstance(payload, dict) and "diagnostics" in payload:
            return payload["diagnostics"]
    return None


def run_session(files, label):
    session = Session()
    try:
        if not session.initialize():
            print(f"{label}: initialize failed")
            return None
        base = {"server": "bacon-ls", "workspace": WORKSPACE}
        session.call("session_status", base, 120)
        results = {}
        for rel in files:
            resp = session.call("diagnostics", {**base, "path": rel}, 240)
            diags = diagnostics_of(resp)
            if diags is None:
                print(f"{label}: NO PAYLOAD for {rel}: {json.dumps(resp)[:200]}")
                return None
            errors = [d for d in diags if d.get("severity") == 1]
            warnings = [d for d in diags if d.get("severity") == 2]
            results[rel] = (len(errors), len(warnings))
            print(f"{label}: {rel}: {len(diags)} diagnostics ({len(errors)} errors, {len(warnings)} warnings)")
            for d in errors:
                print(f"  ERROR: {d.get('message')}")
        return results
    finally:
        session.close()


def main():
    control_path = os.path.join(WORKSPACE, CONTROL_FILE)
    with open(control_path, "rb") as f:
        original = f.read()
    original_sha = hashlib.sha256(original).hexdigest()

    # Phase 1 — control.
    with open(control_path, "ab") as f:
        f.write(SEED.encode())
    try:
        if not run_producer_until("mismatched types"):
            print("THEODOLITE: producer did not record the seeded error in .bacon-locations; route unproven")
            return 2
        control = run_session([CONTROL_FILE], "control")
    finally:
        with open(control_path, "wb") as f:
            f.write(original)
    with open(control_path, "rb") as f:
        restored_sha = hashlib.sha256(f.read()).hexdigest()
    assert restored_sha == original_sha, "control file restore mismatch"
    print(f"control: {CONTROL_FILE} restored byte-identical (sha256 {restored_sha[:12]}…)")
    if control is None:
        print("THEODOLITE: control session produced no payload — route unverified")
        return 2
    control_errors = control[CONTROL_FILE][0]
    print(f"control: seeded E0308 produced {control_errors} error diagnostics via the bridge")
    if control_errors < 1:
        print("THEODOLITE: VACUOUS — control not detected; real-file zeros would prove nothing")
        return 2

    # Phase 2 — verdict on the real files, fresh producer + session,
    # first query on a file the control never touched.
    if not run_producer_until(None):
        print("THEODOLITE: producer did not refresh .bacon-locations after restore")
        return 2
    ordered = sorted(FILES, key=lambda p: (p == CONTROL_FILE, p))
    real = run_session(ordered, "real")
    if real is None:
        print("THEODOLITE: no verdict (route produced no payload)")
        return 2
    total_errors = sum(e for e, _ in real.values())
    total_warnings = sum(w for _, w in real.values())
    print(f"THEODOLITE: {len(real)} real files checked, {total_errors} errors, {total_warnings} warnings; control verified live")
    return 1 if total_errors else 0


if __name__ == "__main__":
    sys.exit(main())
