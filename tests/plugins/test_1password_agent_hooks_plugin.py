from __future__ import annotations

import importlib.util
import json
import os
import stat
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
BRIDGE_PATH = REPO_ROOT / "plugins" / "1password-agent-hooks" / "bridge.py"


def load_bridge_module():
    spec = importlib.util.spec_from_file_location("onepassword_agent_hooks_bridge_test", BRIDGE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_bundle(tmp_path: Path, body: str) -> Path:
    bundle = tmp_path / "bundle"
    bin_dir = bundle / "bin"
    bin_dir.mkdir(parents=True)
    script = bin_dir / "run-hook.sh"
    script.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return bundle


def test_build_generic_payload_for_terminal_workdir():
    bridge = load_bridge_module()

    payload = bridge.build_generic_payload(
        "terminal",
        {"command": "echo hello", "workdir": "/tmp/project"},
    )

    assert payload["command"] == "echo hello"
    assert payload["cwd"] == "/tmp/project"
    assert payload["workspace_roots"] == ["/tmp/project"]
    assert payload["hermes"]["tool_name"] == "terminal"


def test_generic_adapter_deny_exit_stderr_blocks(tmp_path):
    bridge_mod = load_bridge_module()
    bundle = make_bundle(
        tmp_path,
        "cat >/dev/null\necho '1Password environment file .env is not mounted' >&2\nexit 1\n",
    )
    bridge = bridge_mod.OnePasswordAgentHookBridge(bundle)

    result = bridge.pre_tool_call("terminal", {"command": "npm test"})

    assert result == {
        "action": "block",
        "message": "1Password environment file .env is not mounted",
    }


def test_allow_exit_without_stdout_allows(tmp_path):
    bridge_mod = load_bridge_module()
    bundle = make_bundle(tmp_path, "cat >/dev/null\nexit 0\n")
    bridge = bridge_mod.OnePasswordAgentHookBridge(bundle)

    assert bridge.pre_tool_call("terminal", {"command": "echo ok"}) is None


def test_json_deny_stdout_blocks(tmp_path):
    bridge_mod = load_bridge_module()
    bundle = make_bundle(
        tmp_path,
        "cat >/dev/null\nprintf '%s\\n' '{\"decision\":\"deny\",\"message\":\"no env\"}'\nexit 0\n",
    )
    bridge = bridge_mod.OnePasswordAgentHookBridge(bundle)

    assert bridge.pre_tool_call("terminal", {"command": "echo ok"}) == {
        "action": "block",
        "message": "no env",
    }


def test_non_target_tool_is_ignored(tmp_path):
    bridge_mod = load_bridge_module()
    bundle = make_bundle(tmp_path, "cat >/dev/null\necho denied >&2\nexit 1\n")
    bridge = bridge_mod.OnePasswordAgentHookBridge(bundle, target_tools=["terminal"])

    assert bridge.pre_tool_call("read_file", {"path": "README.md"}) is None


def test_missing_bundle_fails_open(tmp_path):
    bridge_mod = load_bridge_module()
    bridge = bridge_mod.OnePasswordAgentHookBridge(tmp_path / "missing")

    assert bridge.pre_tool_call("terminal", {"command": "echo ok"}) is None


def test_payload_is_sent_to_run_hook(tmp_path, monkeypatch):
    bridge_mod = load_bridge_module()
    capture = tmp_path / "payload.json"
    monkeypatch.setenv("CAPTURE_PAYLOAD", str(capture))
    bundle = make_bundle(
        tmp_path,
        "cat > \"$CAPTURE_PAYLOAD\"\nexit 0\n",
    )
    bridge = bridge_mod.OnePasswordAgentHookBridge(bundle)

    assert bridge.pre_tool_call("terminal", {"command": "echo hello", "workdir": "/tmp/proj"}) is None

    payload = json.loads(capture.read_text(encoding="utf-8"))
    assert payload["command"] == "echo hello"
    assert payload["cwd"] == "/tmp/proj"
    assert payload["workspace_roots"] == ["/tmp/proj"]
