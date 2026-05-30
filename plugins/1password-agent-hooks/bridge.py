"""Bridge Hermes pre_tool_call events to 1Password's agent-hooks bundle."""

from __future__ import annotations

import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from hermes_constants import get_hermes_home

logger = logging.getLogger(__name__)

DEFAULT_HOOK_NAME = "1password-validate-mounted-env-files"
DEFAULT_TARGET_TOOLS = ("terminal", "execute_code")
DEFAULT_TIMEOUT_SECONDS = 30


class OnePasswordAgentHookBridge:
    """Invoke an installed 1Password agent-hooks bundle for Hermes tool calls.

    The upstream bundle's generic adapter exits non-zero and writes the deny
    message to stderr instead of returning JSON on stdout. Hermes plugin hooks
    need an in-process block directive, so this bridge translates both the
    generic adapter shape and any future JSON shape into Hermes' canonical
    {"action": "block", "message": ...} response. All failures fail open.
    """

    def __init__(
        self,
        bundle_path: Path,
        *,
        hook_name: str = DEFAULT_HOOK_NAME,
        target_tools: Iterable[str] = DEFAULT_TARGET_TOOLS,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.bundle_path = Path(bundle_path).expanduser()
        self.hook_name = hook_name or DEFAULT_HOOK_NAME
        self.target_tools = {str(t) for t in target_tools if str(t)}
        self.timeout = max(1, min(int(timeout or DEFAULT_TIMEOUT_SECONDS), 300))

    @property
    def run_hook_path(self) -> Path:
        return self.bundle_path / "bin" / "run-hook.sh"

    def available(self) -> bool:
        return self.run_hook_path.is_file()

    def pre_tool_call(self, tool_name: str = "", args: Any = None, **_: Any) -> Optional[Dict[str, str]]:
        if tool_name not in self.target_tools:
            return None
        if not isinstance(args, dict):
            args = {}
        payload = build_generic_payload(tool_name, args)
        return self.invoke(payload)

    def invoke(self, payload: Dict[str, Any]) -> Optional[Dict[str, str]]:
        if not self.available():
            logger.debug("1password-agent-hooks bundle unavailable at %s", self.bundle_path)
            return None

        try:
            proc = subprocess.run(
                [str(self.run_hook_path), self.hook_name],
                input=json.dumps(payload, ensure_ascii=False),
                capture_output=True,
                text=True,
                timeout=self.timeout,
                shell=False,
            )
        except subprocess.TimeoutExpired:
            logger.warning(
                "1password-agent-hooks timed out after %ss running %s",
                self.timeout,
                self.run_hook_path,
            )
            return None
        except (OSError, ValueError) as exc:
            logger.warning("1password-agent-hooks failed open: %s", exc)
            return None

        stdout = (proc.stdout or "").strip()
        stderr = (proc.stderr or "").strip()

        # Upstream's generic adapter emits deny as exit 1 + stderr message.
        if proc.returncode != 0:
            if stderr:
                return _block(stderr)
            logger.warning(
                "1password-agent-hooks exited %s without a deny message; failing open",
                proc.returncode,
            )
            return None

        if not stdout:
            return None

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            logger.debug("1password-agent-hooks stdout was not JSON: %s", stdout[:300])
            return None
        if not isinstance(data, dict):
            return None

        decision = data.get("decision") or data.get("action")
        if decision in {"deny", "block"}:
            message = data.get("message") or data.get("reason") or "Blocked by 1Password agent hook."
            return _block(str(message))
        return None


def discover_bundle_path(configured: str = "") -> Optional[Path]:
    """Return the configured/default bundle path if it contains run-hook.sh."""
    candidates = []
    env_path = os.environ.get("HERMES_1PASSWORD_AGENT_HOOKS_BUNDLE", "")
    for raw in (configured, env_path):
        if raw:
            candidates.append(Path(os.path.expandvars(raw)).expanduser())

    hermes_home = get_hermes_home()
    cwd = Path.cwd()
    candidates.extend(
        [
            hermes_home / "1password-hooks-bundle",
            hermes_home / "agent-hooks" / "1password-hooks-bundle",
            cwd / ".hermes" / "1password-hooks-bundle",
            cwd / "1password-hooks-bundle",
        ]
    )

    for candidate in candidates:
        if (candidate / "bin" / "run-hook.sh").is_file():
            return candidate
    return None


def build_generic_payload(tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Build JSON accepted by 1Password's upstream generic adapter."""
    cwd = _extract_cwd(args)
    command = _extract_command(tool_name, args)
    return {
        "command": command,
        "cwd": cwd,
        "workspace_roots": [cwd] if cwd else [],
        "hermes": {
            "tool_name": tool_name,
            "tool_input": args,
        },
    }


def _extract_cwd(args: Dict[str, Any]) -> str:
    raw = args.get("workdir") or args.get("cwd")
    if isinstance(raw, str) and raw:
        return str(Path(raw).expanduser())
    try:
        return str(Path.cwd())
    except OSError:
        return ""


def _extract_command(tool_name: str, args: Dict[str, Any]) -> str:
    if tool_name == "terminal":
        command = args.get("command")
        return command if isinstance(command, str) else ""
    if tool_name == "execute_code":
        code = args.get("code")
        if isinstance(code, str):
            return "python <<'PY'\n" + code + "\nPY"
    return ""


def _block(message: str) -> Dict[str, str]:
    return {"action": "block", "message": message or "Blocked by 1Password agent hook."}
