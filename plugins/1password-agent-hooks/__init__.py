"""1Password agent-hooks integration for Hermes.

Enable with:

    hermes plugins enable 1password-agent-hooks

Then place a 1Password agent-hooks bundle at one of the default locations
(e.g. ``~/.hermes/1password-hooks-bundle``) or set
``onepassword_agent_hooks.bundle_path`` in config.yaml.
"""

from __future__ import annotations

import logging
from typing import Any, Iterable

from .bridge import (
    DEFAULT_HOOK_NAME,
    DEFAULT_TARGET_TOOLS,
    DEFAULT_TIMEOUT_SECONDS,
    OnePasswordAgentHookBridge,
    discover_bundle_path,
)

logger = logging.getLogger(__name__)


def _coerce_target_tools(raw: Any) -> Iterable[str]:
    if isinstance(raw, list):
        return [str(item) for item in raw if str(item)]
    if isinstance(raw, str) and raw.strip():
        return [part.strip() for part in raw.split(",") if part.strip()]
    return DEFAULT_TARGET_TOOLS


def _coerce_timeout(raw: Any) -> int:
    try:
        return int(raw or DEFAULT_TIMEOUT_SECONDS)
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT_SECONDS


def register(ctx) -> None:
    try:
        from hermes_cli.config import load_config

        config = load_config()
    except Exception as exc:  # pragma: no cover - defensive; fail open
        logger.warning("1password-agent-hooks could not read config: %s", exc)
        return

    cfg = config.get("onepassword_agent_hooks", {})
    if not isinstance(cfg, dict):
        cfg = {}

    bundle_path = discover_bundle_path(str(cfg.get("bundle_path") or ""))
    if bundle_path is None:
        logger.info(
            "1password-agent-hooks enabled but no bundle found. Set "
            "onepassword_agent_hooks.bundle_path or install a bundle at "
            "~/.hermes/1password-hooks-bundle."
        )
        return

    bridge = OnePasswordAgentHookBridge(
        bundle_path,
        hook_name=str(cfg.get("hook_name") or DEFAULT_HOOK_NAME),
        target_tools=_coerce_target_tools(cfg.get("target_tools")),
        timeout=_coerce_timeout(cfg.get("timeout")),
    )
    ctx.register_hook("pre_tool_call", bridge.pre_tool_call)
    logger.info("1password-agent-hooks registered using bundle %s", bundle_path)
