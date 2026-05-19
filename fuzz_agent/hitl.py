"""Human-in-the-loop approval hooks."""
from __future__ import annotations

import asyncio
import os
from typing import Any, Protocol


class HITL(Protocol):
    async def confirm(self, kind: str, context: dict[str, Any]) -> bool: ...


class AlwaysAllow:
    async def confirm(self, kind: str, context: dict[str, Any]) -> bool:
        return True


class AlwaysDeny:
    async def confirm(self, kind: str, context: dict[str, Any]) -> bool:
        return False


class CLIPrompt:
    async def confirm(self, kind: str, context: dict[str, Any]) -> bool:
        loop = asyncio.get_running_loop()
        print(f"HITL confirmation required: {kind}")
        for key, value in context.items():
            print(f"{key}: {value}")
        answer = await loop.run_in_executor(None, input, "Allow? [y/N] ")
        return answer.strip().lower() in {"y", "yes"}


def select(name: str | None = None) -> HITL:
    selected = (name or os.environ.get("FUZZ_AGENT_HITL") or "none").strip().lower()
    if selected in {"none", "allow", "always_allow", ""}:
        return AlwaysAllow()
    if selected in {"deny", "always_deny"}:
        return AlwaysDeny()
    if selected == "cli":
        return CLIPrompt()
    return AlwaysAllow()
