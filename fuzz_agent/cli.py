"""Command-line entry: `fuzz-agent {analyze,run,triage,status}`."""
from __future__ import annotations

import asyncio
import json
import re
import sys
from pathlib import Path

import click

from . import tools
from .events.stream import EventBus
from .orchestrator import CampaignGoal, Orchestrator
from .state.models import EngineKind
from .state.store import CampaignStore

_ENGINE_CHOICES = [
    EngineKind.LIBFUZZER.value,
    EngineKind.CARGO_FUZZ.value,
    EngineKind.ATHERIS.value,
    "cargo_fuzz",
]


def _parse_duration(s: str) -> int:
    m = re.fullmatch(r"(\d+)([smhd]?)", s.strip())
    if not m:
        raise click.BadParameter(f"bad duration: {s!r}")
    n, u = int(m.group(1)), m.group(2) or "s"
    return n * {"s": 1, "m": 60, "h": 3600, "d": 86400}[u]


def _parse_engine(s: str) -> EngineKind:
    try:
        return EngineKind(s)
    except ValueError as exc:
        if s == "cargo_fuzz":
            return EngineKind.CARGO_FUZZ
        raise click.BadParameter(f"unknown engine: {s!r}") from exc


@click.group()
def main() -> None:
    """Fuzz Agent — harness-engineering-style fuzzing orchestrator."""


@main.command()
@click.option("--host", default="127.0.0.1")
@click.option("--port", default=8000, type=int)
def serve(host: str, port: int) -> None:
    """Run the Fuzz Agent web UI."""
    try:
        import uvicorn
    except ImportError as exc:
        raise click.UsageError("Install with `pip install fuzz-agent[web]`") from exc
    from fuzz_agent.web.server import app

    uvicorn.run(app, host=host, port=port)


@main.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path))
def analyze(path: Path) -> None:
    """Identify language, build system, and likely fuzz entry points."""
    profile = tools.analyze_target(str(path))
    click.echo(json.dumps({
        "root": str(profile.root),
        "language": profile.language.value,
        "build_system": profile.build_system,
        "entry_points": profile.entry_points,
        "notes": profile.notes,
    }, indent=2))


@main.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--time", "time_str", default="30m", help="time budget (e.g. 30m, 2h)")
@click.option("--max-crashes", default=50, type=int)
@click.option("--plateau", default=300, type=int, help="plateau idle seconds")
@click.option("--no-triage", is_flag=True, default=False)
@click.option(
    "--engine",
    "engine_str",
    default=EngineKind.LIBFUZZER.value,
    type=click.Choice(_ENGINE_CHOICES),
)
def run(
    path: Path,
    time_str: str,
    max_crashes: int,
    plateau: int,
    no_triage: bool,
    engine_str: str,
) -> None:
    """Plan + drive a fuzz campaign on PATH."""
    root = Path.cwd()
    store = CampaignStore(root)
    bus = EventBus()
    # Tools default to a runtime singleton — wire it to ours.
    from .tools import _runtime
    rt = _runtime.runtime()
    rt.bus = bus
    rt.store = store

    goal = CampaignGoal(
        target_path=path.resolve(),
        time_budget_sec=_parse_duration(time_str),
        max_unique_crashes=max_crashes,
        coverage_plateau_sec=plateau,
        auto_triage=not no_triage,
        engine=_parse_engine(engine_str),
    )
    orch = Orchestrator(store, bus)
    summary = asyncio.run(orch.run(goal))
    click.echo(json.dumps(summary, indent=2, default=str))


@main.command()
@click.argument("campaign_id")
@click.option("--top", default=20, type=int)
def triage(campaign_id: str, top: int) -> None:
    """Re-run crash triage on an existing campaign."""
    crashes = tools.triage_crashes(campaign_id, top_n=top)
    click.echo(json.dumps([
        {"crash_id": c.crash_id, "stack_hash": c.stack_hash,
         "sanitizer_kind": c.sanitizer_kind, "top_frames": c.top_frames,
         "status": c.status.value, "reproducible": c.reproducible,
         "vulnerability_matches": [
             {"rule_id": m.rule_id, "title": m.title, "cwe": m.cwe,
              "confidence": m.confidence, "source": m.source}
             for m in c.vulnerability_matches
         ]}
        for c in crashes
    ], indent=2))


@main.command()
@click.argument("campaign_id")
@click.option("--time", "time_str", default=None, help="new time budget (e.g. 30m, 2h)")
def resume(campaign_id: str, time_str: str | None) -> None:
    """Resume an existing campaign as a new campaign seeded from its corpus."""
    budget = _parse_duration(time_str) if time_str else None
    cid = tools.resume_campaign(campaign_id, budget)
    click.echo(json.dumps({"campaign_id": cid, "resumed_from": campaign_id}, indent=2))


@main.command()
@click.argument("campaign_id")
def status(campaign_id: str) -> None:
    """Show current stats for a campaign."""
    s = tools.query_status(campaign_id)
    click.echo(json.dumps({
        "campaign_id": s.campaign_id, "status": s.status.value,
        "elapsed_sec": s.elapsed_sec, "execs_total": s.execs_total,
        "execs_per_sec": s.execs_per_sec, "edges_covered": s.edges_covered,
        "corpus_size": s.corpus_size, "unique_crashes": s.unique_crashes,
    }, indent=2))


if __name__ == "__main__":
    sys.exit(main())
