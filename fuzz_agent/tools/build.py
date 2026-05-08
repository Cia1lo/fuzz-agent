"""build_target — compile harness via the engine adapter."""
from __future__ import annotations

from typing import Optional

from ..state.models import BuildArtifact, HarnessSpec, Sanitizer
from ._runtime import runtime


def build_target_impl(spec: HarnessSpec,
                      sanitizers: Optional[list[Sanitizer]]) -> BuildArtifact:
    if sanitizers:
        spec.sanitizers = sanitizers
    eng = runtime().engine(spec.engine)
    out_dir = spec.target.root / ".fuzz" / "build"
    return eng.build(spec, out_dir)
