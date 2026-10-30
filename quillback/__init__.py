"""quillback — offline red-team harness for AI agent scaffolds."""

from __future__ import annotations

__version__ = "0.1.0"

# Public surface. Kept small and explicit: whatever is importable from the top
# level is the API we promise not to break without a major version bump.
from .asi import ASI, AsiCategory, get as asi_get
from .models import (
    AttackResult,
    Finding,
    ScanReport,
    Severity,
    Step,
    Tool,
    ToolCall,
)
from .registry import all_attacks, coverage_summary, select
from .runner import ScanAborted, run_scan
from .scaffold import NOT_IMPLEMENTED, Recorder, Scaffold, Trace

__all__ = [
    "__version__",
    # scaffold / target API
    "Scaffold",
    "Recorder",
    "Trace",
    "NOT_IMPLEMENTED",
    # models
    "Tool",
    "ToolCall",
    "Step",
    "Finding",
    "Severity",
    "AttackResult",
    "ScanReport",
    # registry / runner
    "all_attacks",
    "select",
    "coverage_summary",
    "run_scan",
    "ScanAborted",
    # owasp mapping
    "ASI",
    "AsiCategory",
    "asi_get",
]
