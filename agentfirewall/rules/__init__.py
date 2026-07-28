"""Rule registry.

``all_rules()`` returns the full set of detections the scanner runs. Adding a
new rule is as simple as appending a :class:`~agentfirewall.rules.base.Rule` here
(or a signature to :mod:`agentfirewall.rules.signatures`).
"""
from __future__ import annotations

from .base import PatternRule, Rule, Signature, compile_sig
from .signatures import PATTERN_RULES
from .structural import STRUCTURAL_RULES

__all__ = ["Rule", "PatternRule", "Signature", "compile_sig", "all_rules"]


def all_rules() -> list[Rule]:
    """Return every rule instance the engine should run, in a stable order."""
    return [*PATTERN_RULES, *STRUCTURAL_RULES]
