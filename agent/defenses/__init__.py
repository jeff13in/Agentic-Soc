"""Prompt-injection defenses. Each one can be switched on independently for the robustness sweep.

tagging   wrap tool results in untrusted-data envelopes          (agent/defenses/tagging.py)
sanitize  flag instruction-like text in attacker-controlled fields (agent/defenses/sanitizer.py)
verifier  second pass over structured facts; disagreement escalates (agent/defenses/verifier.py)

Least privilege (read-only tools, no response actions) is always on and is not a switch.
"""

from __future__ import annotations

from agent.config import Settings

KNOWN_DEFENSES = ("tagging", "sanitize", "verifier")


def make_verifier(backend: str, settings: Settings):
    from agent.defenses.verifier import HeuristicVerifier, LLMVerifier

    if backend == "heuristic":
        return HeuristicVerifier()
    from agent.llm import make_client

    model = settings.claude_verifier_model if backend == "claude" else None
    return LLMVerifier(make_client(backend, settings, model))
