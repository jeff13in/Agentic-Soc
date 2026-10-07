"""Named defense configurations for the robustness sweep. Each adds one layer to the previous."""

from __future__ import annotations

DEFENSE_CONFIGS: dict[str, dict] = {
    "baseline": {"prompt_version": "v1", "defenses": []},
    "spotlight": {"prompt_version": "v2", "defenses": ["tagging"]},
    "sanitize": {"prompt_version": "v2", "defenses": ["tagging", "sanitize"]},
    "full": {"prompt_version": "v2", "defenses": ["tagging", "sanitize", "verifier"]},
}
