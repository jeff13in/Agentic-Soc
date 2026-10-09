from __future__ import annotations

import os

from fastapi import APIRouter

from api import deps
from evals.defense_configs import DEFENSE_CONFIGS

router = APIRouter(tags=["meta"])


@router.get("/config")
def config() -> dict:
    """What the dashboard can offer: backends, defense profiles, data status."""
    s = deps.settings()
    claude_ready = bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"))
    return {
        "default_backend": s.backend,
        "backends": [
            {"id": "heuristic", "label": "Heuristic baseline (offline)", "available": True},
            {"id": "claude", "label": f"Claude ({s.claude_model})", "available": claude_ready,
             "note": None if claude_ready else "set ANTHROPIC_API_KEY on the API server"},
            {"id": "vllm", "label": f"vLLM ({s.vllm_model})", "available": True,
             "note": f"needs a server at {s.vllm_base_url}"},
        ],
        "profiles": [{"id": k, **v} for k, v in DEFENSE_CONFIGS.items()],
        "default_profile": "spotlight",
        "data_ready": (s.data_dir / "events.parquet").exists(),
        "alerts": len(deps.alerts()),
    }
