"""Runtime configuration. Every knob can be set by an env var prefixed with SOC_."""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parent.parent

# USD per million tokens (input, output). Used for cost-per-alert reporting.
PRICING: dict[str, tuple[float, float]] = {
    "claude-sonnet-5-5": (2.00, 10.00),
    "claude-opus-5-5": (4.00, 20.00),
    "claude-haiku-4-5": (1.00, 5.00),
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SOC_", env_file=".env", extra="ignore")

    backend: str = "claude"  # claude | vllm | heuristic
    claude_model: str = "claude-sonnet-5-5"
    claude_effort: str = "medium"
    # Server-side refusal fallback (Claude API only). Security telemetry can trip safety
    # classifiers; "default" lets the API re-route a declined turn instead of failing it.
    claude_fallbacks: bool = True
    # The verifier pass uses a cheaper model than the investigator.
    claude_verifier_model: str = "claude-haiku-4-5"

    vllm_base_url: str = "http://localhost:8000/v1"
    vllm_model: str = "soc-qwen-lora"
    vllm_api_key: str = "EMPTY"
    # Rented-GPU price and the batch concurrency the benchmark ran at; cost per alert is
    # latency * gpu_usd_per_hour / 3600 / concurrency.
    vllm_gpu_usd_per_hour: float = 0.79
    vllm_concurrency: int = 8

    max_steps: int = 10
    max_seconds: float = 60.0
    prompt_version: str = "v1"

    intel_mode: str = "mock"  # mock | cache | live
    abuseipdb_api_key: str | None = None
    virustotal_api_key: str | None = None

    data_dir: Path = ROOT / "data" / "generated"
    labels_dir: Path = ROOT / "data" / "labels"
    db_path: Path = ROOT / "var" / "soc.db"


def get_settings() -> Settings:
    return Settings()
