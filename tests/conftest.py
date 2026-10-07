from __future__ import annotations

import os
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def built(tmp_path_factory: pytest.TempPathFactory) -> dict:
    """Benign week + the OTRF-format fixture, built into a temp dir; env points the app at it."""
    root = tmp_path_factory.mktemp("soc")
    os.environ["SOC_DATA_DIR"] = str(root / "generated")
    os.environ["SOC_LABELS_DIR"] = str(root / "labels")
    os.environ["SOC_DB_PATH"] = str(root / "soc.db")
    os.environ["SOC_INTEL_MODE"] = "mock"
    from data.build import build

    meta = build(FIXTURES / "otrf" / "manifest.yml", out_dir=root / "generated", labels_dir=root / "labels")
    return {"root": root, "meta": meta}


@pytest.fixture(scope="session")
def ctx(built):
    from agent.config import get_settings
    from agent.tools import build_context

    return build_context(get_settings())


@pytest.fixture(scope="session")
def labelled(built):
    from agent.schemas import LabelledAlert

    out = []
    for split in ("dev", "test"):
        path = built["root"] / "labels" / f"{split}.jsonl"
        out += [LabelledAlert.model_validate_json(x) for x in path.read_text().splitlines() if x.strip()]
    return out
