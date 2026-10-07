# SOC Triage Agent

An LLM agent that investigates endpoint security alerts the way a Tier-1 analyst does. It pulls surrounding logs, the process tree, threat intel, host context and ATT&CK mappings, then returns a verdict, a confidence score and an evidence-backed report. The same loop runs on Claude (Anthropic API) or on a local model served with vLLM, and every change is scored by an eval harness.

> **Status: Phase 1 (MVP) in progress.** The agent loop, tools, Claude and vLLM adapters, eval harness, regression gate, API and CI are built and tested. The headline results table is still empty: it needs the OTRF datasets downloaded (see [Data](#data)) and a run with an Anthropic API key.

## Results

| Backend | Accuracy | FN rate | Escalated | Faithful | Tool-call validity | p50 latency | Cost / alert | Injection success |
|---|---|---|---|---|---|---|---|---|
| Claude Sonnet 5.5 | _pending_ | | | | | | | _Phase 2_ |
| Base Qwen2.5-7B (vLLM) | _Phase 3_ | | | | | | | |
| Fine-tuned Qwen2.5-7B (vLLM) | _Phase 3_ | | | | | | | |
| Heuristic baseline (rules, no LLM) | see below | | | | | | $0 | n/a |

Targets for v1: FN rate < 5%, accuracy > 85%, tool-call validity > 95%, median < 60 s per alert.

**What has been measured so far.** The offline heuristic backend on the benign week plus the 3-alert test fixture (`python -m evals.run_eval --backend heuristic`): 99 test alerts, 88.9% accuracy, 0% of benign alerts called malicious, 10.1% escalated, 100% faithfulness, 99.8% tool-call validity. It caught 1 of the 3 fixture true positives, missed 1 and escalated 1. Treat this as a check that the pipeline works, not a result. There are only 3 true positives, and the heuristic's weights were written alongside the benign generator.

## How it works

```
 data in                         agent loop                                  outputs
 ───────                         ──────────                                  ───────
 OTRF Security-Datasets ─┐       alert ──► model ──► tool call ──► result ─┐   verdict (Pydantic-validated)
 benign week generator ──┼─► Parquet ─► 12 rules ─► labelled alerts         │   trace (every prompt, call, token)
 asset inventory ────────┘       ▲          ▲                   (≤10 steps, ≤60 s)   │
                                 │          └───────────────────────────────┘        ▼
                                 DuckDB      search_logs · get_process_tree     SQLite trace store
                                             lookup_ip/hash/domain · map_attack   ├─► eval harness + CI gate
                                             get_host_context · submit_verdict    ├─► API / dashboard
                                                                                  └─► SFT data (Phase 3)
```

- **Loop** (`agent/loop.py`): a hand-written, bounded ReAct loop on native tool calling. It stops on `submit_verdict`, 10 tool calls or 60 seconds. The verdict is validated with Pydantic; one repair retry is allowed, after which the alert is escalated. A plain-text reply gets a nudge. A refusal or API error is recorded on the trace, not raised.
- **Backends** (`agent/llm/`): one `LLMClient` interface with three adapters. **Claude** uses the Messages API with adaptive thinking, effort `medium`, prompt caching on the static prefix and server-side refusal fallback; it replays the model's own content blocks so thinking stays valid. **vLLM** uses the OpenAI-compatible server. **Heuristic** is a deterministic rule-based policy that runs the pipeline offline and in CI.
- **Tools** (`agent/tools/`): all read-only. Threat intel has `mock`, `cache` and `live` modes (AbuseIPDB, VirusTotal); evals always use recorded responses. ATT&CK mapping is offline BM25 over technique descriptions, and uses the full MITRE STIX bundle if it's present.
- **Safety boundary**: no tool can change anything outside the agent's own trace store, so the worst case of a successful prompt injection is a wrong verdict, never an action on a host. Tool results can optionally be wrapped in untrusted-data tags (`--defenses tagging`); the full injection study is Phase 2.

## Data

True positives come from real attack telemetry: [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets), Windows and Sysmon logs recorded while an ATT&CK technique ran in a lab. False positives come from a seeded generator (`data/generate.py`) that produces a week of benign activity across 12 hosts. That activity deliberately trips the rules: SCCM's encoded PowerShell, Defender reading LSASS, vendor services and scheduled tasks, admin discovery commands, OneDrive Run keys and so on.

1. Download the dataset files you want into `data/raw/`.
2. Copy `data/otrf_manifest.example.yml` to `data/raw/manifest.yml`. List each file with its techniques, map the lab host to an inventory host, and optionally narrow the attack with `attack_window` / `attack_filter`.
3. `python -m data.build`

The build writes events to Parquet and runs the 12 Sigma-style rules in `data/rules/`. It then labels each alert:

- **true_positive**: the event is in the manifest's attack window.
- **false_positive**: the event came from the benign generator.
- **review**: lab background noise from an OTRF file. It's kept out of the splits until you hand-label it in `data/labels/overrides.yml`.

Alerts are split dev/test by source group, so one attack or one benign activity never lands in both. The build also records a dataset version hash covering the rules, generator, seed, dataset file hashes and overrides.

Without OTRF data, `python -m data.build --no-otrf` builds the benign week only, and `--manifest tests/fixtures/otrf/manifest.yml` adds a tiny, harmless fixture in OTRF format (used by tests and CI).

## Quickstart

```bash
pip install -e ".[dev]"
python -m data.build                       # or --manifest tests/fixtures/otrf/manifest.yml
export ANTHROPIC_API_KEY=...
python -m evals.run_eval --backend claude --repeats 3       # held-out test split
python -m evals.run_eval --backend heuristic                # offline, no key
python -m evals.gate                                        # thresholds in evals/thresholds.yml
uvicorn api.main:app --reload                               # GET /alerts, POST /triage/{id}, GET /traces/{id}, GET /evals
pytest -q
```

Configuration is environment variables prefixed `SOC_` (see `agent/config.py`), for example `SOC_BACKEND=vllm SOC_VLLM_BASE_URL=http://gpu-box:8000/v1`.

## Evaluation

`evals/run_eval.py` scores a backend and prompt version against a split. For every run it stores the git commit, prompt hash, model ID and dataset version, so results are reproducible.

| Metric | Definition |
|---|---|
| Accuracy | correct verdicts ÷ all alerts (an escalation counts as not correct) |
| FN rate | true positives called `false_positive` ÷ all true positives |
| Escalation rate | share sent to `needs_escalation` |
| ATT&CK match | Jaccard overlap of predicted vs labelled techniques, at the parent-technique level |
| Faithfulness | every evidence entry cites a tool that returned data, and every IP, hash, domain, file and technique in the summary appears in the alert or a tool result. Optional LLM judge with `--judge claude` |
| Tool-call validity | calls with valid arguments that returned a result |
| Latency, cost | p50/p95 per alert; Claude cost from token usage incl. cache reads, vLLM cost from GPU-hour price |

Rules that keep it honest: threat intel runs on recorded responses, the test split is never used for prompt tuning or training data, and `--repeats 3` reports mean ± spread. Claude Sonnet 5.5 doesn't accept a temperature setting, so run-to-run spread is reported rather than forced to zero; the vLLM backend runs at temperature 0. The CI gate (`.github/workflows/eval-smoke.yml`) runs the heuristic baseline on every PR, plus a 30-alert Claude smoke eval when the `ANTHROPIC_API_KEY` secret is set. FN rate is only gated when the sample holds at least 10 true positives.

## Design decisions and limitations

- **A hand-written loop, not a framework**, so every step is visible in the trace and easy to debug.
- **Static datasets.** This is not a SIEM: no live ingestion, and the benign population is synthetic. The real-world signal is in the OTRF true positives.
- **Small labelled set.** Expect a few hundred alerts, so differences of a few points are within noise; use `--repeats`.
- **OTRF labels are window-based.** Lab background inside the attack window gets labelled as attack unless you narrow it with `attack_filter`. Hand-check a sample.
- **The heuristic baseline is optimistic on the benign week** because its weights and the generator share an author. It's a pipeline check and a floor, not a competitor.

## Roadmap

- [ ] **Phase 1:** OTRF data loaded, first Claude results table in this README, one traced alert walkthrough
- [ ] **Phase 2:** prompt-injection study. Attacker-controlled fields (command lines, file and service names), five attack types, and defenses measured one at a time: tagging, field sanitization, a verifier pass, least privilege and adversarial fine-tuning
- [ ] **Phase 3:** distil filtered Claude traces into QLoRA SFT data for Qwen2.5-7B, serve with vLLM (stretch: SGLang), three-way benchmark
- [ ] **Phase 4:** React dashboard (alert queue, trace viewer, eval results), Docker Compose, Langfuse tracing

## Repo layout

```
agent/      loop.py, llm/ (Claude, vLLM, heuristic), tools/, prompts/, defenses/, schemas.py, store.py
api/        FastAPI app and routes
data/       generate.py (benign week), ingest/otrf.py, rules/, detect.py, build.py, assets.yml, attack/, intel/
evals/      run_eval.py, metrics.py, gate.py, thresholds.yml, judges/
tests/      unit and end-to-end tests; fixtures/otrf is a harmless OTRF-format sample
```
