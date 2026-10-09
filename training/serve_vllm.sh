#!/usr/bin/env bash
# Serve Qwen2.5-7B-Instruct with the triage LoRA adapter on vLLM's OpenAI-compatible server.
#
#   ADAPTER=training/out/soc-qwen-lora/adapter ./training/serve_vllm.sh
#
# Two model names are exposed, which is what the three-way benchmark needs:
#   Qwen/Qwen2.5-7B-Instruct   base model, no fine-tune
#   soc-qwen-lora              base model + adapter
# Point the agent at it with SOC_BACKEND=vllm SOC_VLLM_BASE_URL=http://<host>:8000/v1 and
# SOC_VLLM_MODEL set to either name. Needs a CUDA GPU (24 GB is comfortable for 7B in bf16).
set -euo pipefail

BASE_MODEL="${BASE_MODEL:-Qwen/Qwen2.5-7B-Instruct}"
ADAPTER="${ADAPTER:-training/out/soc-qwen-lora/adapter}"
PORT="${PORT:-8000}"
MAX_LEN="${MAX_LEN:-16384}"

exec vllm serve "$BASE_MODEL" \
  --port "$PORT" \
  --max-model-len "$MAX_LEN" \
  --enable-lora \
  --lora-modules "soc-qwen-lora=$ADAPTER" \
  --max-lora-rank 16 \
  --enable-auto-tool-choice \
  --tool-call-parser hermes
