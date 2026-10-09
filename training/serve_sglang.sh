#!/usr/bin/env bash
# Stretch: serve the same base model + adapter with SGLang, to compare throughput with vLLM.
#
#   ADAPTER=training/out/soc-qwen-lora/adapter ./training/serve_sglang.sh
#
# SGLang also speaks the OpenAI API, so the agent's vLLM adapter works unchanged:
# SOC_BACKEND=vllm SOC_VLLM_BASE_URL=http://<host>:30000/v1 SOC_VLLM_MODEL=soc-qwen-lora
set -euo pipefail

BASE_MODEL="${BASE_MODEL:-Qwen/Qwen2.5-7B-Instruct}"
ADAPTER="${ADAPTER:-training/out/soc-qwen-lora/adapter}"
PORT="${PORT:-30000}"

exec python -m sglang.launch_server \
  --model-path "$BASE_MODEL" \
  --port "$PORT" \
  --context-length 16384 \
  --lora-paths "soc-qwen-lora=$ADAPTER" \
  --tool-call-parser qwen25
