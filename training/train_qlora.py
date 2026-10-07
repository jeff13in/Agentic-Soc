"""QLoRA fine-tune of Qwen2.5-7B-Instruct on distilled triage traces (Unsloth + TRL).

    pip install -e ".[train]"
    python -m training.train_qlora --data training/data --out training/out/soc-qwen-lora

Needs a CUDA GPU (a free Colab T4 or Kaggle P100/T4 is enough for 7B in 4-bit; see
training/train_qlora.ipynb). Loss is computed on assistant turns only, so the model learns
which tools to call and what verdict to give, not to reproduce tool output or the alert.

Not run in this repo's CI: there is no GPU there. The data it consumes is validated by
training/build_sft_data.py, which is tested.
"""

from __future__ import annotations

import argparse
import inspect
import json
from pathlib import Path

BASE_MODEL = "unsloth/Qwen2.5-7B-Instruct-bnb-4bit"  # 4-bit Qwen/Qwen2.5-7B-Instruct
TARGET_MODULES = ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]
# Qwen2.5 chat template markers: tool results are rendered inside user turns, so masking
# everything up to each assistant header trains on assistant tokens only.
INSTRUCTION_PART = "<|im_start|>user\n"
RESPONSE_PART = "<|im_start|>assistant\n"


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", type=Path, default=Path("training/data"))
    ap.add_argument("--out", type=Path, default=Path("training/out/soc-qwen-lora"))
    ap.add_argument("--base-model", default=BASE_MODEL)
    ap.add_argument("--max-seq-length", type=int, default=12288)
    ap.add_argument("--rank", type=int, default=16)
    ap.add_argument("--alpha", type=int, default=32)
    ap.add_argument("--epochs", type=float, default=2)
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--batch-size", type=int, default=1)
    ap.add_argument("--grad-accum", type=int, default=8)
    ap.add_argument("--report-to", default="tensorboard", help="tensorboard | wandb | none")
    ap.add_argument("--push-to-hub", default=None, help="Hugging Face repo id for the adapter")
    args = ap.parse_args(argv)

    # Heavy imports here so `--help` and the rest of the repo work without the train extras.
    from datasets import Dataset
    from trl import SFTConfig, SFTTrainer
    from unsloth import FastLanguageModel
    from unsloth.chat_templates import train_on_responses_only

    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=args.base_model, max_seq_length=args.max_seq_length, load_in_4bit=True)
    model = FastLanguageModel.get_peft_model(
        model, r=args.rank, lora_alpha=args.alpha, lora_dropout=0.0, target_modules=TARGET_MODULES,
        bias="none", use_gradient_checkpointing="unsloth", random_state=3407)

    def render(ex: dict) -> dict:
        return {"text": tokenizer.apply_chat_template(ex["messages"], tools=ex["tools"], tokenize=False)}

    def dataset(name: str) -> Dataset | None:
        path = args.data / name
        if not path.exists():
            return None
        rows = [render(ex) for ex in load_jsonl(path)]
        keep = [r for r in rows if len(tokenizer(r["text"]).input_ids) <= args.max_seq_length]
        if len(keep) < len(rows):
            print(f"{name}: dropping {len(rows) - len(keep)} examples longer than {args.max_seq_length} tokens")
        return Dataset.from_list(keep)

    train, val = dataset("sft_train.jsonl"), dataset("sft_val.jsonl")
    if train is None or len(train) == 0:
        raise SystemExit(f"no training data in {args.data}; run `python -m training.build_sft_data` first")
    print(f"train examples: {len(train)}  val examples: {len(val) if val else 0}")

    cfg_kwargs = dict(
        output_dir=str(args.out / "checkpoints"), dataset_text_field="text", num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size, gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.lr, lr_scheduler_type="cosine", warmup_ratio=0.05, weight_decay=0.01,
        optim="adamw_8bit", logging_steps=5, save_strategy="epoch", seed=3407, report_to=args.report_to,
        eval_strategy="epoch" if val else "no", packing=False,
    )
    # TRL renamed max_seq_length to max_length; support both.
    length_key = "max_length" if "max_length" in inspect.signature(SFTConfig).parameters else "max_seq_length"
    cfg_kwargs[length_key] = args.max_seq_length

    # TRL renamed SFTTrainer's tokenizer argument to processing_class.
    tok_key = "processing_class" if "processing_class" in inspect.signature(SFTTrainer).parameters else "tokenizer"
    trainer = SFTTrainer(model=model, train_dataset=train, eval_dataset=val, args=SFTConfig(**cfg_kwargs),
                         **{tok_key: tokenizer})
    trainer = train_on_responses_only(trainer, instruction_part=INSTRUCTION_PART, response_part=RESPONSE_PART)
    stats = trainer.train()

    adapter_dir = args.out / "adapter"
    model.save_pretrained(str(adapter_dir))
    tokenizer.save_pretrained(str(adapter_dir))
    meta = {"base_model": args.base_model, "rank": args.rank, "alpha": args.alpha, "epochs": args.epochs,
            "lr": args.lr, "train_examples": len(train), "val_examples": len(val) if val else 0,
            "train_loss": stats.training_loss}
    (args.out / "training_meta.json").write_text(json.dumps(meta, indent=2))
    print(json.dumps(meta, indent=2))
    if args.push_to_hub:
        model.push_to_hub(args.push_to_hub)
        tokenizer.push_to_hub(args.push_to_hub)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
