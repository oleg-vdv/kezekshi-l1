"""Склейка LoRA-адаптера с полной моделью (вместе с vision/audio, чтобы Ollama узнала архитектуру).
Всё на CPU, видеокарта не нужна. Выход: ./kezekshi-l1-merged (safetensors bf16).
Запуск: python merge_hf.py [адаптер] [выход]"""
import sys, torch
from transformers import AutoProcessor, AutoModelForCausalLM
from peft import PeftModel

name = "unsloth/gemma-4-E2B-it"
lora = sys.argv[1] if len(sys.argv) > 1 else "kezekshi-l1-lora"
out = sys.argv[2] if len(sys.argv) > 2 else "kezekshi-l1-merged"
model = AutoModelForCausalLM.from_pretrained(name, dtype=torch.bfloat16, device_map="cpu")
model = PeftModel.from_pretrained(model, lora).merge_and_unload()
model.save_pretrained(out, safe_serialization=True)
AutoProcessor.from_pretrained(name).save_pretrained(out)
print("done:", out, flush=True)
