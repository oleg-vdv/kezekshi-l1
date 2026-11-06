"""Дообучение L1-агента без Unsloth: LoRA на bf16-модели, transformers + peft.

Unsloth на этой связке (Gemma 4 E2B, Windows, offload) ломает обратный проход: grad_norm 1e6, loss не падает.
Таблица эмбеддингов по слоям (2,3 млрд параметров) живёт в RAM, остальное на GPU.

Запуск:  python train_hf.py train.jsonl [max_steps]
Выход:   ./kezekshi-l1-lora (адаптер); склейка отдельно, merge_hf.py.
"""
import json, math, random, sys, time, torch
from torch import nn
from transformers import AutoProcessor, AutoModelForCausalLM
from peft import LoraConfig, get_peft_model

data_path = sys.argv[1]
max_steps = int(sys.argv[2]) if len(sys.argv) > 2 else -1
name = "unsloth/gemma-4-E2B-it"
EPOCHS, ACCUM, LR, MAX_LEN = 2, 8, 2e-4, 2048
torch.manual_seed(26); random.seed(26)

tok = getattr(AutoProcessor.from_pretrained(name), "tokenizer", None)
model = AutoModelForCausalLM.from_pretrained(name, dtype=torch.bfloat16, device_map="cpu", attn_implementation="sdpa")
model.config.use_cache = False


class CpuEmbedding(nn.Module):
    """Поиск по таблице на CPU, результат на GPU."""
    def __init__(self, emb):
        super().__init__()
        self.emb = emb

    def forward(self, ids):
        return self.emb(ids.cpu()).to("cuda")


lm = model.model.language_model
ple = lm.embed_tokens_per_layer
lm.embed_tokens_per_layer = None
model.model.vision_tower = None
model.model.audio_tower = None
model.to("cuda")
lm.embed_tokens_per_layer = CpuEmbedding(ple.requires_grad_(False))

model.gradient_checkpointing_enable(gradient_checkpointing_kwargs={"use_reentrant": False})
model.enable_input_require_grads()
model = get_peft_model(model, LoraConfig(r=16, lora_alpha=32, lora_dropout=0, task_type="CAUSAL_LM",
                                         target_modules=r".*language_model.*\.(q_proj|k_proj|v_proj|o_proj|gate_proj|up_proj|down_proj)"))

resp = tok("<|turn>model\n", add_special_tokens=False).input_ids
data = []
for line in open(data_path, encoding="utf-8"):
    m = json.loads(line)["messages"]
    seq = tok(tok.apply_chat_template(m, tokenize=False), add_special_tokens=False).input_ids
    if len(seq) > MAX_LEN:
        continue
    start = max(j for j in range(len(seq) - len(resp)) if seq[j:j + len(resp)] == resp) + len(resp)
    data.append((seq, start))
print("examples", len(data), flush=True)

total = math.ceil(len(data) * EPOCHS / ACCUM) if max_steps == -1 else max_steps
warmup = max(1, int(total * 0.05))
params = [p for p in model.parameters() if p.requires_grad]
opt = torch.optim.AdamW(params, lr=LR, weight_decay=0.0)
sched = torch.optim.lr_scheduler.LambdaLR(opt, lambda s: (s + 1) / warmup if s < warmup
                                          else 0.5 * (1 + math.cos(math.pi * (s - warmup) / max(1, total - warmup))))
model.train()
order = [i for _ in range(EPOCHS) for i in random.sample(range(len(data)), len(data))]
step, run_loss, t0 = 0, 0.0, time.time()
for k, i in enumerate(order):
    seq, start = data[i]
    ids = torch.tensor([seq], device="cuda")
    # ответ стоит в конце: логиты только для него, иначе словарь 262k съедает гигабайт
    logits = model(input_ids=ids, logits_to_keep=len(seq) - start + 1).logits[0, :-1].float()
    loss = nn.functional.cross_entropy(logits, ids[0, start:]) / ACCUM
    loss.backward()
    run_loss += loss.item()
    if (k + 1) % ACCUM:
        continue
    gn = torch.nn.utils.clip_grad_norm_(params, 1.0).item()
    opt.step(); sched.step(); opt.zero_grad()
    step += 1
    if step % 5 == 0 or step == 1:
        el = time.time() - t0
        print(f"step {step}/{total} loss {run_loss:.3f} grad_norm {gn:.2f} lr {sched.get_last_lr()[0]:.2e} "
              f"peak_GiB {torch.cuda.max_memory_allocated() / 2**30:.2f} {el / step:.1f}s/step eta {el / step * (total - step) / 60:.0f}m",
              flush=True)
    run_loss = 0.0
    if max_steps == -1 and step % 50 == 0:
        model.save_pretrained(f"kezekshi-l1-lora-step{step}")
    if step >= total:
        break
if max_steps == -1:
    model.save_pretrained("kezekshi-l1-lora")
    print("done: kezekshi-l1-lora", flush=True)
