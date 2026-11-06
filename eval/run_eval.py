# coding: utf-8
"""Оценка модели на тестовом наборе в формате чата.

Берёт test-файл (строки {messages:[system,user,assistant], meta}), шлёт в Ollama
system+пакет, получает JSON-карточку модели и сравнивает с эталоном:
- точность вердикта (4 класса);
- эскалация (suspicious|incident_candidate) против не-эскалации: recall и ложные;
- техники MITRE: полнота и точность;
- проверка ответа: ссылки claims на существующие E-id, отсутствие выдуманных IP/хешей.

Запуск: python run_eval.py <model> <test.jsonl> [think|nothink]
Выход:  результаты в eval/out/<model>__<test>__<mode>[__tight].jsonl (с сырым
        ответом модели) и строка метрик. TRIAGE_TIGHT=0 - прежняя свободная схема.
"""
import os, sys, json, re, time, urllib.request
from collections import Counter

OLLAMA = os.environ.get("OLLAMA", "http://localhost:11434/api/chat")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import attack  # noqa: E402  локальный индекс ATT&CK для подбора кандидатов MITRE
import triage  # noqa: E402  схема ответа та же, что в боевом контуре
RAG = os.environ.get("MITRE_RAG") == "1"
TIGHT = os.environ.get("TRIAGE_TIGHT", "1") == "1"
VERDICTS = ["false_positive", "benign_true_positive", "suspicious", "incident_candidate"]
ESC = {"suspicious", "incident_candidate"}
IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
MITRE = re.compile(r"^T\d{4}(\.\d{3})?$")

def ask(model, system, user, think, schema):
    body = {"model": model, "stream": False, "format": schema,
            "options": {"temperature": 0, "num_ctx": 8192, "num_predict": 4096},
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
    if not think:
        body["think"] = False
    req = urllib.request.Request(OLLAMA, json.dumps(body).encode(), {"Content-Type": "application/json"})
    t = time.time()
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=300) as r:
                res = json.loads(r.read())
            try:
                return json.loads(res["message"]["content"]), round(time.time() - t, 2)
            except Exception:
                return {}, round(time.time() - t, 2)  # модель вернула не-JSON
        except Exception as e:
            if attempt == 2:
                print(f"  ask failed after retries: {type(e).__name__}: {e}", flush=True)
                return {}, round(time.time() - t, 2)
            time.sleep(3)


def evidence_ids(user):
    return set(re.findall(r"\bE\d+\b", user))


def pack_text(user):
    return user


def validate(ans, user):
    ids = evidence_ids(user)
    pack = pack_text(user)
    errs = []
    if ans.get("verdict") not in VERDICTS:
        errs.append("bad_verdict")
    for c in ans.get("claims", []):
        refs = [r for r in c.get("evidence", []) if r in ids]
        if not refs:
            errs.append("claim_without_evidence")
    # выдуманные IP/хеши, которых нет в пакете
    for ip in set(IP.findall(json.dumps(ans, ensure_ascii=False))):
        if ip not in pack and not MITRE.match(ip):
            errs.append("invented_ip")
    for h in set(HASH.findall(json.dumps(ans, ensure_ascii=False))):
        if h not in pack:
            errs.append("invented_hash")
    for m in ans.get("mitre", []):
        if not MITRE.match(m):
            errs.append("bad_mitre_format")
    return errs


def main():
    model, path = sys.argv[1], sys.argv[2]
    think = (len(sys.argv) > 3 and sys.argv[3] == "think")
    mode = "think" if think else "nothink"
    rows = [json.loads(l) for l in open(path, encoding="utf-8")]
    os.makedirs("out", exist_ok=True)
    tag = f"{model.replace(':','_').replace('/','_')}__{os.path.basename(path).replace('.jsonl','')}__{mode}{'__tight' if TIGHT else ''}"
    out = open(f"out/{tag}.jsonl", "w", encoding="utf-8")

    v_ok = esc_tp = esc_fn = esc_fp = esc_tn = mitre_hit = mitre_tot = mitre_pred = valfail = 0
    times = []
    for i, r in enumerate(rows):
        system = r["messages"][0]["content"]
        user = r["messages"][1]["content"]
        cands = attack.candidates(user) if RAG else None
        if cands:
            system = system + attack.block_for(cands)   # подбор кандидатов MITRE в системный промпт
        schema = (triage.response_schema(evidence_ids(user), [t for t, _ in cands] if cands is not None else None)
                  if TIGHT else triage.SCHEMA)
        gold = json.loads(r["messages"][2]["content"])
        ans, wall = ask(model, system, user, think, schema)
        times.append(wall)
        gv, pv = gold["verdict"], ans.get("verdict")
        v_ok += (gv == pv)
        g_esc, p_esc = gv in ESC, pv in ESC
        esc_tp += (g_esc and p_esc); esc_fn += (g_esc and not p_esc)
        esc_fp += (not g_esc and p_esc); esc_tn += (not g_esc and not p_esc)
        gm, pm = set(gold["mitre"]), set(ans.get("mitre", []))
        mitre_tot += len(gm); mitre_hit += len(gm & pm); mitre_pred += len(pm)
        errs = validate(ans, user)
        valfail += bool(errs)
        out.write(json.dumps({"key": r["meta"]["key"], "gold": gv, "pred": pv,
                              "mitre_gold": sorted(gm), "mitre_pred": sorted(pm),
                              "errs": errs, "wall": wall, "answer": ans}, ensure_ascii=False) + "\n")
        print(f"{i} {r['meta']['key']} gold={gv} pred={pv} {wall}s", flush=True)
    n = len(rows)
    tsort = sorted(times)
    res = {"model": model, "test": os.path.basename(path), "mode": mode, "n": n,
           "verdict_acc": f"{v_ok}/{n}",
           "escalation_recall": f"{esc_tp}/{esc_tp+esc_fn}" if esc_tp+esc_fn else "n/a",
           "false_escalation": f"{esc_fp}/{esc_fp+esc_tn}" if esc_fp+esc_tn else "n/a",
           "mitre": f"{mitre_hit}/{mitre_tot}" if mitre_tot else "n/a",
           "mitre_precision": f"{mitre_hit}/{mitre_pred}" if mitre_tot else "n/a",
           "validator_fail": f"{valfail}/{n}",
           "median_s": tsort[n//2] if n else 0}
    print("RESULT " + json.dumps(res, ensure_ascii=False))
    with open(f"out/{tag}.metrics.json", "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
