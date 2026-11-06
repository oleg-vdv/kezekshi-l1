"""Метрики разбора: эскалация, проверка ответа, MITRE, скорость."""
import glob, json, statistics

ESC = {"suspicious", "incident_candidate"}
EXPECTED_MITRE = {"5712": "T1110", "5551": "T1110", "2502": "T1110", "100116": "T1003",
                  "40501": "T1136", "5902": "T1136", "5901": "T1136", "592": "T1070"}

def pct(a, b):
    return f"{a}/{b} ({100 * a / b:.0f}%)" if b else "–"

rows = []
for path in sorted(glob.glob("results_*.jsonl")):
    model = path[8:-6]
    R = [json.loads(l) for l in open(path, encoding="utf-8")]
    if path.endswith("_B.jsonl"):
        ok = sum(r["answer"].get("verdict") in ESC for r in R)
        exp = {json.loads(l)["case"]: json.loads(l)["expected_mitre"] for l in open("test_b.jsonl", encoding="utf-8")}
        mok = sum(any(m.split(".")[0] == e.split(".")[0] for m in r["answer"].get("mitre", []) for e in exp[r["case"]]) for r in R)
        print(json.dumps({"model": model, "heldout_attacks_caught": pct(ok, len(R)), "heldout_mitre": pct(mok, len(R)),
                          "validator_fail": pct(sum(bool(r["errors"]) for r in R), len(R))}, ensure_ascii=False))
        continue
    if len(R) < 51:
        continue
    pos = [r for r in R if r["escalate"] is True]
    neg = [r for r in R if r["escalate"] is False]
    m_esc = lambda r: r["answer"].get("verdict") in ESC
    # итог по ТЗ: правила (уровень ≥12) и отказ проверки отправляют кейс человеку
    f_esc = lambda r: m_esc(r) or bool(r["flags"]) or bool(r["errors"])
    walls = [r["wall_s"] for r in R if r["wall_s"]]
    toks = [r["tok_s"] for r in R if r.get("tok_s")]
    mit = [(r, EXPECTED_MITRE[r["rule_id"]]) for r in R if r["rule_id"] in EXPECTED_MITRE]
    mit_ok = sum(any(m.startswith(exp) for m in r["answer"].get("mitre", [])) for r, exp in mit)
    invented = sum(any(e.startswith("invented") for e in r["errors"]) for r in R)
    rows.append({
        "model": model,
        "recall_model": pct(sum(map(m_esc, pos)), len(pos)),
        "false_esc_model": pct(sum(map(m_esc, neg)), len(neg)),
        "recall_final": pct(sum(map(f_esc, pos)), len(pos)),
        "false_esc_final": pct(sum(map(f_esc, neg)), len(neg)),
        "validator_fail": pct(sum(bool(r["errors"]) for r in R), len(R)),
        "invented": invented,
        "mitre_ok": pct(mit_ok, len(mit)),
        "median_s": round(statistics.median(walls), 1),
        "p90_s": round(sorted(walls)[int(len(walls) * 0.9) - 1], 1),
        "tok_s": round(statistics.median(toks), 1) if toks else None,
        "per_day": int(86400 / statistics.median(walls)),
        "heldout_rules": pct(sum(m_esc(r) == r["escalate"] for r in R if r["rule_id"] in {"592", "60112", "5551", "61105", "19007"}), sum(r["rule_id"] in {"592", "60112", "5551", "61105", "19007"} for r in R)),
        "missed": sorted({r["rule_id"] for r in pos if not m_esc(r)}),
        "false": sorted({r["rule_id"] for r in neg if m_esc(r)}),
    })
for r in rows:
    print(json.dumps(r, ensure_ascii=False))
