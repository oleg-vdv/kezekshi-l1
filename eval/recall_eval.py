# coding: utf-8
"""Замер recall контура на управляемых атаках (ground truth задаётся вручную).

Берёт список атак (имя, ожидаемые техники MITRE, окно времени, опционально IP
источника). Для каждой атаки тянет алерты Wazuh в окне, прогоняет ключевые через
модель + памятку и считает, ПОЙМАНА ли атака:
  - detected   : Wazuh вообще сгенерировал алерт в окне (иначе слепое пятно правил);
  - escalated_pipeline : хотя бы один алерт ушёл бы на L2 (модель susp/inc ИЛИ памятка
                 susp/inc) - это recall БОЕВОГО контура (ассист);
  - escalated_model    : хотя бы один алерт сама модель назвала susp/inc - recall
                 одной модели (без памятки-предохранителя).

Recall = поймано / всего атак. Отдельно считаем по двум уровням (модель и контур),
потому что сегодня реальная сеть безопасности - памятка, а не модель.

Запуск: python recall_eval.py attacks.json
"""
import os, sys, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
os.environ.setdefault("TRIAGE_THINK", "0")
os.environ.setdefault("TRIAGE_HINT", "1")
import wz, normalize, triage, rulebook  # noqa: E402

ESC = {"suspicious", "incident_candidate"}
MODEL = os.environ.get("MODEL", "kezekshi-l1-v6")
MAX_PER_ATTACK = int(os.environ.get("RECALL_MAX", "6"))   # сколько алертов гнать через модель на атаку


def alerts_in(since, until, src_ip=None):
    flt = [{"range": {"timestamp": {"gte": since, "lte": until}}}]
    if src_ip:
        flt.append({"term": {"data.srcip": src_ip}})
    body = {"size": 200, "sort": [{"timestamp": "asc"}], "query": {"bool": {"filter": flt}}}
    return wz.q("/wazuh-alerts-*/_search", body)["hits"]["hits"]


def run(attacks):
    rows = []
    for a in attacks:
        hits = alerts_in(a["since"], a["until"], a.get("src_ip"))
        rules = sorted({h["_source"].get("rule", {}).get("id") for h in hits})
        detected = len(hits) > 0
        esc_model = esc_pipe = False
        model_verdicts = []
        # прогоняем до MAX_PER_ATTACK наиболее тяжёлых алертов (по уровню)
        hits_sorted = sorted(hits, key=lambda h: -int(h["_source"].get("rule", {}).get("level", 0)))
        for h in hits_sorted[:MAX_PER_ATTACK]:
            s = h["_source"]
            case = normalize.to_case(s, h["_id"])
            ev = {e["field"]: e["value"] for e in case["evidence"]}
            rb = rulebook.label(case["rule_id"], ev, case["level"])[0]
            try:
                ans, _ = triage.ask(MODEL, case)
            except Exception:
                ans = {}
            mv = (ans or {}).get("verdict")
            model_verdicts.append(mv)
            if mv in ESC:
                esc_model = True
            if mv in ESC or rb in ESC:        # контур в ассист-режиме поднимает на L2
                esc_pipe = True
        rows.append({"name": a["name"], "mitre": a.get("mitre", []), "alerts": len(hits),
                     "rules": rules, "detected": detected,
                     "escalated_model": esc_model, "escalated_pipeline": esc_pipe,
                     "model_verdicts": model_verdicts})
    return rows


def main():
    attacks = json.load(open(sys.argv[1], encoding="utf-8"))
    rows = run(attacks)
    n = len(rows)
    det = sum(r["detected"] for r in rows)
    em = sum(r["escalated_model"] for r in rows)
    ep = sum(r["escalated_pipeline"] for r in rows)
    print("=" * 70)
    for r in rows:
        mark = "OK " if r["escalated_pipeline"] else ("DET" if r["detected"] else "MISS")
        print(f"[{mark}] {r['name']:<28} алертов {r['alerts']:>3} правила {r['rules']} "
              f"| модель-эск {r['escalated_model']} контур-эск {r['escalated_pipeline']} "
              f"| вердикты {r['model_verdicts']}")
    print("=" * 70)
    print(f"атак: {n}")
    print(f"Wazuh детект (есть алерт):      {det}/{n}")
    print(f"recall МОДЕЛИ (сама эскалирует): {em}/{n}")
    print(f"recall КОНТУРА (модель+памятка): {ep}/{n}")
    print(f"Правило трёх: при 0 пропусков и n={n} верхняя граница промаха ~{round(3/n*100) if n else 0}% (recall >= {100-round(3/n*100) if n else 0}%)")


if __name__ == "__main__":
    main()
