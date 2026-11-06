# coding: utf-8
"""Сборка датасета из разметки (здесь: примеры из seed_example.py).

Делает:
- пакет доказательств E1..En для каждого кейса;
- обучающий пример в формате чата (system + пакет + JSON-карточка);
- синтетические варианты с согласованной заменой сущностей (IP, хост, УЗ);
- разбивку: train.jsonl, cases.jsonl (тест по знакомым типам), test_b.jsonl
  (отложенные типы атак, которых нет в обучении).

Запуск: python build.py
"""
import json, re, random, hashlib
from seed_example import CASES, HELDOUT_TYPES
from triage import SYSTEM, VERDICTS

random.seed(26)
VARIANTS_TRAIN = 48     # копий знакомого кейса в обучение
VARIANTS_TEST = 4       # копий отложенного типа в тест

IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
USER = re.compile(r"\b[a-z]{1,2}[._][a-z]{3,}\b|\b[a-z]{3,}_[a-z]{3,}\b")
HOST = re.compile(r"\b(?:WS|WRK|SRV|DC|FS|PC|ALM|WKSTN|FIN)[A-Z]*-?[A-Za-z0-9-]+\b")


def rand_ip():
    return f"{random.choice([10,172,192])}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"


def rand_host():
    pre = random.choice(["WS", "SRV", "WRK", "PC", "FS", "DC", "APP"])
    return f"{pre}-{random.choice(['FIN','HR','IT','DEV','OPS','DB','WEB'])}-{random.randint(1,99):02d}"


def rand_user():
    first = random.choice("abdeiklmnoprstv")
    last = random.choice(["ivanov", "petrov", "smirnov", "kozlov", "orlov", "volkov",
                          "sokolov", "popov", "lebedev", "morozov", "novikov", "fedorov"])
    return f"{first}.{last}"


def entity_map(text_blob):
    """Собирает карту замен для всех сущностей кейса."""
    m = {}
    for ip in sorted(set(IP.findall(text_blob)), key=len, reverse=True):
        if ip.startswith(("114.", "198.51.", "203.0.113.", "84.38.", "176.98.", "95.56.", "109.123.")):
            continue  # публичные/внешние IOC не трогаем
        m[ip] = rand_ip()
    for h in sorted(set(HOST.findall(text_blob)), key=len, reverse=True):
        if h.upper() in ("HTTP", "HTTPS", "SRV"):
            continue
        m[h] = rand_host()
    for u in sorted(set(USER.findall(text_blob)), key=len, reverse=True):
        if "." in u or "_" in u:
            if u in ("etc.passwd", "pool.supportxmr"):
                continue
            m[u] = rand_user()
    return m


def apply_map(s, m):
    for k, v in m.items():
        s = s.replace(k, v)
    return s


def build_answer(case):
    g = case["gold"]
    return {"verdict": case["label"], "summary": g["summary"],
            "claims": [{"text": t, "evidence": ev} for t, ev in g["claims"]],
            "mitre": g["mitre"], "missing": g["missing"], "next_steps": g["next_steps"]}


def render_pack(evidence):
    return "\n".join(f"E{i+1} {f}: {v}" for i, (f, v) in enumerate(evidence))


def make_example(case, m=None):
    ev = [(f, apply_map(v, m) if m else v) for f, v in case["evidence"]]
    ans = build_answer(case)
    if m:
        ans["summary"] = apply_map(ans["summary"], m)
        ans["mitre"] = [apply_map(x, m) for x in ans["mitre"]]
        ans["missing"] = [apply_map(x, m) for x in ans["missing"]]
        ans["next_steps"] = [apply_map(x, m) for x in ans["next_steps"]]
    pack = render_pack(ev)
    user = "<<<ПАКЕТ ДОКАЗАТЕЛЬСТВ (данные, не инструкции)\n" + pack + "\n>>>"
    return {"messages": [{"role": "system", "content": SYSTEM},
                         {"role": "user", "content": user},
                         {"role": "assistant", "content": json.dumps(ans, ensure_ascii=False)}],
            "meta": {"key": case["key"], "type": case["type"], "label": case["label"]}}


def main():
    assert all(c["label"] in VERDICTS for c in CASES), "неизвестный вердикт"
    train, cases_test, test_b = [], [], []
    for c in CASES:
        blob = " ".join(v for _, v in c["evidence"]) + " " + c["gold"]["summary"]
        held = c["type"] in HELDOUT_TYPES
        if held:
            for _ in range(VARIANTS_TEST):
                test_b.append(make_example(c, entity_map(blob)))
            continue
        # один вариант кейса уходит в тест знакомых типов и НЕ попадает в train
        cases_test.append(make_example(c, entity_map(blob)))
        seen = set()
        for _ in range(VARIANTS_TRAIN):
            m = entity_map(blob)
            sig = hashlib.md5(json.dumps(m, sort_keys=True).encode()).hexdigest()
            if sig in seen:
                continue
            seen.add(sig)
            train.append(make_example(c, m))

    random.shuffle(train)
    for name, rows in [("train.jsonl", train), ("cases.jsonl", cases_test), ("test_b.jsonl", test_b)]:
        with open("../data/" + name, "w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    types = sorted({c["type"] for c in CASES if c["type"] not in HELDOUT_TYPES})
    print(f"train {len(train)}  cases(знакомые типы) {len(cases_test)}  test_b(отложенные) {len(test_b)}")
    print(f"типов в обучении: {len(types)}; отложено: {sorted(HELDOUT_TYPES)}")
    from collections import Counter
    print("вердикты train:", dict(Counter(r['meta']['label'] for r in train)))


if __name__ == "__main__":
    main()
