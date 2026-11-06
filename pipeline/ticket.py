# coding: utf-8
"""Оформление тикета L1 -> L2 в виде структурированного SOC-отчёта.

Берёт запись очереди (с пакетом доказательств и карточкой модели) и собирает
тикет по принятой форме: ID, заголовок, время, активы, категория, критичность,
описание, MITRE, индикаторы компрометации, рекомендации и записка для L2.
Аналитическую суть даёт модель (summary/claims/mitre/next_steps), структурные
поля (активы, ИОК, критичность) выводятся из самого алерта - без домыслов.
"""
import re

CRIT = {"incident_candidate": "High", "suspicious": "Medium",
        "benign_true_positive": "Low", "false_positive": "Информационно", "": "Требует разбора"}
# ранг тяжести: берём безопасный максимум из вердикта модели и памятки,
# чтобы занижение моделью не опускало реальную атаку (памятка - разметка аналитика)
RANK = {"incident_candidate": 3, "suspicious": 2, "benign_true_positive": 1, "false_positive": 0, "": 0}


def eff_verdict(model_v, rule_v):
    model_v, rule_v = model_v or "", rule_v or ""
    return model_v if RANK.get(model_v, 0) >= RANK.get(rule_v, 0) else rule_v
IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH = re.compile(r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b")
URL = re.compile(r"https?://[^\s\"'<>]+", re.I)
WINPATH = re.compile(r"[A-Za-z]:\\[^\s\"'<>|]+")
NIXPATH = re.compile(r"(?:/[\w.\-]+){2,}")
PRIVATE = ("10.", "192.168.", "127.", "172.16.", "172.17.", "172.18.", "172.19.")


def _evget(ev, *fields):
    for f in fields:
        for e in ev:
            if e.get("field") == f and e.get("value"):
                return e["value"]
    return ""


def _blob(ev):
    return "\n".join(e.get("value", "") for e in ev)


def _title(card, rule_desc, rid):
    s = (card.get("summary") or "").strip()
    if s:
        first = re.split(r"(?<=[.!?])\s", s)[0]
        return first[:120]
    return (rule_desc or f"Срабатывание правила {rid}")[:120]


def _iocs(ev):
    blob = _blob(ev)
    out, seen = [], set()

    def add(kind, val, ctx):
        key = (kind, val)
        if val and key not in seen:
            seen.add(key); out.append((kind, val, ctx))

    # хеши и файлы из FIM - приоритетные индикаторы
    for h in HASH.findall(blob):
        add("Хеш", h, "")
    path = _evget(ev, "syscheck.path")
    if path:
        add("Файл", path, "объект FIM")
    for u in URL.findall(blob):
        add("URL", u, "")
    src = _evget(ev, "data.srcip")
    if src:
        add("IP", src, "источник соединения/входа")
    # прочие внешние IP из тела
    for ip in IP.findall(blob):
        if not ip.startswith(PRIVATE) and ip != src:
            add("IP (внешний)", ip, "встречается в событии")
    return out[:12]


def _assets(ev, rec):
    parts = []
    coll = _evget(ev, "collector.agent") or rec.get("agent")
    if coll:
        parts.append(f"агент-сборщик {coll}")
    eh = _evget(ev, "event.host") or rec.get("event_host")
    if eh:
        parts.append(f"компьютер события {eh}")
    user = _evget(ev, "data.srcuser", "data.dstuser", "data.win.eventdata.targetUserName", "data.uid")
    if user and user not in ("?", "-"):
        parts.append(f"пользователь {user}")
    src = _evget(ev, "data.srcip")
    if src:
        parts.append(f"источник {src}")
    return "; ".join(parts) or "не определены"


def _category(eff, ev):
    tac = _evget(ev, "rule.mitre.tactic")
    base = {"incident_candidate": "подтверждённый инцидент",
            "suspicious": "подозрительная активность, требует разбора",
            "benign_true_positive": "легитимное событие",
            "false_positive": "ложное срабатывание"}.get(eff, "требует разбора")
    return f"{base}" + (f" ({tac})" if tac else "")


def render(rec):
    """rec: запись очереди {case, rule_id, level, agent, event_host, evidence, card, ts}."""
    ev = rec.get("evidence") or []
    card = rec.get("card") or {}
    rid = str(rec.get("rule_id", ""))
    v = card.get("verdict") or ""
    eff = eff_verdict(v, rec.get("rule_verdict"))   # безопасный максимум модель/памятка
    crit = CRIT.get(eff, "Требует разбора")
    if rec.get("level", 0) >= 12 and eff in ("suspicious", "incident_candidate"):
        crit = "High"
    rule_desc = _evget(ev, "rule.description")
    ts = _evget(ev, "timestamp") or rec.get("ts", "")
    prefix = "INC" if eff in ("incident_candidate", "suspicious") else "TKT"
    tid = f"{prefix}-{str(rec.get('case',''))[-8:]}"

    L = []
    L.append(f"ТИКЕТ {tid}   ·   критичность: {crit}")
    L.append(f"Заголовок: {_title(card, rule_desc, rid)}")
    L.append(f"Обнаружено: {ts} (правило {rid}, уровень {rec.get('level','?')})")
    ctx = _evget(ev, "context.same_rule_same_agent_pm1h")
    if ctx and ctx.isdigit() and int(ctx) > 1:
        L.append(f"Период активности: серия, {ctx} однотипных событий за ±1ч")
    L.append(f"Затронутые активы: {_assets(ev, rec)}")
    L.append(f"Категория: {_category(eff, ev)}")
    L.append(f"Вердикт модели: {v or '—'}   Памятка: {rec.get('rule_verdict','—')}")
    if RANK.get(v or "", 0) < RANK.get(eff, 0):
        L.append(f"! Модель занизила вердикт ({v or '—'}); итоговая тяжесть взята по памятке ({eff}). "
                 f"Описание и рекомендации ниже - черновик модели, проверять критически; не отключать правило по её совету.")
    L.append("")
    L.append("Описание:")
    L.append(f"  {card.get('summary','') or rule_desc or '—'}")
    for c in card.get("claims", []):
        refs = ", ".join(c.get("evidence", []))
        L.append(f"  - {c.get('text','')}" + (f" [{refs}]" if refs else ""))
    L.append("")
    L.append("Техники MITRE ATT&CK: " + (", ".join(card.get("mitre", [])) or "нет"))

    iocs = _iocs(ev)
    if iocs:
        L.append("")
        L.append("Индикаторы компрометации:")
        for kind, val, c in iocs:
            L.append(f"  {kind}: {val}" + (f"  ({c})" if c else ""))

    steps = card.get("next_steps") or rec.get("rule_checks") or []
    L.append("")
    L.append("Рекомендации (L1):")
    if steps:
        for i, s in enumerate(steps, 1):
            L.append(f"  {i}. {s}")
    else:
        L.append("  1. Разобрать событие, сверить с владельцем актива.")
    miss = card.get("missing") or []
    if miss:
        L.append("Не хватает: " + "; ".join(miss))

    # записка для L2 - компактная выжимка
    L.append("")
    L.append("Записка для L2:")
    L.append(f"  {tid}, {crit}. {_assets(ev, rec)}.")
    L.append(f"  {ts}: {_title(card, rule_desc, rid).rstrip('.')}.")
    if card.get("summary"):
        L.append(f"  Суть: {card['summary']}")
    if card.get("mitre"):
        L.append(f"  MITRE: {', '.join(card['mitre'])}")
    return "\n".join(L)
