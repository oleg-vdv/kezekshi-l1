# coding: utf-8
"""Алерт Wazuh (документ индексатора) -> пакет доказательств для модели.

На вход `_source` документа wazuh-alerts, на выход case в том же формате, что
ждут `src/triage.py` и `src/rulebook.py`: {case, rule_id, level, agent,
event_host, evidence:[{id,field,value}]}.

Две доработки из замера на стенде:
- агент-сборщик и компьютер из самого события разводятся в разные поля
  (иначе модель предлагает изолировать сборщик логов, а не пострадавший хост);
- лечится битая кодировка Defender (cp1251, прочитанная как UTF-8).
"""
import re

# поля верхнего уровня, которые несут смысл для L1 (как в замере)
KEEP = ("timestamp", "rule", "agent", "data", "full_log", "location",
        "syscheck", "decoder", "predecoder")
# шумные/комплаенс-поля, которые только раздувают пакет
SKIP = ("rule.mail", "rule.firedtimes", "rule.gpg", "rule.gdpr", "rule.hipaa",
        "rule.nist", "rule.pci", "rule.tsc", "rule.mitre.id", "rule.info",
        "manager.", "agent.labels", "rule.description_ovr")

_MOJI = re.compile(r"[ÂÃÐÑ][\x80-\xBF]")


def fix_mojibake(s):
    """Best-effort: строку в cp1251, прочитанную как UTF-8/latin1, вернуть читаемой."""
    if not isinstance(s, str) or not _MOJI.search(s):
        return s
    try:
        return s.encode("latin1").decode("cp1251")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return s


def flat(d, prefix=""):
    for k, v in d.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            yield from flat(v, key + ".")
        elif isinstance(v, list):
            yield key, ", ".join(map(str, v))
        else:
            yield key, fix_mojibake(str(v))


def event_host(src):
    """Компьютер из самого события (не агент-сборщик), если его видно."""
    data = src.get("data", {})
    win = data.get("win", {}) if isinstance(data, dict) else {}
    sysm = win.get("system", {}) if isinstance(win, dict) else {}
    for cand in (sysm.get("computer"), data.get("dstuser") and data.get("dsthostname"),
                 data.get("hostname"), data.get("srcip")):
        if cand:
            return str(cand)
    return ""


def wazuh_mitre(rule):
    """Техники из метки правила Wazuh: [(id, название)] для кандидатов MITRE.

    В пакет доказательств rule.mitre.id не идёт (формат обучения), подсказка
    передаётся отдельным полем. Правило может не иметь метки.
    """
    m = rule.get("mitre") or {}
    ids, names = m.get("id") or [], m.get("technique") or []
    ids = [ids] if isinstance(ids, str) else ids
    names = [names] if isinstance(names, str) else names
    return [(str(t), str(names[i]) if i < len(names) else "") for i, t in enumerate(ids)]


def to_case(src, doc_id, ctx_count=None):
    sub = {k: src[k] for k in KEEP if k in src}
    ev, i = [], 1
    agent = src.get("agent", {})
    eh = event_host(src)
    # агент-сборщик и компьютер события - явными полями в начале пакета
    ev.append({"id": "E1", "field": "collector.agent",
               "value": f"{agent.get('name','?')} ({agent.get('id','?')}, {agent.get('ip','?')})"})
    i = 2
    if eh:
        ev.append({"id": f"E{i}", "field": "event.host", "value": eh}); i += 1
    for k, v in flat(sub):
        if k.startswith(SKIP):
            continue
        ev.append({"id": f"E{i}", "field": k, "value": v[:600]}); i += 1
    if ctx_count is not None:
        ev.append({"id": f"E{i}", "field": "context.same_rule_same_agent_pm1h",
                   "value": str(ctx_count)})
    rule = src.get("rule", {})
    return {"case": doc_id, "rule_id": str(rule.get("id", "")),
            "level": int(rule.get("level", 0)), "agent": agent.get("name", "?"),
            "event_host": eh, "evidence": ev, "wazuh_mitre": wazuh_mitre(rule)}
