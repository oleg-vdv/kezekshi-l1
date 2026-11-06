# coding: utf-8
"""Рабочее место аналитика SOC: очередь тикетов L1 -> L2 как список задач.

L1-триаж (run.py) кладёт в out/l2_queue.jsonl всё, что требует человека, с
готовой карточкой. Этот инструмент даёт дежурному разобрать очередь:

  python analyst.py list                     # открытые тикеты (что ждёт разбора)
  python analyst.py show <id>                # полная карточка одного тикета
  python analyst.py close <id> <вердикт> [-n "почему"] [-m T1110.001]
                                             # закрыть тикет с диспозицией дежурного

Вердикт (true_verdict) - один из четырёх классов:
  false_positive        сработка ошибочна/штатная работа (события по сути нет)
  benign_true_positive  событие реальное, но легитимное (админ, обновление, заявка)
  suspicious            возможная атака без подтверждённого успеха
  incident_candidate    подтверждённый успех / воздействие / компрометация

Диспозиция пишется в out/dispositions.csv (тот же формат, что
disposition_review.csv) - это и журнал разбора, и эталон дежурного для
дообучения следующей версии модели. Сам Wazuh инструмент не трогает (read-only).
"""
import argparse, csv, json, os, sys
from datetime import datetime, timezone

try:
    sys.stdout.reconfigure(encoding="utf-8")       # чтобы кириллица не билась в консоли Windows
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.environ.get("KEZEKSHI_OUT", os.path.join(HERE, "out"))
QUEUE = os.path.join(OUT, "l2_queue.jsonl")
AUDIT = os.path.join(OUT, "audit.jsonl")
DISPO = os.path.join(OUT, "dispositions.csv")
VERDICTS = ["false_positive", "benign_true_positive", "suspicious", "incident_candidate"]
COLS = ["closed_at", "analyst", "alert_id", "rule", "level", "host", "суть",
        "вердикт_модели", "памятка", "true_verdict", "note", "mitre"]


def _read_jsonl(path):
    rows = []
    if not os.path.exists(path):
        return rows
    for ln in open(path, encoding="utf-8"):
        ln = ln.strip()
        if ln:
            try:
                rows.append(json.loads(ln))
            except ValueError:
                pass                               # битый хвост строки не роняет разбор
    return rows


def _closed_ids():
    ids = set()
    if os.path.exists(DISPO):
        with open(DISPO, encoding="utf-8-sig", newline="") as f:
            for r in csv.DictReader(f, delimiter=";"):
                ids.add(r.get("alert_id", ""))
    return ids


def _audit_index():
    """case -> последняя запись аудита: уровень и вердикт памятки."""
    idx = {}
    for r in _read_jsonl(AUDIT):
        idx[r.get("case")] = r
    return idx


def _pending():
    closed = _closed_ids()
    seen, out = set(), []
    for q in _read_jsonl(QUEUE):                    # последняя карточка по кейсу побеждает
        out.append(q)
    uniq = {}
    for q in out:
        uniq[q["case"]] = q
    return [q for cid, q in uniq.items() if cid not in closed and cid not in seen]


def _match(cid_prefix, items):
    exact = [q for q in items if q["case"] == cid_prefix]
    if exact:
        return exact[0]
    pre = [q for q in items if q["case"].startswith(cid_prefix)]
    if len(pre) == 1:
        return pre[0]
    if len(pre) > 1:
        print(f"неоднозначный id '{cid_prefix}': подходит {len(pre)} тикетов, уточните", file=sys.stderr)
    return None


def _age(ts):
    try:
        t = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        d = datetime.now(timezone.utc) - t
        m = int(d.total_seconds() // 60)
        return f"{m}м" if m < 90 else f"{m//60}ч"
    except Exception:
        return "?"


def cmd_list(args):
    items = sorted(_pending(), key=lambda q: q.get("ts", ""))
    if not items:
        print("Очередь пуста: открытых тикетов нет.")
        return
    print(f"Открытых тикетов: {len(items)}\n")
    print(f"{'ID':<14} {'правило':>7} {'возраст':>7}  {'вердикт модели':<20} хост / суть")
    print("-" * 100)
    for q in items:
        c = q.get("card") or {}
        summ = (c.get("summary") or "").replace("\n", " ")[:46]
        print(f"{q['case'][:14]:<14} {str(q['rule_id']):>7} {_age(q.get('ts','')):>7}  "
              f"{(c.get('verdict') or '?'):<20} {(q.get('event_host') or q.get('agent') or '?')[:18]} | {summ}")
    print("\nРазобрать:  python analyst.py show <ID>   |   закрыть:  python analyst.py close <ID> <вердикт> -n \"причина\"")


def cmd_show(args):
    q = _match(args.id, _pending())
    if not q:
        print("Тикет не найден среди открытых (возможно уже закрыт).")
        return
    print(q.get("card_md") or json.dumps(q.get("card"), ensure_ascii=False, indent=2))
    ai = _audit_index().get(q["case"], {})
    print(f"\n[служебное] уровень={ai.get('level','?')} памятка={ai.get('rule_verdict','?')} "
          f"валидатор={ai.get('errors') or 'ok'}")
    print(f"Закрыть: python analyst.py close {q['case'][:14]} <{'|'.join(VERDICTS)}> -n \"причина\"")


def cmd_close(args):
    if args.verdict not in VERDICTS:
        print(f"Неизвестный вердикт '{args.verdict}'. Допустимо: {', '.join(VERDICTS)}", file=sys.stderr)
        sys.exit(2)
    q = _match(args.id, _pending())
    if not q:
        print("Тикет не найден среди открытых.", file=sys.stderr)
        sys.exit(1)
    c = q.get("card") or {}
    ai = _audit_index().get(q["case"], {})
    row = {"closed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "analyst": args.analyst or os.environ.get("ANALYST") or os.environ.get("USERNAME", "l2"),
           "alert_id": q["case"], "rule": q["rule_id"], "level": ai.get("level", ""),
           "host": q.get("event_host") or q.get("agent") or "",
           "суть": (c.get("summary") or "").replace("\n", " ")[:300],
           "вердикт_модели": c.get("verdict", ""), "памятка": ai.get("rule_verdict", ""),
           "true_verdict": args.verdict, "note": args.note or "",
           "mitre": args.mitre or ",".join(c.get("mitre", []))}
    new = not os.path.exists(DISPO)
    with open(DISPO, "a", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLS, delimiter=";")
        if new:
            w.writeheader()
        w.writerow(row)
    verdict_ru = {"false_positive": "ложное срабатывание", "benign_true_positive": "легитимно",
                  "suspicious": "подозрительно", "incident_candidate": "ИНЦИДЕНТ"}[args.verdict]
    print(f"Тикет {q['case'][:14]} закрыт как: {args.verdict} ({verdict_ru}). Диспозиция записана в {os.path.relpath(DISPO)}.")
    if args.verdict == "incident_candidate":
        print("  -> это подтверждённый инцидент: заводите реагирование по регламенту (IR), это вне ответственности L1-триажа.")


def main():
    ap = argparse.ArgumentParser(description="Рабочее место аналитика: очередь тикетов L1 -> L2.")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("list", help="открытые тикеты")
    s = sub.add_parser("show", help="полная карточка тикета"); s.add_argument("id")
    c = sub.add_parser("close", help="закрыть тикет с диспозицией")
    c.add_argument("id"); c.add_argument("verdict"); c.add_argument("-n", "--note", default="")
    c.add_argument("-m", "--mitre", default=""); c.add_argument("-a", "--analyst", default="")
    a = ap.parse_args()
    {"list": cmd_list, "show": cmd_show, "close": cmd_close}.get(a.cmd, lambda _: ap.print_help())(a)


if __name__ == "__main__":
    main()
