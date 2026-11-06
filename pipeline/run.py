# coding: utf-8
"""Офлайн-сервис L1-триажа поверх Wazuh.

Поток: алерт Wazuh (read-only) -> нормализация -> детерминированный предфильтр
-> модель (Ollama, локально) -> валидатор ответа -> консервативная маршрутизация
-> очередь L2 + журнал аудита. В Wazuh ничего не пишется.

Режимы:
  python run.py --dry-run samples/wazuh_alerts.sample.jsonl   # без сети, по файлу
  python run.py --once         # один проход по новым алертам Wazuh
  python run.py --interval 30  # сервис-демон: опрос каждые 30 с
  python run.py --stats        # сводка по всему журналу: что сделала L1
  python run.py --report        # суточный отчёт из аудита (today/yesterday/ГГГГ-ММ-ДД)

Триаж двухуровневый: детерминированный fast-path решает исход, не зависящий от
модели (инъекция/операционный шум по памятке - ~98% реального потока стенда), а
модель вызывается только на неоднозначном хвосте.

Демон-режим боеготов: дедуп по _id с границей по времени (не теряет и не
повторяет алерты на одинаковых штампах), атомарный state + чекпоинт на каждый
алерт (рестарт продолжает ровно с места остановки), мягкая остановка по сигналу,
выборка страницами под всплеск. Падение Ollama не стопорит поток: ~98% алертов
идут fast-path мимо модели, остальное уходит на L2 по предохранителю.

Настройки через окружение: MODEL (по умолч. kezekshi-l1-v6), KEZEKSHI_THINK=0/1,
KEZEKSHI_HINT=0/1, TRIAGE_TIMEOUT (потолок запроса к модели, с; по умолч. 120),
OLLAMA_URL, WAZUH_INDEXER_HOST (+ ~/.kezekshi/wazuh.env).
"""
import argparse, json, os, signal, sys, time
from datetime import datetime, timezone, timedelta

SRC = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, SRC)

_STOP = False  # мягкая остановка по сигналу: сервис доделывает текущий алерт и выходит


def _request_stop(*_):
    global _STOP
    _STOP = True

MODEL = os.environ.get("MODEL", "kezekshi-l1-v6")
# предфильтр-памятка и режим размышления настраиваются ДО импорта triage
os.environ.setdefault("TRIAGE_HINT", os.environ.get("KEZEKSHI_HINT", "1"))
os.environ.setdefault("TRIAGE_THINK", "1" if os.environ.get("KEZEKSHI_THINK", "1") == "1" else "0")

import triage  # noqa: E402  (читает TRIAGE_HINT/TRIAGE_THINK при импорте)
import normalize  # noqa: E402
import policy  # noqa: E402

if os.environ.get("OLLAMA_URL"):
    triage.OLLAMA = os.environ["OLLAMA_URL"]

OUT = os.path.join(os.path.dirname(__file__), "out")
Q_PATH = os.path.join(OUT, "l2_queue.jsonl")
AUDIT_PATH = os.path.join(OUT, "audit.jsonl")
STATE_PATH = os.path.join(OUT, "state.json")
PAGE = int(os.environ.get("KEZEKSHI_PAGE", "500"))      # размер страницы выборки Wazuh
MAX_PER_PASS = int(os.environ.get("KEZEKSHI_MAX_PASS", "5000"))  # потолок алертов за один проход


def _append(path, rec):
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        f.flush(); os.fsync(f.fileno())         # запись переживает падение процесса


def _read_jsonl(path):
    """Строки журнала; битый хвост (обрыв при падении) пропускается, не роняет чтение."""
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if not ln:
                continue
            try:
                yield json.loads(ln)
            except ValueError:
                continue


def format_card(case, ans, dec):
    """Короткая карточка для L2 из ответа модели и полей алерта."""
    a = ans or {}
    lines = [f"# Карточка L1 -> L2  (алерт {case['case']}, правило {case['rule_id']}, уровень {case['level']})",
             f"Агент-сборщик: {case['agent']}   Компьютер события: {case['event_host'] or '?'}",
             f"Вердикт модели: {a.get('verdict','?')}   Памятка: {dec['rule_verdict']}",
             f"Причина маршрутизации: {dec['reason']}", "",
             f"Суть: {a.get('summary','')}", "", "Утверждения:"]
    for c in a.get("claims", []):
        lines.append(f"  - {c.get('text','')} [{', '.join(c.get('evidence', []))}]")
    lines.append("MITRE: " + (", ".join(a.get("mitre", [])) or "нет"))
    lines.append("Не хватает: " + ("; ".join(a.get("missing", [])) or "-"))
    lines.append("Проверить: " + ("; ".join(a.get("next_steps", [])) or "; ".join(dec.get("rule_checks", [])) or "-"))
    return "\n".join(lines)


def process(case):
    """Один алерт. Двухуровневый триаж: сперва детерминированный fast-path
    (исход не зависит от модели - инъекция/операционный шум), и только
    неоднозначный хвост уходит в модель. Возвращает (dec, ans)."""
    flags = triage.prerules(case)
    ev = {e["field"]: e["value"] for e in case["evidence"]}
    dec = policy.fast_decide(case, flags, ev)
    if dec is not None:                         # решено без модели (~95% потока)
        ans, perf, errs = {}, {"wall_s": 0.0}, []
    else:
        try:
            ans, perf = triage.ask(MODEL, case)
        except Exception as e:
            ans, perf = {}, {"wall_s": None, "error": type(e).__name__}
        errs = triage.validate(case, ans) if ans else ["no answer"]
        dec = policy.decide(case, ans, errs, flags)
    rec = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "case": case["case"], "rule_id": case["rule_id"], "level": case["level"],
           "agent": case["agent"], "event_host": case["event_host"],
           "action": dec["action"], "model_verdict": dec.get("model_verdict"),
           "rule_verdict": dec.get("rule_verdict"), "reason": dec["reason"],
           "model_used": dec.get("model_used", True),
           "flags": flags, "errors": errs, "wall_s": perf.get("wall_s"), "card": ans}
    _append(AUDIT_PATH, rec)                    # аудит: каждое решение, с тем что видела модель
    if dec["action"] == "to_L2":
        _append(Q_PATH, {"ts": rec["ts"], "case": case["case"], "rule_id": case["rule_id"],
                         "agent": case["agent"], "event_host": case["event_host"],
                         "level": case["level"], "evidence": case["evidence"],
                         "rule_verdict": dec.get("rule_verdict"), "rule_checks": dec.get("rule_checks"),
                         "card_md": format_card(case, ans, dec), "card": ans})
    return dec, ans


def iter_dry(path):
    for ln in open(path, encoding="utf-8"):
        ln = ln.strip()
        if not ln:
            continue
        doc = json.loads(ln)
        src = doc.get("_source", doc)
        yield normalize.to_case(src, doc.get("_id", src.get("id", "dry-" + str(abs(hash(ln)) % 10**8))))


def iter_wazuh(since, seen):
    """Новые алерты Wazuh начиная с `since` (ISO, включительно), с дедупом по _id.

    Граница по времени берётся `gte`, а не `gt`: иначе алерт с тем же штампом, что
    и последний обработанный, потерялся бы. От повторной обработки на границе
    спасает `seen` - множество уже разобранных _id на штампе `since`. Выборка
    страницами (`PAGE`): под всплеском проход не ограничен одной страницей.
    Только чтение: _search + _count."""
    from wz import q
    seen = set(seen)
    cur = since
    yielded = 0
    while yielded < MAX_PER_PASS and not _STOP:
        body = {"size": PAGE, "sort": [{"timestamp": "asc"}],
                "query": {"range": {"timestamp": {"gte": cur}}}}
        hits = q("/wazuh-alerts-*/_search", body)["hits"]["hits"]
        new = [h for h in hits if h["_id"] not in seen]
        for h in new:
            s = h["_source"]
            ctx = q("/wazuh-alerts-*/_count", {"query": {"bool": {"filter": [
                {"term": {"rule.id": str(s.get("rule", {}).get("id", ""))}},
                {"term": {"agent.name": s.get("agent", {}).get("name", "")}},
                {"range": {"timestamp": {"gte": s["timestamp"] + "||-1h", "lte": s["timestamp"] + "||+1h"}}}]}}})["count"]
            yield h["_id"], normalize.to_case(s, h["_id"], ctx), s["timestamp"]
            seen.add(h["_id"]); cur = s["timestamp"]; yielded += 1
            if yielded >= MAX_PER_PASS or _STOP:
                return
        if len(hits) < PAGE:        # дошли до конца потока
            return
        if not new:                 # вся страница уже разобрана - сдвигаемся вперёд
            cur = hits[-1]["_source"]["timestamp"]


def load_state():
    try:
        st = json.load(open(STATE_PATH, encoding="utf-8"))
        st.setdefault("seen", [])
        return st
    except (OSError, ValueError):
        return {"since": datetime.now(timezone.utc).isoformat(timespec="seconds"), "seen": []}


def save_state(st):
    """Атомарно: запись во временный файл + replace, чтобы падение в середине
    записи не оставило битый state.json (иначе сервис потерял бы место остановки)."""
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(st, f, ensure_ascii=False)
        f.flush(); os.fsync(f.fileno())
    os.replace(tmp, STATE_PATH)


def run_once():
    st = load_state()
    max_ts = st["since"]
    boundary = set(st.get("seen", []))          # _id, уже разобранные на max_ts
    n = ac = l2 = mc = 0
    for aid, case, ts in iter_wazuh(max_ts, boundary):
        dec, _ = process(case)                  # аудит пишется внутри process (fsync)
        n += 1; ac += dec["action"] == "auto_close"; l2 += dec["action"] == "to_L2"
        mc += dec.get("model_used", True)
        if ts > max_ts:                         # новый штамп - граница сдвинулась
            max_ts = ts; boundary = {aid}
        else:                                   # тот же штамп, что и граница
            boundary.add(aid)
        st["since"] = max_ts; st["seen"] = list(boundary)
        save_state(st)                          # чекпоинт на каждый алерт: рестарт без потерь и повторов
        if _STOP:
            break
    saved = f", модель вызвана {mc} ({100*mc//n if n else 0}%)" if n else ""
    print(f"обработано {n}: авто-закрыто {ac}, на L2 {l2}{saved}", flush=True)
    return n


def stats():
    """Сводка по всему журналу аудита: что сделала L1, на чём сэкономлен вызов модели."""
    import collections
    n = ac = l2 = mc = 0
    by_rule = collections.Counter()
    walls = []
    for r in _read_jsonl(AUDIT_PATH):
        n += 1
        ac += r["action"] == "auto_close"; l2 += r["action"] == "to_L2"
        used = r.get("model_used", True); mc += used
        if not used:
            by_rule[str(r["rule_id"])] += 1
        if used and isinstance(r.get("wall_s"), (int, float)):
            walls.append(r["wall_s"])
    if not n:
        print("журнал пуст, сначала прогоните run.py", flush=True); return
    avg = sum(walls) / len(walls) if walls else 0
    print(f"Всего разобрано: {n}")
    print(f"  авто-закрыто (L1 закрыл сам): {ac} ({100*ac//n}%)")
    print(f"  на L2 (человеку):            {l2} ({100*l2//n}%)")
    print(f"Модель вызвана: {mc} ({100*mc//n}%); без модели (fast-path): {n-mc} ({100*(n-mc)//n}%)")
    if walls:
        print(f"Среднее время вызова модели: {avg:.1f} с; сэкономлено вызовов: {n-mc}"
              f" (~{(n-mc)*avg/60:.0f} мин модельного времени)")
    print("Топ правил, закрытых без модели:")
    for rid, cnt in by_rule.most_common(10):
        print(f"  правило {rid:>8}  {cnt:>6}")


def report(day=None):
    """Читаемый суточный отчёт из аудита за один день (UTC).

    day: 'YYYY-MM-DD', 'today', 'yesterday' или None (= сегодня). Отчёт печатается
    и сохраняется в out/report-YYYY-MM-DD.txt для архива."""
    import collections
    today = datetime.now(timezone.utc).date()
    if day in (None, "today"):
        d = today
    elif day == "yesterday":
        d = today - timedelta(days=1)
    else:
        try:
            d = datetime.strptime(day, "%Y-%m-%d").date()
        except ValueError:
            print(f"не понял дату '{day}', нужен формат ГГГГ-ММ-ДД", flush=True); return
    pref = d.isoformat()

    recs = [r for r in _read_jsonl(AUDIT_PATH) if str(r.get("ts", "")).startswith(pref)]
    L = []  # строки отчёта
    L.append(f"=== Суточный отчёт L1-триажа за {pref} (UTC) ===")
    if not recs:
        L.append("За эти сутки записей в журнале нет.")
        out = "\n".join(L); print(out, flush=True); return
    n = len(recs)
    ac = sum(r["action"] == "auto_close" for r in recs)
    l2 = sum(r["action"] == "to_L2" for r in recs)
    mc = sum(r.get("model_used", True) for r in recs)
    walls = [r["wall_s"] for r in recs if r.get("model_used", True) and isinstance(r.get("wall_s"), (int, float))]
    avg = sum(walls) / len(walls) if walls else 0.0
    L.append(f"Разобрано алертов: {n}")
    L.append(f"  закрыл сам (L1):   {ac:>5} ({100*ac//n}%)")
    L.append(f"  передал на L2:     {l2:>5} ({100*l2//n}%)")
    L.append(f"Модель вызвана: {mc} ({100*mc//n}%); без модели: {n-mc} ({100*(n-mc)//n}%).")
    if avg:
        L.append(f"Экономия: {n-mc} алертов без вызова модели (~{(n-mc)*avg/60:.0f} мин модельного времени "
                 f"при средней {avg:.1f} с/вызов).")

    noise = collections.Counter(str(r["rule_id"]) for r in recs if not r.get("model_used", True))
    if noise:
        L.append("\nТоп шумовых правил, закрытых без модели:")
        for rid, cnt in noise.most_common(8):
            L.append(f"  правило {rid:>8}  {cnt:>5}")

    l2recs = [r for r in recs if r["action"] == "to_L2"]
    if l2recs:
        L.append(f"\nНа L2 ждут разбора ({len(l2recs)}):")
        inj = sum("injection" in (r.get("flags") or []) for r in l2recs)
        vf = sum(bool(r.get("errors")) and "injection" not in (r.get("flags") or []) for r in l2recs)
        esc = len(l2recs) - inj - vf
        L.append(f"  эскалаций модели: {esc}; инъекций: {inj}; не прошли валидатор: {vf}")
        for r in l2recs[:20]:
            host = r.get("event_host") or r.get("agent") or "?"
            mv = r.get("model_verdict") or "-"
            L.append(f"  - правило {r['rule_id']} ур.{r['level']} | {host} | модель: {mv} | {str(r.get('reason',''))[:70]}")
        if len(l2recs) > 20:
            L.append(f"  ... и ещё {len(l2recs)-20}")
    else:
        L.append("\nНа L2 ничего не передано: весь поток за сутки - шум, закрытый L1.")

    hosts = collections.Counter((r.get("event_host") or r.get("agent") or "?") for r in recs)
    L.append("\nСамые шумные узлы:")
    for h, cnt in hosts.most_common(5):
        L.append(f"  {h:<28} {cnt:>5}")

    out = "\n".join(L)
    print(out, flush=True)
    try:
        path = os.path.join(OUT, f"report-{pref}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(out + "\n")
        print(f"\n(сохранено: {path})", flush=True)
    except OSError:
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", metavar="FILE", help="обработать алерты из файла, без сети Wazuh")
    ap.add_argument("--once", action="store_true", help="один проход по новым алертам Wazuh")
    ap.add_argument("--interval", type=int, default=0, help="сервис: опрос Wazuh каждые N секунд")
    ap.add_argument("--stats", action="store_true", help="сводка по всему журналу аудита")
    ap.add_argument("--report", nargs="?", const="today", metavar="ДЕНЬ",
                    help="суточный отчёт из аудита: today/yesterday/ГГГГ-ММ-ДД (по умолч. today)")
    args = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)
    if args.stats:
        stats()
        return
    if args.report:
        report(args.report)
        return
    print(f"модель={MODEL} think={os.environ['TRIAGE_THINK']} hint={os.environ['TRIAGE_HINT']} ollama={triage.OLLAMA}", flush=True)

    if args.dry_run:
        n = ac = l2 = mc = 0
        for case in iter_dry(args.dry_run):
            dec, ans = process(case)
            n += 1; ac += dec["action"] == "auto_close"; l2 += dec["action"] == "to_L2"
            mc += dec.get("model_used", True)
            tag = "модель" if dec.get("model_used", True) else "fast"
            print(f"  {case['case']} rule={case['rule_id']} lvl={case['level']} "
                  f"[{tag}] model={dec.get('model_verdict')} rule={dec['rule_verdict']} -> {dec['action']}", flush=True)
        print(f"dry-run: {n} алертов, авто-закрыто {ac}, на L2 {l2}, модель вызвана {mc}. "
              f"Очередь: {Q_PATH}, аудит: {AUDIT_PATH}", flush=True)
        return
    if args.interval:
        for s in (signal.SIGINT, getattr(signal, "SIGTERM", None), getattr(signal, "SIGBREAK", None)):
            if s is not None:
                try:
                    signal.signal(s, _request_stop)
                except (ValueError, OSError):
                    pass                        # не главный поток/не поддерживается - полагаемся на KeyboardInterrupt
        print(f"сервис запущен, опрос каждые {args.interval} с (Ctrl+C - мягкая остановка)", flush=True)
        while not _STOP:
            try:
                run_once()
            except KeyboardInterrupt:
                _request_stop()
            except Exception as e:
                print(f"ошибка прохода: {type(e).__name__}: {e}", flush=True)
            # прерываемый сон: быстро реагируем на сигнал остановки
            for _ in range(args.interval):
                if _STOP:
                    break
                time.sleep(1)
        print("остановлено, место в потоке сохранено (out/state.json)", flush=True)
    else:
        run_once()


if __name__ == "__main__":
    main()
