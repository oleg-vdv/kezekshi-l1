# coding: utf-8
"""Наглядный дашборд работы L1-триажа из журнала аудита и очереди L2.

Самодостаточный HTML (без внешних зависимостей, открывается офлайн) для показа:
сколько алертов разобрано, что L1 закрыл сам, что ушло аналитику и с какими
карточками. Данные берутся локально из out/, сам Wazuh не трогает.

  python dashboard.py [путь.html]
  KEZEKSHI_OUT=<каталог>  - откуда читать audit.jsonl / l2_queue.jsonl
"""
import csv, html, json, os, sys
from collections import Counter
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.environ.get("KEZEKSHI_OUT", os.path.join(HERE, "out"))
AUDIT = os.path.join(OUT, "audit.jsonl")
QUEUE = os.path.join(OUT, "l2_queue.jsonl")
DISPO = os.path.join(OUT, "dispositions.csv")
AVG_S = 10.3                                        # средняя длительность вызова модели, с

VERDICT_RU = {"false_positive": "ложное срабатывание", "benign_true_positive": "легитимно",
              "suspicious": "подозрительно", "incident_candidate": "инцидент", "": "нет ответа"}
VERDICT_CLASS = {"false_positive": "ok", "benign_true_positive": "ok",
                 "suspicious": "warn", "incident_candidate": "crit", "": "muted"}


def read_jsonl(path):
    rows = []
    if os.path.exists(path):
        for ln in open(path, encoding="utf-8"):
            ln = ln.strip()
            if ln:
                try:
                    rows.append(json.loads(ln))
                except ValueError:
                    pass
    return rows


def closed_ids():
    ids = set()
    if os.path.exists(DISPO):
        with open(DISPO, encoding="utf-8-sig", newline="") as f:
            for r in csv.DictReader(f, delimiter=";"):
                ids.add(r.get("alert_id", ""))
    return ids


def esc(s):
    return html.escape(str(s or ""))


def main():
    dest = sys.argv[1] if len(sys.argv) > 1 else os.path.join(OUT, "dashboard.html")
    audit = read_jsonl(AUDIT)
    total = len(audit)
    ac = sum(1 for r in audit if r.get("action") == "auto_close")
    l2 = sum(1 for r in audit if r.get("action") == "to_L2")
    used = sum(1 for r in audit if r.get("model_used"))
    saved = total - used
    saved_min = round(saved * AVG_S / 60)
    pct_auto = round(100 * ac / total) if total else 0

    noise = Counter(str(r["rule_id"]) for r in audit
                    if r.get("action") == "auto_close" and not r.get("model_used"))
    hosts = Counter((r.get("event_host") or r.get("agent") or "?") for r in audit)

    # очередь: последняя карточка по кейсу, без уже закрытых
    done = closed_ids()
    uniq = {}
    for q in read_jsonl(QUEUE):
        uniq[q["case"]] = q
    tickets = [q for cid, q in uniq.items() if cid not in done]
    incidents = sum(1 for q in tickets if (q.get("card") or {}).get("verdict") == "incident_candidate")

    # период наблюдения из штампов аудита
    ts = sorted(r.get("ts", "") for r in audit if r.get("ts"))
    window = ""
    if ts:
        def hm(x):
            try:
                return datetime.fromisoformat(x.replace("Z", "+00:00")).strftime("%H:%M")
            except Exception:
                return x[:16]
        d0 = ts[0][:10]
        window = f"{d0}, {hm(ts[0])}–{hm(ts[-1])} UTC"

    noise_rows = "".join(
        f'<li><span class="rid">{esc(r)}</span><span class="bar" style="--w:{int(100*c/max(noise.values()))}%"></span>'
        f'<span class="n">{c}</span></li>' for r, c in noise.most_common(8))
    host_rows = "".join(
        f'<li><span class="h">{esc(h)}</span><span class="bar alt" style="--w:{int(100*c/max(hosts.values()))}%"></span>'
        f'<span class="n">{c}</span></li>' for h, c in hosts.most_common(6))

    def ticket_card(q):
        c = q.get("card") or {}
        v = c.get("verdict") or ""
        cls = VERDICT_CLASS.get(v, "muted")
        mitre = " ".join(esc(m) for m in c.get("mitre", []))
        steps = c.get("next_steps") or []
        step = esc(steps[0]) if steps else ""
        return f'''<article class="tk {cls}">
      <header><span class="chip {cls}">{esc(VERDICT_RU.get(v, v))}</span>
        <span class="rid">rule {esc(q.get("rule_id"))}</span>
        <span class="host">{esc(q.get("event_host") or q.get("agent"))}</span>
        {f'<span class="mitre">{mitre}</span>' if mitre else ''}</header>
      <p class="sum">{esc((c.get("summary") or "ответ модели не прошёл валидатор, нужен ручной разбор")[:240])}</p>
      {f'<p class="next">следующий шаг: {step}</p>' if step else ''}</article>'''

    tickets_html = "".join(ticket_card(q) for q in sorted(
        tickets, key=lambda q: {"crit": 0, "warn": 1}.get(
            VERDICT_CLASS.get((q.get("card") or {}).get("verdict") or "", "z"), 2)))

    sig = l2
    noise_seg = ac
    tot_seg = max(sig + noise_seg, 1)
    gen = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    htmlout = f'''<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>kezekshi-l1 · триаж</title>
<style>
:root{{
  --bg:#0E1620; --panel:#16212E; --panel2:#1B2838; --line:#243445;
  --ink:#D7E0EA; --mut:#8092A3; --ok:#3FB68B; --warn:#E0A43B; --crit:#E5575B;
  --mono:ui-monospace,"Cascadia Code",Consolas,monospace;
  --sans:ui-sans-serif,"Segoe UI",system-ui,sans-serif;
}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);
  line-height:1.5;-webkit-font-smoothing:antialiased;padding:28px 20px 48px}}
.wrap{{max-width:980px;margin:0 auto}}
.top{{display:flex;justify-content:space-between;align-items:baseline;gap:16px;
  border-bottom:1px solid var(--line);padding-bottom:14px;flex-wrap:wrap}}
.brand{{font-weight:600;letter-spacing:-.01em;font-size:19px}}
.brand span{{color:var(--mut);font-weight:400}}
.state{{display:flex;gap:16px;align-items:center;color:var(--mut);font-size:13px}}
.dot{{width:8px;height:8px;border-radius:50%;background:var(--ok);display:inline-block;
  margin-right:6px;box-shadow:0 0 0 0 rgba(63,182,139,.6);animation:p 2.6s infinite}}
@keyframes p{{0%{{box-shadow:0 0 0 0 rgba(63,182,139,.5)}}70%{{box-shadow:0 0 0 7px rgba(63,182,139,0)}}}}
@media (prefers-reduced-motion:reduce){{.dot{{animation:none}}}}

.hero{{margin:26px 0 8px}}
.hero h1{{font-size:15px;font-weight:500;color:var(--mut);margin:0 0 14px}}
.split{{display:flex;height:64px;border-radius:7px;overflow:hidden;background:var(--panel)}}
.split .seg{{display:flex;flex-direction:column;justify-content:center;padding:0 18px;min-width:0}}
.split .noise{{background:linear-gradient(180deg,#223a33,#1c3129);flex:var(--noise)}}
.split .sig{{background:linear-gradient(180deg,#3a2a24,#30231e);flex:var(--sig)}}
.split .big{{font-size:27px;font-weight:600;letter-spacing:-.02em;line-height:1}}
.split .lab{{font-size:12.5px;color:var(--mut);margin-top:5px;white-space:nowrap;
  overflow:hidden;text-overflow:ellipsis}}
.noise .big{{color:var(--ok)}} .sig .big{{color:var(--warn)}}

.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--line);
  border:1px solid var(--line);border-radius:7px;overflow:hidden;margin:18px 0 30px}}
.stats div{{background:var(--panel);padding:16px 16px}}
.stats .v{{font-size:23px;font-weight:600;letter-spacing:-.02em}}
.stats .k{{font-size:12.5px;color:var(--mut);margin-top:4px}}
.stats .v.crit{{color:var(--crit)}}

h2{{font-size:14px;font-weight:600;margin:0 0 14px;color:var(--ink)}}
h2 b{{color:var(--mut);font-weight:400}}

.tk{{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--mut);
  border-radius:0 6px 6px 0;padding:13px 16px;margin-bottom:9px}}
.tk.warn{{border-left-color:var(--warn)}} .tk.crit{{border-left-color:var(--crit)}}
.tk.ok{{border-left-color:var(--ok)}}
.tk header{{display:flex;gap:11px;align-items:center;flex-wrap:wrap;font-size:13px}}
.chip{{font-size:11.5px;padding:2px 9px;border-radius:999px;font-weight:600;
  background:#2a3a33;color:var(--ok)}}
.chip.warn{{background:#3b3020;color:var(--warn)}} .chip.crit{{background:#3b2224;color:var(--crit)}}
.chip.muted{{background:#28313d;color:var(--mut)}}
.rid{{font-family:var(--mono);color:var(--mut);font-size:12.5px}}
.host{{font-family:var(--mono);font-size:12.5px;color:var(--ink)}}
.mitre{{font-family:var(--mono);font-size:11.5px;color:var(--warn);margin-left:auto}}
.sum{{margin:9px 0 0;font-size:14px}}
.next{{margin:6px 0 0;font-size:12.5px;color:var(--mut)}}

.cols{{display:grid;grid-template-columns:1fr 1fr;gap:26px;margin-top:34px}}
.panel{{background:var(--panel);border:1px solid var(--line);border-radius:7px;padding:16px 18px}}
.panel ul{{list-style:none;margin:0;padding:0}}
.panel li{{display:flex;align-items:center;gap:10px;padding:6px 0;font-size:13px}}
.panel .rid,.panel .h{{width:92px;flex:none}} .panel .h{{font-family:var(--mono);font-size:12.5px}}
.panel .bar{{height:7px;border-radius:4px;background:var(--ok);width:var(--w);flex:none;
  min-width:3px;opacity:.75}}
.panel .bar.alt{{background:#4a6f8c}}
.panel .n{{margin-left:auto;color:var(--mut);font-variant-numeric:tabular-nums}}

.flow{{margin-top:34px;border-top:1px solid var(--line);padding-top:18px;color:var(--mut);font-size:13px}}
.flow code{{font-family:var(--mono);color:var(--ink);background:var(--panel2);padding:2px 7px;border-radius:4px}}
.flow .arrow{{color:var(--line);margin:0 7px}}
.note{{margin-top:12px;font-size:12.5px;color:var(--mut)}}
.note b{{color:var(--ok);font-weight:600}}
.foot{{margin-top:22px;color:var(--line);font-size:11.5px}}
@media(max-width:680px){{.stats{{grid-template-columns:repeat(2,1fr)}}.cols{{grid-template-columns:1fr}}
  .split{{height:auto;flex-direction:column}}.mitre{{margin-left:0}}}}
</style></head><body><div class="wrap">

<div class="top">
  <div class="brand">kezekshi&#8209;l1 <span>· локальный L1&#8209;триаж SOC</span></div>
  <div class="state"><span><span class="dot"></span>служба активна</span>
    <span>{esc(window)}</span></div>
</div>

<div class="hero">
  <h1>Из потока алертов система сама отсеивает шум, аналитику остаётся значимое</h1>
  <div class="split">
    <div class="seg noise" style="--noise:{noise_seg}"><div class="big">{pct_auto}%</div>
      <div class="lab">закрыто автоматически · {noise_seg} шумовых</div></div>
    <div class="seg sig" style="--sig:{max(sig,0)}"><div class="big">{l2}</div>
      <div class="lab">аналитику на разбор</div></div>
  </div>
</div>

<div class="stats">
  <div><div class="v">{total}</div><div class="k">алертов разобрано</div></div>
  <div><div class="v">{used}</div><div class="k">вызовов модели · {saved} без неё</div></div>
  <div><div class="v">~{saved_min}&#8201;мин</div><div class="k">сэкономлено времени модели</div></div>
  <div><div class="v {'crit' if incidents else ''}">{incidents}</div><div class="k">инцидентов</div></div>
</div>

<h2>Очередь аналитика <b>— {len(tickets)} тикетов с карточкой модели</b></h2>
{tickets_html or '<p style="color:var(--mut)">Очередь пуста.</p>'}

<div class="cols">
  <div class="panel"><h2>Закрыто само <b>— топ шумовых правил</b></h2><ul>{noise_rows}</ul></div>
  <div class="panel"><h2>Узлы <b>— откуда поток</b></h2><ul>{host_rows}</ul></div>
</div>

<div class="flow">
  <code>Wazuh</code><span class="arrow">&#8594;</span>
  <code>памятка: шум закрыт</code><span class="arrow">&#8594;</span>
  <code>модель: карточка</code><span class="arrow">&#8594;</span>
  <code>аналитик</code>
  <div class="note">Режим <b>Фаза 2 (ассист)</b>: сам закрывается только детерминированный шум;
    всё, что дошло до модели, идёт человеку с разбором. Инцидент не закрывается автоматически.</div>
</div>

<div class="foot">kezekshi-l1-v5.1 · Gemma 4 E2B, офлайн · сгенерировано {gen} · Wazuh только на чтение</div>
</div></body></html>'''

    with open(dest, "w", encoding="utf-8") as f:
        f.write(htmlout)
    print(f"дашборд: {dest} ({total} алертов, {l2} на L2, {len(tickets)} в очереди)")


if __name__ == "__main__":
    main()
