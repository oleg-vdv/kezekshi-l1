# coding: utf-8
"""Рабочее место дежурного: живой веб-пульт L1-триажа (локально, без зависимостей).

Поднимает http-сервер на 127.0.0.1:<порт>, читает живой журнал out/ (его пишет
демон run.py) и даёт дежурному:
  - видеть поток в реальном времени (сам обновляется): сколько закрыто, что в очереди;
  - открыть тикет с карточкой модели (вердикт, MITRE, обоснование, что проверить);
  - закрыть тикет вердиктом - запись в out/dispositions.csv (эталон для v6).
Wazuh не трогает. Демон и пульт работают одновременно: демон пишет очередь,
пульт её читает и пишет только диспозиции.

  python console.py [порт]            # по умолчанию 8787
  KEZEKSHI_OUT=<каталог>              # откуда читать журнал
"""
import csv, json, os, sys, html
from collections import Counter
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
import ticket

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.environ.get("KEZEKSHI_OUT", os.path.join(HERE, "out"))
AUDIT = os.path.join(OUT, "audit.jsonl")
QUEUE = os.path.join(OUT, "l2_queue.jsonl")
DISPO = os.path.join(OUT, "dispositions.csv")
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8787
# адрес прослушивания: по умолчанию только localhost (безопасно); для доступа из
# сети SOC задать KEZEKSHI_BIND=0.0.0.0 (пульт без аутентификации - только в доверенном сегменте)
BIND = os.environ.get("KEZEKSHI_BIND", "127.0.0.1")

VERDICTS = ["false_positive", "benign_true_positive", "suspicious", "incident_candidate"]
VERDICT_RU = {"false_positive": "ложное", "benign_true_positive": "легитимно",
              "suspicious": "подозрительно", "incident_candidate": "инцидент", "": "нет ответа"}
CLS = {"false_positive": "ok", "benign_true_positive": "ok",
       "suspicious": "warn", "incident_candidate": "crit", "": "muted"}
COLS = ["closed_at", "analyst", "alert_id", "rule", "level", "host", "суть",
        "вердикт_модели", "памятка", "true_verdict", "note", "mitre"]


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


def audit_index():
    idx = {}
    for r in read_jsonl(AUDIT):
        idx[r.get("case")] = r
    return idx


def _ticket_text(q, a):
    """Структурированный тикет из записи очереди; при отсутствии пакета - старая карточка."""
    if not q.get("evidence"):
        return q.get("card_md") or ""
    rec = dict(q)
    rec.setdefault("level", a.get("level", 0))
    rec.setdefault("rule_verdict", a.get("rule_verdict", ""))
    try:
        return ticket.render(rec)
    except Exception:
        return q.get("card_md") or ""


def state():
    audit = read_jsonl(AUDIT)
    total = len(audit)
    ac = sum(1 for r in audit if r.get("action") == "auto_close")
    l2 = sum(1 for r in audit if r.get("action") == "to_L2")
    used = sum(1 for r in audit if r.get("model_used"))
    noise = Counter(str(r["rule_id"]) for r in audit
                    if r.get("action") == "auto_close" and not r.get("model_used"))
    done = closed_ids()
    uniq = {}
    for q in read_jsonl(QUEUE):
        uniq[q["case"]] = q
    ai = audit_index()
    tickets = []
    for cid, q in uniq.items():
        if cid in done:
            continue
        c = q.get("card") or {}
        v = c.get("verdict") or ""
        a = ai.get(cid, {})
        rv = q.get("rule_verdict") or a.get("rule_verdict", "")
        eff = ticket.eff_verdict(v, rv)             # безопасный максимум модель/памятка
        tickets.append({
            "id": cid, "rule": q.get("rule_id"), "host": q.get("event_host") or q.get("agent") or "?",
            "verdict": eff, "verdict_ru": VERDICT_RU.get(eff, eff), "cls": CLS.get(eff, "muted"),
            "model_verdict": v, "rule_verdict": rv,
            "mitre": c.get("mitre", []), "summary": (c.get("summary") or "")[:300],
            "next": (c.get("next_steps") or [""])[0], "level": a.get("level", ""),
            "card_md": _ticket_text(q, a), "ts": q.get("ts", "")})
    order = {"crit": 0, "warn": 1}
    tickets.sort(key=lambda t: (order.get(t["cls"], 2), t["ts"]))
    return {"total": total, "auto_close": ac, "l2": l2, "model_used": used,
            "saved": total - used, "pct_auto": round(100 * ac / total) if total else 0,
            "noise_top": noise.most_common(6), "closed_today": len(done),
            "tickets": tickets, "updated": datetime.now().strftime("%H:%M:%S")}


def close_ticket(body):
    v = body.get("verdict")
    if v not in VERDICTS:
        return {"ok": False, "error": "bad verdict"}
    uniq = {}
    for q in read_jsonl(QUEUE):
        uniq[q["case"]] = q
    q = uniq.get(body.get("id"))
    if not q:
        return {"ok": False, "error": "ticket not found"}
    c = q.get("card") or {}
    a = audit_index().get(q["case"], {})
    row = {"closed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "analyst": body.get("analyst") or "дежурный", "alert_id": q["case"], "rule": q["rule_id"],
           "level": a.get("level", ""), "host": q.get("event_host") or q.get("agent") or "",
           "суть": (c.get("summary") or "").replace("\n", " ")[:300],
           "вердикт_модели": c.get("verdict", ""), "памятка": a.get("rule_verdict", ""),
           "true_verdict": v, "note": body.get("note", ""), "mitre": ",".join(c.get("mitre", []))}
    new = not os.path.exists(DISPO)
    with open(DISPO, "a", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLS, delimiter=";")
        if new:
            w.writeheader()
        w.writerow(row)
    return {"ok": True}


PAGE = """<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Дежурный · kezekshi-l1</title><style>
:root{--bg:#0E1620;--panel:#16212E;--panel2:#1B2838;--line:#243445;--ink:#D7E0EA;
 --mut:#8092A3;--ok:#3FB68B;--warn:#E0A43B;--crit:#E5575B;
 --mono:ui-monospace,"Cascadia Code",Consolas,monospace;--sans:ui-sans-serif,"Segoe UI",system-ui,sans-serif}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);line-height:1.5}
.top{display:flex;justify-content:space-between;align-items:center;gap:16px;padding:14px 22px;
 border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--bg);z-index:5}
.brand{font-weight:600;font-size:17px;letter-spacing:-.01em}
.brand span{color:var(--mut);font-weight:400}
.live{display:flex;gap:18px;align-items:center;color:var(--mut);font-size:13px}
.dot{width:8px;height:8px;border-radius:50%;background:var(--ok);display:inline-block;margin-right:6px;
 animation:p 2.4s infinite}@keyframes p{0%{box-shadow:0 0 0 0 rgba(63,182,139,.5)}70%{box-shadow:0 0 0 7px rgba(63,182,139,0)}}
.stats{display:flex;gap:1px;background:var(--line);border-bottom:1px solid var(--line)}
.stats div{background:var(--panel);padding:12px 22px;flex:1}
.stats .v{font-size:21px;font-weight:600;letter-spacing:-.02em}.stats .v.crit{color:var(--crit)}
.stats .k{font-size:12px;color:var(--mut);margin-top:2px}
.main{display:grid;grid-template-columns:minmax(340px,1fr) minmax(360px,1.1fr);gap:0;
 height:calc(100vh - 118px)}
.queue{border-right:1px solid var(--line);overflow-y:auto}
.qh{padding:13px 22px 8px;font-size:13px;color:var(--mut);position:sticky;top:0;background:var(--bg)}
.row{display:flex;gap:11px;align-items:center;padding:11px 22px;border-bottom:1px solid var(--line);
 cursor:pointer;border-left:3px solid var(--mut)}
.row:hover{background:var(--panel)}.row.sel{background:var(--panel2)}
.row.warn{border-left-color:var(--warn)}.row.crit{border-left-color:var(--crit)}.row.ok{border-left-color:var(--ok)}
.row .chip{font-size:11px;padding:2px 8px;border-radius:999px;font-weight:600;background:#28313d;color:var(--mut);flex:none}
.chip.ok{background:#2a3a33;color:var(--ok)}.chip.warn{background:#3b3020;color:var(--warn)}.chip.crit{background:#3b2224;color:var(--crit)}
.row .rid{font-family:var(--mono);font-size:12px;color:var(--mut);flex:none}
.row .sm{font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.detail{overflow-y:auto;padding:0}
.empty{color:var(--mut);padding:40px 24px;text-align:center}
.card{padding:20px 24px}
.card pre{font-family:var(--sans);font-size:13.5px;white-space:pre-wrap;margin:0;line-height:1.55}
.svc{color:var(--mut);font-size:12px;margin-top:12px;font-family:var(--mono)}
.act{position:sticky;bottom:0;background:var(--panel);border-top:1px solid var(--line);padding:14px 24px}
.act .lbl{font-size:12px;color:var(--mut);margin-bottom:8px}
.btns{display:flex;gap:8px;flex-wrap:wrap}
.btns button{font:inherit;font-size:13px;border:1px solid var(--line);background:var(--panel2);color:var(--ink);
 padding:8px 12px;border-radius:6px;cursor:pointer}
.btns button:hover{border-color:var(--mut)}
.btns .ok{border-color:#2a4a3d}.btns .ok:hover{background:#1d2e27}
.btns .warn{border-color:#4a3d22}.btns .warn:hover{background:#2e2619}
.btns .crit{border-color:#4a2528}.btns .crit:hover{background:#2e1b1d}
.note{margin-top:10px;width:100%;background:var(--bg);border:1px solid var(--line);color:var(--ink);
 border-radius:6px;padding:8px 10px;font:inherit;font-size:13px}
.flash{padding:10px 24px;color:var(--ok);font-size:13px;border-bottom:1px solid var(--line);background:#14241d}
</style></head><body>
<div class="top"><div class="brand">Дежурный L1 <span>· kezekshi&#8209;l1</span></div>
 <div class="live"><span><span class="dot"></span>демон активен</span><span id="upd">—</span></div></div>
<div class="stats" id="stats"></div>
<div id="flash"></div>
<div class="main">
 <div class="queue"><div class="qh" id="qh">очередь…</div><div id="rows"></div></div>
 <div class="detail" id="detail"><div class="empty">Выберите тикет слева, чтобы увидеть карточку и закрыть его.</div></div>
</div>
<script>
let S=null, sel=null;
const esc=s=>(s==null?'':String(s)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
async function load(){
 try{const r=await fetch('/api/state');S=await r.json();}catch(e){return;}
 document.getElementById('upd').textContent='обновлено '+S.updated;
 const st=S;
 document.getElementById('stats').innerHTML=
  `<div><div class="v">${st.total}</div><div class="k">разобрано</div></div>`+
  `<div><div class="v">${st.pct_auto}%</div><div class="k">закрыто само (${st.auto_close})</div></div>`+
  `<div><div class="v">${st.l2}</div><div class="k">на L2 всего</div></div>`+
  `<div><div class="v">${st.tickets.length}</div><div class="k">в очереди сейчас</div></div>`+
  `<div><div class="v">${st.saved}</div><div class="k">без вызова модели</div></div>`+
  `<div><div class="v">${st.closed_today}</div><div class="k">закрыто дежурным</div></div>`;
 document.getElementById('qh').textContent='Очередь: '+st.tickets.length+' тикетов (сначала инциденты и подозрительное)';
 document.getElementById('rows').innerHTML=st.tickets.map(t=>
  `<div class="row ${t.cls} ${t.id===sel?'sel':''}" onclick="pick('${t.id}')">`+
  `<span class="chip ${t.cls}">${esc(t.verdict_ru)}</span>`+
  `<span class="rid">${esc(t.rule)}</span>`+
  `<span class="sm">${esc(t.host)} · ${esc(t.summary.slice(0,54))}</span></div>`).join('')||
  '<div class="empty">Очередь пуста. Поток под контролем.</div>';
 const noteEl=document.getElementById('note');
 if(sel && st.tickets.find(t=>t.id===sel) && !(noteEl&&noteEl.value)) renderDetail(st.tickets.find(t=>t.id===sel));
}
function pick(id){sel=id;document.querySelectorAll('.row').forEach(r=>r.classList.remove('sel'));
 renderDetail(S.tickets.find(t=>t.id===id));load();}
function renderDetail(t){
 if(!t){document.getElementById('detail').innerHTML='<div class="empty">Тикет закрыт.</div>';return;}
 document.getElementById('detail').innerHTML=
  `<div class="card"><pre>${esc(t.card_md||t.summary)}</pre>`+
  `<div class="svc">уровень ${esc(t.level)} · памятка: ${esc(t.rule_verdict)} · MITRE ${esc(t.mitre.join(' ')||'—')}</div></div>`+
  `<div class="act"><div class="lbl">Решение дежурного (запишется в журнал диспозиций):</div>`+
  `<div class="btns">`+
  `<button class="crit" onclick="close1('incident_candidate')">Инцидент</button>`+
  `<button class="warn" onclick="close1('suspicious')">Подозрительно</button>`+
  `<button class="ok" onclick="close1('benign_true_positive')">Легитимно</button>`+
  `<button class="ok" onclick="close1('false_positive')">Ложное</button>`+
  `</div><input class="note" id="note" placeholder="причина / что сделано (необязательно)"></div>`;
}
async function close1(v){
 const note=(document.getElementById('note')||{}).value||'';
 const r=await fetch('/api/close',{method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({id:sel,verdict:v,note:note})});
 const j=await r.json();
 if(j.ok){flash('Тикет закрыт как «'+v+'». Запись добавлена в журнал диспозиций.');sel=null;
  document.getElementById('detail').innerHTML='<div class="empty">Готово. Выберите следующий тикет.</div>';load();}
 else flash('Ошибка: '+(j.error||'?'));
}
function flash(m){const f=document.getElementById('flash');f.innerHTML='<div class="flash">'+esc(m)+'</div>';
 setTimeout(()=>f.innerHTML='',4000);}
load();setInterval(load,5000);
</script></body></html>"""


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        b = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        p = urlparse(self.path).path
        if p == "/" or p == "/index.html":
            self._send(200, PAGE, "text/html")
        elif p == "/api/state":
            self._send(200, json.dumps(state(), ensure_ascii=False))
        else:
            self._send(404, "{}")

    def do_POST(self):
        if urlparse(self.path).path == "/api/close":
            n = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
            except ValueError:
                body = {}
            self._send(200, json.dumps(close_ticket(body), ensure_ascii=False))
        else:
            self._send(404, "{}")


def main():
    srv = ThreadingHTTPServer((BIND, PORT), H)
    print(f"рабочее место дежурного: http://{BIND}:{PORT}  (out={OUT})", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()
