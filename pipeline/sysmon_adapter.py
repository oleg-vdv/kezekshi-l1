# coding: utf-8
"""Адаптер: сырые Sysmon-события из дампа Wazuh-архива -> пакет доказательств -> v4.

Пайплайн (run.py/normalize.py) рассчитан на готовые алерты Wazuh. Sysmon-архив -
это сырая телеметрия (отдельные события data.Event.EventData), а не алерты.
Чтобы прогнать модель по таким данным, события агрегируются ПО ПРОЦЕССУ
(ProcessGuid): для каждого процесса собирается поведение (создание файлов,
сетевые соединения, DNS-запросы с пометкой NXDOMAIN/односложных = DGA-подобных),
и из этого строится пакет доказательств - как если бы SIEM поднял алерт на
подозрительное поведение процесса.

Это КАЧЕСТВЕННЫЙ прогон на живых данных (без эталонных вердиктов - честных
метрик по нему не посчитать). Данные обрабатываются локально, наружу не уходят.

Запуск:  python sysmon_adapter.py <wazuh_archive_search.json> [N]
         N - сколько самых активных/подозрительных процессов разобрать (по умолч. 6).
"""
import json, os, sys
from collections import defaultdict

try:
    sys.stdout.reconfigure(encoding="utf-8")   # карточки по-русски, независимо от кодировки консоли
except Exception:
    pass

SRC = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, SRC)
os.environ.setdefault("TRIAGE_HINT", "0")      # синтетического правила нет в памятке
os.environ.setdefault("TRIAGE_THINK", "0")     # рабочий режим - без размышления
import triage   # noqa: E402
import policy    # noqa: E402

MODEL = os.environ.get("MODEL", "kezekshi-l1-v4")
if os.environ.get("OLLAMA_URL"):
    triage.OLLAMA = os.environ["OLLAMA_URL"]

EIDNAME = {"1": "ProcessCreate", "3": "NetworkConnect", "11": "FileCreate",
           "22": "DnsQuery", "12": "RegCreateDelete", "13": "RegSetValue",
           "8": "CreateRemoteThread", "10": "ProcessAccess", "7": "ImageLoad"}
SUSP_IMG = ("powershell.exe", "mshta.exe", "cmd.exe", "wscript.exe", "cscript.exe",
            "rundll32.exe", "regsvr32.exe", "ftp.exe", "certutil.exe", "bitsadmin.exe")


def short(guid):
    return (guid or "")[-12:]


def load_procs(path):
    doc = json.load(open(path, encoding="utf-8"))
    procs = defaultdict(lambda: {"image": "", "parent": "", "user": "", "integrity": "",
                                 "cmdline": "", "host": "", "files": [], "net": [], "dns": [],
                                 "children": [], "nevents": 0})
    for h in doc.get("hits", {}).get("hits", []):
        src = h.get("_source", {})
        ev = (src.get("data") or {}).get("Event")
        if not isinstance(ev, dict):
            continue
        ed = ev.get("EventData", {}) or {}
        sysm = ev.get("System", {}) or {}
        eid = str(sysm.get("EventID", ""))
        guid = ed.get("ProcessGuid") or ed.get("SourceProcessGuid") or "?"
        p = procs[guid]
        p["nevents"] += 1
        if not p["host"]:
            p["host"] = sysm.get("Computer", "")
        if eid == "1":   # ProcessCreate: личность процесса
            p["image"] = ed.get("Image", p["image"])
            p["parent"] = ed.get("ParentImage", p["parent"])
            p["user"] = ed.get("User", p["user"])
            p["integrity"] = ed.get("IntegrityLevel", p["integrity"])
            p["cmdline"] = ed.get("CommandLine", p["cmdline"])
            par = ed.get("ParentProcessGuid")
            if par:
                procs[par]["children"].append(ed.get("Image", "").split("\\")[-1])
        else:
            if not p["image"]:
                p["image"] = ed.get("Image", "")
            if eid == "11":
                tf = ed.get("TargetFilename")
                if tf:
                    p["files"].append(tf)
            elif eid == "3":
                dst = f'{ed.get("DestinationIp","?")}:{ed.get("DestinationPort","?")}'
                p["net"].append(dst)
            elif eid == "22":
                q = ed.get("QueryName", "?")
                st = ed.get("QueryStatus", "?")
                nx = st == "9003"
                dga = nx and "." not in q and len(q) >= 8   # односложный несуществующий домен
                p["dns"].append((q, "NXDOMAIN" if nx else st, dga))
    return procs


def suspiciousness(p):
    score = 0
    score += 3 * sum(1 for _, _, dga in p["dns"] if dga)   # DGA-подобные запросы весомее
    score += min(len(p["files"]), 40) * 0.1
    score += min(len(p["net"]), 40) * 0.2
    if p["image"].split("\\")[-1].lower() in SUSP_IMG:
        score += 2
    return score


def build_case(guid, p):
    img = p["image"].split("\\")[-1] or "?"
    ev, i = [], 1

    def add(field, value):
        nonlocal i
        ev.append({"id": f"E{i}", "field": field, "value": str(value)[:600]}); i += 1

    add("event.host", p["host"] or "?")
    add("process.image", f'{p["image"]} (guid …{short(guid)})')
    if p["parent"]:
        add("process.parent", p["parent"])
    if p["user"] or p["integrity"]:
        add("process.user", f'{p["user"]} integrity={p["integrity"]}')
    if p["cmdline"]:
        add("process.cmdline", p["cmdline"])
    if p["files"]:
        sample = "; ".join(p["files"][:6])
        add("file.creates", f'{len(p["files"])} файлов, напр.: {sample}')
    if p["net"]:
        uniq = sorted(set(p["net"]))
        add("network.connections", f'{len(p["net"])} соединений к: {"; ".join(uniq[:10])}')
    if p["dns"]:
        shown = "; ".join(f'{q}({st})' for q, st, _ in p["dns"][:12])
        add("dns.queries", f'{len(p["dns"])} запросов: {shown}')
        ndga = sum(1 for _, _, dga in p["dns"] if dga)
        if ndga:
            add("dns.dga_like", f'{ndga} односложных несуществующих домена (NXDOMAIN) - похоже на DGA/C2')
    if p["children"]:
        add("process.children", f'{len(p["children"])} дочерних: {", ".join(p["children"][:8])}')
    return {"case": f"sysmon:{img}:…{short(guid)}", "rule_id": "92100",
            "level": 10, "agent": "ubuntu-8gb-hel1-1", "event_host": p["host"] or "?",
            "evidence": ev}


def card(case, ans, dec):
    a = ans or {}
    out = [f"=== {case['case']}  (событий агрегировано в пакет: {len(case['evidence'])} E) ===",
           f"Компьютер: {case['event_host']}",
           f"Вердикт модели: {a.get('verdict','?')}    Маршрут: {dec['action']}  ({dec['reason']})",
           f"Суть: {a.get('summary','')}", "Утверждения:"]
    for c in a.get("claims", []):
        out.append(f"  - {c.get('text','')} [{', '.join(c.get('evidence', []))}]")
    out.append("MITRE: " + (", ".join(a.get("mitre", [])) or "нет"))
    out.append("Проверить: " + ("; ".join(a.get("next_steps", [])) or "-"))
    return "\n".join(out)


def main():
    path = sys.argv[1]
    topn = int(sys.argv[2]) if len(sys.argv) > 2 else 6
    procs = load_procs(path)
    ranked = sorted(procs.items(), key=lambda kv: suspiciousness(kv[1]), reverse=True)
    ranked = [(g, p) for g, p in ranked if p["image"]][:topn]
    print(f"процессов всего: {len(procs)};  разбираю топ-{len(ranked)} по подозрительности  (модель {MODEL})\n")
    for guid, p in ranked:
        case = build_case(guid, p)
        flags = triage.prerules(case)
        if "injection" in flags:
            ans = {}
        else:
            try:
                ans, _ = triage.ask(MODEL, case)
            except Exception as e:
                ans = {}
                print("ошибка модели:", type(e).__name__, e)
        errs = triage.validate(case, ans) if ans else ["no answer"]
        dec = policy.decide(case, ans, errs, flags)
        print(card(case, ans, dec))
        if errs:
            print("валидатор:", errs)
        print()


if __name__ == "__main__":
    main()
