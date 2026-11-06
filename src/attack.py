# coding: utf-8
"""Локальный индекс MITRE ATT&CK + подбор кандидатов по тексту алерта (офлайн).

Модель плохо вспоминает идентификаторы техник из весов (на незнакомых типах
0/36). Поэтому технику не угадываем, а подбираем: по словам из пакета
доказательств достаём несколько кандидатов из этого индекса, а модель выбирает
подходящие из списка и не выдумывает коды.

Индекс покрывает все техники нашей разметки плюс частые для L1. Это не полный
STIX ATT&CK, а компактная таблица под SOC первой линии; при желании заменяется
на выгрузку enterprise-attack без изменения интерфейса.

Триггеры - слова и обороты (рус/англ), которые реально встречаются в пакетах
доказательств Wazuh/EDR. Подбор: сколько триггеров техники нашлось в тексте,
с весом по длине триггера (специфичные обороты весомее общих слов).
"""
import re

# id: (название, [триггеры в нижнем регистре])
TECH = {
    "T1003.001": ("LSASS Memory", ["lsass", "dumplsass", "дамп lsass", "дамп памяти", "comsvcs", "procdump", "mimikatz"]),
    "T1003.003": ("NTDS", ["ntds.dit", "ntds", "ntdsutil", "теневую копию", "vssadmin create", "reg save hklm\\system"]),
    "T1003.006": ("DCSync", ["dcsync", "ds-replication", "get-changes", "директори репликац", "репликац каталог", "4662", "krbtgt"]),
    "T1018": ("Remote System Discovery", ["remote system", "обнаружение хостов", "ping sweep", "net view", "nmap", "os detection", "-sn"]),
    "T1021": ("Remote Services", ["remote service", "удалён вход", "удалён служб", "lateral", "logontype 3", "сетевой вход"]),
    "T1021.001": ("Remote Desktop Protocol", ["rdp", "удалённого рабочего стола", "logontype 10", "3389", "remote desktop"]),
    "T1021.002": ("SMB/Windows Admin Shares", ["smb", "445", "admin share", "сетев вход", "logontype 3", "\\\\", "шар"]),
    "T1046": ("Network Service Discovery", ["nmap", "сканирован", "scan", "port scan", "-ss", "-o -t4", "портов"]),
    "T1048": ("Exfiltration Over Alternative Protocol", ["exfiltration", "эксфильтрац", "data exfil", "вынос данных", "over dns", "по dns", "outbound upload", "гб на", "upload"]),
    "T1053.005": ("Scheduled Task", ["schtask", "scheduled task", "задача планировщик", "4698", "планировщик", "каждые 30 минут"]),
    "T1059.001": ("PowerShell", ["powershell", "-enc", "обфусцированн", "scriptblock", "powershell.exe"]),
    "T1071.001": ("Web Protocols (C2)", ["https к", "c2", "бикон", "beacon", "периодическ", "cdn-telemetry", "command and control"]),
    "T1071.004": ("DNS (C2)", ["dns", "туннел", "tunnel", "резолвер", "resolver", "dns-туннел", "dns tunneling"]),
    "T1078": ("Valid Accounts", ["valid account", "легитимн учётк", "вход в нерабоч", "нерабочее время"]),
    "T1078.002": ("Domain Accounts", ["доменн админ", "domain admin", "da_", "привилегированн вход", "domain admins", "доменных админ"]),
    "T1078.004": ("Cloud Accounts", ["azure", "облачн учётк", "sign-in", "impossible travel", "невозможн перемещен", "вход из", "cloud account", "mfa"]),
    "T1083": ("File and Directory Discovery", ["file_id", "download_report", "перебор идентификатор", "соседн id", "directory discovery", "обход каталог", "etc/passwd", "traversal", "../"]),
    "T1090.003": ("Multi-hop Proxy (Tor)", ["tor", "тор", "guard node", "exit node", ":9001", "onion"]),
    "T1098": ("Account Manipulation", ["account manipulation", "добавил в группу", "4728", "сброс паролей", "4724", "изменение учётк"]),
    "T1098.001": ("Additional Cloud Credentials", ["client secret", "секрет приложени", "добавлен секрет", "service principal", "credentials added", "add-application"]),
    "T1105": ("Ingress Tool Transfer", ["certutil", "urlcache", "скачивани", "download", "загрузк", "-urlcache -split"]),
    "T1110.001": ("Password Guessing", ["перебор парол", "password guess", "failed login", "401", "brute", "python-requests", "logon failures", "failed logon", "failed logins", "4625", "неверный пароль"]),
    "T1110.003": ("Password Spraying", ["password spray", "распыление парол", "разн логин", "4771", "0x18", "несуществующ пользовател"]),
    "T1114.003": ("Email Forwarding Rule", ["inboxrule", "new-inboxrule", "правило пересылк", "forwarding", "пересылк писем", "deleted items"]),
    "T1127.001": ("MSBuild", ["msbuild", "msbuild.exe", "компиляц", "untrusted code"]),
    "T1135": ("Network Share Discovery", ["network share", "перебор шар", "обнаружение шар", "доступ к шар", "access denied"]),
    "T1190": ("Exploit Public-Facing Application", ["sql injection", "sqli", "union select", "path traversal", "../", "cve-", "exploit", "эксплойт", "payload"]),
    "T1213": ("Data from Information Repositories", ["sharepoint", "репозитори", "information repositor", "confluence", "wiki", "документ контрагент"]),
    "T1218": ("System Binary Proxy Execution", ["lolbin", "rundll32", "regsvr32", "mshta", "lolbas", "certutil"]),
    "T1218.011": ("Rundll32", ["rundll32", "rundll32.exe"]),
    "T1219": ("Remote Access Software", ["rustdesk", "anydesk", "teamviewer", "удалённого доступа", "remote admin", "not-a-virus:remoteadmin"]),
    "T1484.001": ("Group Policy Modification", ["gpo", "group policy", "групповую политик", "доменн политик", "5136", "gpcmachineextension", "sysvol"]),
    "T1490": ("Inhibit System Recovery", ["vssadmin delete", "delete shadows", "теневые копии", "shadow copy", "удаление теневых"]),
    "T1496": ("Resource Hijacking", ["xmrig", "coinminer", "майнер", "miner", "pool.supportxmr", "monero", "крипто"]),
    "T1505.003": ("Web Shell", ["web-shell", "webshell", "веб-шелл", "w3wp.exe", "zwso.php", ".php", "www-data"]),
    "T1528": ("Steal Application Access Token", ["oauth", "consent", "consenttoapplication", "согласие приложени", "access token", "scope", "mail.read", "offline_access"]),
    "T1546.003": ("WMI Event Subscription", ["wmi", "eventconsumer", "eventfilter", "подписк wmi", "commandlineeventconsumer", "permanent event"]),
    "T1547.001": ("Registry Run Keys", ["run key", "currentversion\\run", "автозапуск", "hkcu run", "runonce"]),
    "T1548.003": ("Sudo and Sudo Caching", ["sudo", "sudoers", "nopasswd", "sudoers.d", "su -", "беспарольн sudo"]),
    "T1556.006": ("MFA Modification", ["mfa", "метод mfa", "authenticator", "добавлен метод", "mfa method"]),
    "T1558.003": ("Kerberoasting", ["kerberoast", "tgs", "4769", "rc4-hmac", "spn", "mssqlsvc", "weak encryption"]),
    "T1558.004": ("AS-REP Roasting", ["as-rep", "asrep", "dont_require_preauth", "без преаутентификац", "4768", "преаутентификац"]),
    "T1566": ("Phishing", ["phishing", "фишинг", "spoof", "dmarc", "spf", "поддел отправител"]),
    "T1566.001": ("Spearphishing Attachment", ["вложени", "attachment", "invoice", ".exe вложени", ".docm", "statement_v2"]),
    "T1567": ("Exfiltration Over Web Service", ["exfiltration", "эксфильтрац", "выгрузк", "web service", "proton.me"]),
    "T1567.002": ("Exfiltration to Cloud Storage", ["mega.nz", "файлообмен", "file-sharing", "anonfiles", "выгрузка на", "cloud storage", "dropbox"]),
    "T1569.002": ("Service Execution (PsExec)", ["psexec", "psexesvc", "7045", "service execution", "установлена служба"]),
    "T1570": ("Lateral Tool Transfer", ["lateral tool", "перенос инструмент", "admin$", "копирован на хост", "psexesvc", "psexec"]),
    "T1571": ("Non-Standard Port", ["non-standard port", "нестандартн порт", "одинаков размер", "512 байт"]),
    "T1621": ("MFA Request Generation", ["mfa fatigue", "push bombing", "push bomb", "шквал push", "mfa push", "47 запрос", "усталость от mfa"]),
    # Добавлены 06.11.2026 по обучающей разметке (test_b при подборе не использовался).
    "T1003": ("OS Credential Dumping", ["credential dump", "дамп учётн", "читает учётки", "mimikatz"]),
    "T1036": ("Masquerading", ["masquerad", "маскир", "подмен", "herpaderping", "image replacement"]),
    "T1055.013": ("Process Doppelganging", ["doppelg", "herpaderping", "image replacement"]),
    "T1059.004": ("Unix Shell", ["/bin/bash", "/bin/sh", "| sh", "shellshock", "shell session", "bash"]),
    "T1059.007": ("JavaScript", ["<script", "xss", "cross-site scripting", "javascript"]),
    "T1070.001": ("Clear Windows Event Logs", ["log was cleared", "1102", "wevtutil cl", "clear-eventlog", "очистк журнал", "журнал очищен"]),
    "T1087": ("Account Discovery", ["net group", "net user", "account discovery", "перечисление", "enum4linux"]),
    "T1136.001": ("Create Local Account", ["user account created", "4720", "net user /add", "useradd", "создана учётн"]),
    "T1486": ("Data Encrypted for Impact", [".locked", ".encrypted", "ransom", "выкуп", "зашифрован", "шифровальщик"]),
    "T1552.001": ("Credentials In Files", ["/run/secrets", "/etc/shadow", "id_rsa", "credentials in file", "чтение секрет"]),
    "T1555.004": ("Windows Credential Manager", ["credential manager", "5379", "vaultcmd", "диспетчер учётн"]),
    "T1595.002": ("Vulnerability Scanning", ["nikto", "vulnerability scanner", "acunetix", "sqlmap", "nessus", "сканер уязвим"]),
    "T1610": ("Deploy Container", ["docker", "container", "контейнер", "kubectl exec"]),
}


_LATIN = re.compile(r"^[a-z0-9]+$")
_CYR = re.compile(r"^[а-яё]+$")
WID = re.compile(r"^T\d{4}(\.\d{3})?$")


def _pattern(kw):
    """Короткий триггер ищем по границе слова: иначе tor находится в monitor, 401 в номере."""
    if len(kw) <= 4 and _LATIN.match(kw):
        return re.compile(r"(?<![a-z0-9])" + re.escape(kw) + r"(?![a-z0-9])")
    if len(kw) <= 4 and _CYR.match(kw):
        return re.compile(r"(?<![а-яё])" + re.escape(kw))   # русские триггеры - основы слов
    return re.compile(re.escape(kw))


_COMPILED = {tid: [(_pattern(kw), kw) for kw in kws] for tid, (_, kws) in TECH.items()}


def candidates(text, k=8, extra=None):
    """Топ-k кандидатов (id, name) по совпадению триггеров с текстом алерта.

    extra - готовые техники из метки правила Wazuh, [(id, name)]: идут первыми.
    """
    t = text.lower()
    scored = []
    for tid, (name, _) in TECH.items():
        s = 0.0
        for pat, kw in _COMPILED[tid]:
            if pat.search(t):
                s += 1 + 0.5 * kw.count(" ")      # специфичные обороты весомее
        if s > 0:
            scored.append((s, tid, name))
    scored.sort(key=lambda x: (-x[0], x[1]))
    out, seen = [], set()
    for tid, name in list(extra or []) + [(tid, name) for _, tid, name in scored]:
        if tid not in seen and WID.match(tid):
            seen.add(tid)
            out.append((tid, name or TECH.get(tid, ("", []))[0]))
    return out[:k]


def block_for(cands):
    """Блок-инструкция с готовым списком кандидатов для системного промпта."""
    if not cands:
        return ""
    lst = "; ".join(f"{tid} {name}" for tid, name in cands)
    # Список кандидатов влияет на вердикт: подталкивает к эскалации. Оговорка "кандидаты не
    # означают атаку" проверена 06.11.2026 и отвергнута: recall на отложенных v6 упал 20/20 -> 18/20
    # (oauth_consent и idor закрыты как штатные). Лишняя эскалация дешевле пропущенной атаки.
    return ("\n\nКандидаты MITRE ATT&CK для этого алерта (подбор по тексту). "
            "В поле mitre указывай ТОЛЬКО идентификаторы из этого списка и только те, "
            "что действительно подтверждаются доказательствами; если ничего не подходит - "
            f"пустой список. Не придумывай коды вне списка.\n{lst}")


def block(text, k=8, extra=None):
    """Блок с кандидатами по тексту алерта (пусто, если совпадений нет)."""
    return block_for(candidates(text, k, extra))


if __name__ == "__main__":
    import sys
    print(block(sys.stdin.read()))
