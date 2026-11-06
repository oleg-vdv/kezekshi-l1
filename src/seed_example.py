# coding: utf-8
"""Примеры разметки: показывают формат кейса для build.py.

Рабочая разметка в репозиторий не входит (см. docs/dataset.md). Эти кейсы написаны
с нуля, все адреса из документационных диапазонов, имена вымышленные. На пяти
примерах модель не обучить: это образец, по которому собирают свой набор.
"""

HELDOUT_TYPES = {"example_heldout_dcsync"}   # типы только для test_b, в обучение не идут

CASES = [
    {"key": "ssh_bruteforce_success", "type": "ssh_bruteforce", "label": "incident_candidate",
     "evidence": [
         ("rule.description", "sshd: Multiple authentication failures followed by success"),
         ("data.srcip", "203.0.113.45"),
         ("failures", "214 неудачных входа для deploy за 6 минут"),
         ("success", "затем Accepted password for deploy from 203.0.113.45"),
     ],
     "gold": {"summary": "Перебор пароля SSH завершился успешным входом под deploy. Срочно L2.",
              "claims": [("Серия неудачных входов с одного адреса", ["E2", "E3"]),
                         ("После серии вход выполнен успешно", ["E4"])],
              "mitre": ["T1110.001"],
              "missing": ["Что выполнялось в сессии deploy"],
              "next_steps": ["Завершить сессию и сменить пароль", "Проверить действия deploy после входа"]}},
    {"key": "ssh_bruteforce_blocked", "type": "ssh_bruteforce", "label": "suspicious",
     "evidence": [
         ("rule.description", "sshd: Multiple authentication failures"),
         ("data.srcip", "203.0.113.46"),
         ("failures", "120 неудачных входов для root за 3 минуты"),
         ("outcome", "успешного входа нет, адрес заблокирован fail2ban"),
     ],
     "gold": {"summary": "Перебор пароля SSH без успешного входа. Нужен просмотр L2.",
              "claims": [("Серия неудачных входов к root", ["E2", "E3"]),
                         ("Успеха нет, адрес заблокирован", ["E4"])],
              "mitre": ["T1110.001"],
              "missing": ["Попытки с этого адреса на другие узлы"],
              "next_steps": ["Проверить, нет ли других узлов под тем же перебором"]}},
    {"key": "scanner_authorized", "type": "vuln_scan", "label": "benign_true_positive",
     "evidence": [
         ("rule.description", "Multiple web requests to non-existent URLs"),
         ("data.srcip", "198.51.100.10"),
         ("context", "адрес выделенного сканера уязвимостей, заявка CHG-1042 на это окно"),
     ],
     "gold": {"summary": "Плановое сканирование по заявке. Событие реальное, но это не атака.",
              "claims": [("Источник - сканер с заявкой на это окно", ["E2", "E3"])],
              "mitre": [],
              "missing": [],
              "next_steps": ["Закрыть со ссылкой на заявку"]}},
    {"key": "eicar_test_file", "type": "av_test", "label": "false_positive",
     "evidence": [
         ("rule.name", "Antivirus: EICAR test file detected"),
         ("file.path", "/tmp/qa/eicar.com"),
         ("context", "проверка работы антивируса отделом QA, файл удалён"),
     ],
     "gold": {"summary": "Тестовый файл EICAR при проверке антивируса. Угрозы нет.",
              "claims": [("Сработала тестовая сигнатура EICAR", ["E1", "E2"])],
              "mitre": [],
              "missing": [],
              "next_steps": ["Закрыть как ложное срабатывание"]}},
    {"key": "example_dcsync", "type": "example_heldout_dcsync", "label": "incident_candidate",
     "evidence": [
         ("win.system.eventID", "4662"),
         ("object", "DS-Replication-Get-Changes-All на корне домена"),
         ("subject", "учётка m.demo с рабочей станции, не контроллер домена"),
     ],
     "gold": {"summary": "Репликация каталога с рабочей станции: признак DCSync. Срочно L2.",
              "claims": [("Запрошены права репликации каталога", ["E1", "E2"]),
                         ("Источник не контроллер домена", ["E3"])],
              "mitre": ["T1003.006"],
              "missing": ["Какие учётки реплицированы"],
              "next_steps": ["Изолировать станцию", "Сменить пароль krbtgt по процедуре"]}},
]
