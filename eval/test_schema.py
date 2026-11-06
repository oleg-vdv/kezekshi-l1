# coding: utf-8
"""Офлайн-проверки подбора MITRE и схемы ответа (модель не нужна): python eval/test_schema.py"""
import os, sys
sys.path[:0] = [os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", d) for d in ("src", "pipeline")]
import attack, normalize, triage


def ids(text, **kw):
    return [t for t, _ in attack.candidates(text, **kw)]


# короткие триггеры больше не срабатывают внутри слов
assert "T1090.003" not in ids("monitor director монитор сектор")
assert "T1090.003" in ids("connection to tor exit node")
assert "T1110.001" not in ids("request id 74012")
assert "T1110.001" in ids("POST /login HTTP 401")

# метка Wazuh идёт первой, мусор отсекается, лимит соблюдается
got = attack.candidates("lsass powershell", k=2, extra=[("T9999", "X"), ("bad id", "Y")])
assert got[0] == ("T9999", "X") and len(got) == 2 and all(t != "bad id" for t, _ in got)
assert attack.block_for([]) == ""

# схема: только E-id алерта и только кандидаты
s = triage.response_schema(["E2", "E10", "E1"], ["T1110.001"])
ev = s["properties"]["claims"]["items"]["properties"]["evidence"]
assert ev["items"]["enum"] == ["E1", "E2", "E10"] and ev["minItems"] == 1
assert s["properties"]["claims"]["minItems"] == 1
assert s["properties"]["mitre"]["items"]["enum"] == ["T1110.001"]
assert triage.response_schema(["E1"], [])["properties"]["mitre"]["maxItems"] == 0
assert "enum" not in triage.response_schema(["E1"])["properties"]["mitre"]["items"]
assert "enum" not in triage.SCHEMA["properties"]["mitre"]["items"]    # базовая схема не испорчена

# нормализация: метка Wazuh отдельным полем, в пакет id не попадает
case = normalize.to_case({"rule": {"id": "5710", "level": 5,
                                   "mitre": {"id": ["T1110.001"], "technique": ["Password Guessing"]}},
                          "agent": {"name": "a"}}, "x")
assert case["wazuh_mitre"] == [("T1110.001", "Password Guessing")]
assert not any(e["field"] == "rule.mitre.id" for e in case["evidence"])
assert normalize.to_case({"rule": {"id": "1", "level": 1}, "agent": {}}, "y")["wazuh_mitre"] == []
print("ok")
