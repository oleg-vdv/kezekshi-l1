"""Read-only доступ к индексатору Wazuh. Пароль берётся из файла и никуда не выводится.

Доступны только GET и POST на `_search`/`_count` (чтение). В Wazuh ничего не пишется.
Адрес индексатора берётся из WAZUH_INDEXER_HOST, учётные данные - из
~/.kezekshi/wazuh.env (WAZUH_INDEXER_USER, WAZUH_INDEXER_PASS). Пароль не печатается.
"""
import base64, json, os, ssl, urllib.request
from pathlib import Path

HOST = os.environ.get("WAZUH_INDEXER_HOST", "https://10.0.0.28:9200")
_env = dict(l.strip().split("=", 1) for l in Path.home().joinpath(".kezekshi/wazuh.env").read_text(encoding="utf-8-sig").splitlines() if "=" in l)
_auth = base64.b64encode(f"{_env['WAZUH_INDEXER_USER']}:{_env['WAZUH_INDEXER_PASS']}".encode()).decode()
_ctx = ssl.create_default_context(); _ctx.check_hostname = False; _ctx.verify_mode = ssl.CERT_NONE

def q(path, body=None):
    # только GET и _search (POST с запросом на чтение)
    assert body is None or path.endswith("/_search") or path.endswith("/_count"), path
    req = urllib.request.Request(HOST + path, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": "Basic " + _auth, "Content-Type": "application/json"},
                                 method="POST" if body is not None else "GET")
    with urllib.request.urlopen(req, context=_ctx, timeout=60) as r:
        return json.loads(r.read())
