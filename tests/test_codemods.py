from __future__ import annotations

import ast

import pytest

from vulnwarden.codemods import apply_codemod, codemod_for
from vulnwarden.models import Category, Finding, Severity


def finding(rule_id: str, line: int, path: str = "app.py", **details) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="t",
        category=Category.CODE,
        severity=Severity.HIGH,
        source="test",
        path=path,
        line=line,
        details=details,
    )


@pytest.mark.parametrize(
    ("rule", "line", "source", "expected"),
    [
        (
            "VW-PY-YAML-LOAD",
            2,
            "import yaml\ndata = yaml.load(text, Loader=yaml.Loader)\n",
            "import yaml\ndata = yaml.safe_load(text)\n",
        ),
        (
            "VW-PY-TLS-VERIFY-OFF",
            2,
            "import requests\nr = requests.get(url, verify=False, timeout=5)\n",
            "import requests\nr = requests.get(url, timeout=5)\n",
        ),
        ("VW-PY-FLASK-DEBUG", 1, "app.run(host='0.0.0.0', debug=True)\n", "app.run(host='0.0.0.0', debug=False)\n"),
        (
            "VW-PY-SHELL",
            2,
            "import subprocess\nsubprocess.run(['ls', '-l'], shell=True, check=True)\n",
            "import subprocess\nsubprocess.run(['ls', '-l'], check=True)\n",
        ),
        (
            "VW-CRYPTO-WEAK-HASH",
            2,
            "import hashlib\nh = hashlib.md5(body).hexdigest()\n",
            "import hashlib\nh = hashlib.sha256(body).hexdigest()\n",
        ),
        (
            "VW-CRYPTO-WEAK-HASH",
            2,
            "import hashlib\nh = hashlib.new('sha1', body)\n",
            'import hashlib\nh = hashlib.new("sha256", body)\n',
        ),
    ],
)
def test_python_codemods(rule, line, source, expected):
    assert apply_codemod(source, finding(rule, line)) == expected


def test_shell_codemod_adds_shlex_after_imports():
    source = '"""Doc."""\nimport subprocess\n\n\ndef v(tool):\n    return subprocess.check_output(f"{tool} --version", shell=True, text=True).strip()\n'
    result = apply_codemod(source, finding("VW-PY-SHELL", 6))
    assert 'subprocess.check_output(shlex.split(f"{tool} --version"), text=True).strip()' in result
    assert result.splitlines()[2] == "import shlex"
    ast.parse(result)


def test_sql_codemod_parameterizes_by_driver_paramstyle():
    sqlite = "import sqlite3\nrows = conn.execute(f\"SELECT * FROM users WHERE name = '{name}' AND id = {user.id}\").fetchall()\n"
    result = apply_codemod(sqlite, finding("VW-PY-SQL-INJECTION", 2))
    assert "conn.execute('SELECT * FROM users WHERE name = ? AND id = ?', (name, user.id)).fetchall()" in result
    psycopg = 'import psycopg2\ncur.execute(f"DELETE FROM t WHERE id = {tid}")\n'
    assert "cur.execute('DELETE FROM t WHERE id = %s', (tid,))" in apply_codemod(
        psycopg, finding("VW-PY-SQL-INJECTION", 2)
    )


def test_sql_codemod_refuses_unsafe_rewrites():
    like = "import sqlite3\nconn.execute(f\"SELECT * FROM t WHERE n LIKE '%{q}%'\")\n"
    assert apply_codemod(like, finding("VW-PY-SQL-INJECTION", 2)) is None
    unknown_driver = "conn.execute(f\"SELECT * FROM t WHERE n = '{q}'\")\n"
    assert apply_codemod(unknown_driver, finding("VW-PY-SQL-INJECTION", 1)) is None


def test_eval_and_secret_codemods_add_imports():
    result = apply_codemod("def f(x):\n    return eval(x)\n", finding("VW-PY-EVAL", 2))
    assert result == "import ast\ndef f(x):\n    return ast.literal_eval(x)\n"
    secret = apply_codemod('import sys\nAPI_KEY = "abc123456789"\n', finding("VW-PY-HARDCODED-SECRET", 2))
    assert secret == 'import sys\nimport os\nAPI_KEY = os.environ["API_KEY"]\n'


def test_password_hashing_is_never_auto_swapped():
    f = finding("VW-CRYPTO-WEAK-HASH", 2, context="password")
    assert codemod_for(f) is None
    assert apply_codemod("import hashlib\nh = hashlib.sha1(pw).hexdigest()\n", f) is None


def test_codemods_preserve_crlf_line_endings():
    source = "import yaml\r\ndata = yaml.load(text)\r\nprint(data)\r\n"
    assert (
        apply_codemod(source, finding("VW-PY-YAML-LOAD", 2))
        == "import yaml\r\ndata = yaml.safe_load(text)\r\nprint(data)\r\n"
    )


def test_dockerfile_codemods():
    text = 'FROM python:3.8-slim-buster\nWORKDIR /app\nCMD ["python", "app.py"]\n'
    eol = finding(
        "VW-DOCKER-EOL-BASE",
        1,
        path="Dockerfile",
        image="python:3.8-slim-buster",
        recommended_image="python:3.12-slim-bookworm",
    )
    assert apply_codemod(text, eol).startswith("FROM python:3.12-slim-bookworm\n")
    root = apply_codemod(text, finding("VW-DOCKER-ROOT", 1, path="Dockerfile"))
    assert root.splitlines()[2] == "USER 10001" and root.splitlines()[3].startswith("CMD")


def test_tls_config_codemods():
    conf = "server {\n    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n    ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:RC4-SHA:DES-CBC3-SHA';\n}\n"
    tls = apply_codemod(conf, finding("VW-CRYPTO-LEGACY-TLS", 2, path="nginx.conf"))
    assert "    ssl_protocols TLSv1.2;\n" in tls
    ciphers = apply_codemod(conf, finding("VW-CRYPTO-WEAK-TLS-CIPHER", 3, path="nginx.conf"))
    assert "ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:!aNULL:!MD5:!RC4:!3DES';" in ciphers
    apache = apply_codemod("SSLProtocol all -SSLv3\n", finding("VW-CRYPTO-LEGACY-TLS", 1, path="ssl.conf"))
    assert apache == "SSLProtocol -all +TLSv1.2 +TLSv1.3\n"


def test_no_codemod_for_unknown_rules_or_wrong_file_types():
    assert codemod_for(finding("VW-PY-PICKLE", 1)) is None
    assert codemod_for(finding("VW-CRYPTO-LEGACY-TLS", 1, path="tls.py")) is None
    assert apply_codemod("x = 1\n", finding("VW-PY-YAML-LOAD", 1)) is None
