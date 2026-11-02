from __future__ import annotations

import json
import os
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator

from vulnwarden import crypto
from vulnwarden.scanners.dependencies import find_dependencies

NOW = datetime(2026, 11, 2, tzinfo=UTC)


def _cert(path: Path, *, days_left: int, age_days: int, key_size: int = 2048, issuer: str = "Test CA") -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "svc.example.com")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
        .public_key(key.public_key())
        .serial_number(7)
        .not_valid_before(NOW - timedelta(days=age_days))
        .not_valid_after(NOW + timedelta(days=days_left))
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _repo(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(
        "import hashlib, hmac, ssl\n"
        "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n"
        "from cryptography.hazmat.primitives.asymmetric import rsa, ec\n"
        "def etag(b):\n    return hashlib.md5(b).hexdigest()\n"
        "def store(password):\n    return hashlib.sha1(password.encode()).hexdigest()\n"
        "def ok(b):\n    return hashlib.md5(b, usedforsecurity=False).hexdigest()\n"
        "c = Cipher(algorithms.TripleDES(k), modes.ECB())\n"
        "g = Cipher(algorithms.AES(k), modes.GCM(iv))\n"
        "key = rsa.generate_private_key(public_exponent=65537, key_size=1024)\n"
        "eck = ec.generate_private_key(ec.SECP256R1())\n"
        "mac = hmac.new(k, m, hashlib.md5)\n"
        "ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)\n",
        encoding="utf-8",
    )
    (tmp_path / "Crypto.java").write_text(
        'MessageDigest.getInstance("SHA-1");\nCipher.getInstance("AES");\n'
        'KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");\nkpg.initialize(1024);\n',
        encoding="utf-8",
    )
    (tmp_path / "web.js").write_text(
        "crypto.createHash('md5');\ncrypto.createCipheriv('des-ede3-cbc', k, iv);\n"
        "generateKeyPairSync('rsa', { modulusLength: 4096 });\n",
        encoding="utf-8",
    )
    (tmp_path / "main.go").write_text("h := md5.New()\nk, _ := rsa.GenerateKey(rand.Reader, 1024)\n", encoding="utf-8")
    (tmp_path / "Hash.cs").write_text(
        "var h = SHA1.Create();\nvar r = new RSACryptoServiceProvider(1024);\n", encoding="utf-8"
    )
    (tmp_path / "nginx.conf").write_text(
        "ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers 'HIGH:!aNULL:RC4-SHA';\n", encoding="utf-8"
    )
    (tmp_path / "requirements.txt").write_text("pycrypto==2.6.1\ncryptography==44.0.1\n", encoding="utf-8")
    certs = tmp_path / "certs"
    certs.mkdir()
    _cert(certs / "expiring.pem", days_left=5, age_days=500, key_size=1024, issuer="svc.example.com")
    _cert(certs / "healthy.pem", days_left=200, age_days=30)
    key = ec.generate_private_key(ec.SECP256R1())
    (certs / "client.key").write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    return tmp_path


def _inventory(root: Path):
    exclude = [".git"]
    return crypto.discover(root, exclude, find_dependencies(root, exclude))


def test_discovery_across_languages_configs_certs_keys_and_libraries(tmp_path):
    assets = _inventory(_repo(tmp_path))
    names = {(a.path, a.name) for a in assets}
    for expected in [
        ("app.py", "MD5"),
        ("app.py", "SHA1"),
        ("app.py", "3DES-ECB"),
        ("app.py", "AES-GCM"),
        ("app.py", "RSA-1024"),
        ("app.py", "ECDSA-SECP256R1"),
        ("app.py", "HMAC-MD5"),
        ("app.py", "TLS 1.1"),
        ("Crypto.java", "SHA1"),
        ("Crypto.java", "AES-ECB"),
        ("Crypto.java", "RSA-1024"),
        ("web.js", "MD5"),
        ("web.js", "3DES-CBC"),
        ("web.js", "RSA-4096"),
        ("main.go", "MD5"),
        ("main.go", "RSA-1024"),
        ("Hash.cs", "SHA1"),
        ("Hash.cs", "RSA-1024"),
        ("nginx.conf", "TLS 1.2"),
        ("nginx.conf", "RC4"),
        ("certs/expiring.pem", "svc.example.com"),
        ("certs/client.key", "ECDSA private key"),
        ("requirements.txt", "pycrypto"),
    ]:
        assert expected in names, expected
    java_aes = next(a for a in assets if a.path == "Crypto.java" and a.name == "AES-ECB")
    assert "implicit_mode" in java_aes.details


def test_policy_evaluation(tmp_path):
    root = _repo(tmp_path)
    assets = _inventory(root)
    findings = crypto.evaluate(assets, crypto.CryptoPolicy(), NOW, ages={"certs/client.key": 400})
    by_rule: dict[str, list] = {}
    for finding in findings:
        by_rule.setdefault(finding.rule_id, []).append(finding)
    weak_hash_py = [f for f in by_rule["VW-CRYPTO-WEAK-HASH"] if f.path == "app.py"]
    assert {f.line for f in weak_hash_py} == {5, 7, 14}  # usedforsecurity=False on line 9 is exempt
    password = next(f for f in weak_hash_py if f.line == 7)
    assert password.severity.value == "high" and password.cwe == ["CWE-916"]
    assert {
        "VW-CRYPTO-WEAK-CIPHER",
        "VW-CRYPTO-ECB-MODE",
        "VW-CRYPTO-SHORT-KEY",
        "VW-CRYPTO-LEGACY-TLS",
        "VW-CRYPTO-WEAK-TLS-CIPHER",
        "VW-CERT-EXPIRING",
        "VW-CERT-SELF-SIGNED",
        "VW-CRYPTO-ROTATION-DUE",
        "VW-CRYPTO-PRIVATE-KEY",
        "VW-CRYPTO-DEPRECATED-LIB",
    } <= set(by_rule)
    assert not [f for f in findings if f.path == "certs/healthy.pem"]
    assert not [f for f in findings if f.path == "web.js" and "4096" in f.snippet]
    assert by_rule["VW-CRYPTO-PRIVATE-KEY"][0].severity.value == "critical"


def test_custom_policy_from_yaml(tmp_path):
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("name: Strict\nmin_tls_version: '1.3'\nmin_key_sizes: {RSA: 3072}\n", encoding="utf-8")
    policy = crypto.load_policy(policy_file)
    repo = tmp_path / "repo"
    repo.mkdir()
    findings = crypto.evaluate(_inventory(_repo(repo)), policy, NOW)
    assert policy.name == "Strict"
    assert any(f.rule_id == "VW-CRYPTO-LEGACY-TLS" and f.path == "nginx.conf" for f in findings)
    assert any(f.rule_id == "VW-CRYPTO-SHORT-KEY" and f.path == "certs/healthy.pem" for f in findings)


def test_lifecycle_summary(tmp_path):
    assets = _inventory(_repo(tmp_path))
    summary = crypto.lifecycle(assets, crypto.CryptoPolicy(), NOW, ages={"certs/client.key": 900})
    statuses = {c["path"]: c["status"] for c in summary["certificates"]}
    assert statuses == {"certs/expiring.pem": "expiring", "certs/healthy.pem": "ok"}
    assert summary["certificates"][0]["path"] == "certs/expiring.pem"
    assert summary["rotation_due"][0]["path"] == "certs/client.key"
    assert summary["pqc_candidates"]["count"] >= 5 and "ML-KEM" in summary["pqc_candidates"]["recommendation"]
    assert "MD5" in summary["deprecated_algorithms"]


def test_cbom_validates_against_cyclonedx_1_6_schema(tmp_path):
    assets = _inventory(_repo(tmp_path))
    bom = crypto.to_cbom(assets, "demo", NOW)
    errors = JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(bom))
    assert errors is None, errors
    asset_types = {c.get("cryptoProperties", {}).get("assetType") for c in bom["components"]}
    assert {"algorithm", "certificate", "protocol", "related-crypto-material"} <= asset_types
    assert any(c["type"] == "library" and c["purl"] == "pkg:pypi/pycrypto@2.6.1" for c in bom["components"])


def test_key_age_falls_back_to_mtime(tmp_path):
    key_file = tmp_path / "old.key"
    key_file.write_text("x", encoding="utf-8")
    old = time.time() - 400 * 86400
    os.utime(key_file, (old, old))
    age = crypto.file_age_days(tmp_path, "old.key", datetime.now(UTC))
    assert age is not None and 399 <= age <= 401


def test_canonical_names():
    assert crypto.canonical("sha-1") == "SHA1"
    assert crypto.canonical("DESede") == "3DES"
    assert crypto.canonical("arc4") == "RC4"
    assert crypto.canonical("sha3_256") == "SHA3-256"
