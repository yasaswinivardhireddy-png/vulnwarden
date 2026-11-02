"""Cryptographic discovery, policy assurance, lifecycle intelligence and CycloneDX 1.6 CBOM export."""

from __future__ import annotations

import ast
import re
import subprocess
import uuid
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from pydantic import BaseModel, Field

from . import __version__
from .files import iter_files, read_text, redact_secrets, rel
from .models import Category, CryptoAsset, Finding, Severity
from .pyast import ImportMap, const_int, const_str, is_const, kwarg, line_at
from .scanners.dependencies import Dependency

# canonical algorithm -> (CycloneDX primitive, quantum-vulnerable)
ALGORITHMS: dict[str, tuple[str, bool]] = {
    "MD5": ("hash", False),
    "SHA1": ("hash", False),
    "SHA224": ("hash", False),
    "SHA256": ("hash", False),
    "SHA384": ("hash", False),
    "SHA512": ("hash", False),
    "SHA3-256": ("hash", False),
    "SHA3-512": ("hash", False),
    "BLAKE2B": ("hash", False),
    "BLAKE2S": ("hash", False),
    "DES": ("block-cipher", False),
    "3DES": ("block-cipher", False),
    "RC2": ("block-cipher", False),
    "RC4": ("stream-cipher", False),
    "BLOWFISH": ("block-cipher", False),
    "AES": ("block-cipher", False),
    "CHACHA20": ("stream-cipher", False),
    "RSA": ("pke", True),
    "DSA": ("signature", True),
    "EC": ("signature", True),
    "ECDSA": ("signature", True),
    "ECDH": ("key-agree", True),
    "DH": ("key-agree", True),
    "ED25519": ("signature", True),
    "ED448": ("signature", True),
}
_ALIASES = {
    "SHA": "SHA1",
    "TRIPLEDES": "3DES",
    "DESEDE": "3DES",
    "DES3": "3DES",
    "DESEDE3": "3DES",
    "ARC4": "RC4",
    "ARCFOUR": "RC4",
    "BF": "BLOWFISH",
    "AES128": "AES",
    "AES192": "AES",
    "AES256": "AES",
    "SHA3256": "SHA3-256",
    "SHA3512": "SHA3-512",
}
HASHLIB_FUNCS = {"md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_256", "sha3_512", "blake2b", "blake2s"}
CIPHER_MODES = {"ECB", "CBC", "CFB", "OFB", "CTR", "GCM", "CCM", "XTS", "EAX", "SIV", "OCB"}
CURVE_SIZES = {
    "SECP192R1": 192,
    "SECP224R1": 224,
    "SECP256R1": 256,
    "SECP384R1": 384,
    "SECP521R1": 521,
    "SECP256K1": 256,
    "BRAINPOOLP256R1": 256,
    "BRAINPOOLP384R1": 384,
    "BRAINPOOLP512R1": 512,
}
SSL_PROTOCOLS = {
    "ssl.PROTOCOL_SSLv2": ("ssl", "2.0"),
    "ssl.PROTOCOL_SSLv3": ("ssl", "3.0"),
    "ssl.PROTOCOL_TLSv1": ("tls", "1.0"),
    "ssl.PROTOCOL_TLSv1_1": ("tls", "1.1"),
    "ssl.PROTOCOL_TLSv1_2": ("tls", "1.2"),
    "ssl.TLSVersion.SSLv3": ("ssl", "3.0"),
    "ssl.TLSVersion.TLSv1": ("tls", "1.0"),
    "ssl.TLSVersion.TLSv1_1": ("tls", "1.1"),
    "ssl.TLSVersion.TLSv1_2": ("tls", "1.2"),
    "ssl.TLSVersion.TLSv1_3": ("tls", "1.3"),
}
CERT_SUFFIXES = {".pem", ".crt", ".cer", ".der", ".cert"}
KEY_SUFFIXES = {".key"}
CONFIG_SUFFIXES = {".conf", ".cfg", ".properties", ".yml", ".yaml", ".ini", ".config"}
OTHER_LANGUAGES = {".java", ".kt", ".scala", ".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".go", ".cs"}
PRIVATE_KEY = re.compile(
    r"-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----.*?-----END \1-----", re.S
)
PASSWORD_CONTEXT = re.compile(r"(?i)(password|passwd|pwd|passphrase)")
CRYPTO_LIBRARIES: dict[str, dict[str, str | None]] = {
    "PyPI": {
        "cryptography": None,
        "pycryptodome": None,
        "pycryptodomex": None,
        "pyopenssl": None,
        "pynacl": None,
        "bcrypt": None,
        "passlib": None,
        "rsa": None,
        "m2crypto": None,
        "pyjwt": None,
        "python-jose": None,
        "paramiko": None,
        "ecdsa": "python-ecdsa is not hardened against side-channel attacks.",
        "pycrypto": "PyCrypto has been unmaintained since 2013 and has unfixed CVEs; migrate to pycryptodome.",
    },
    "npm": {
        "node-forge": None,
        "jsonwebtoken": None,
        "bcrypt": None,
        "elliptic": None,
        "tweetnacl": None,
        "crypto-js": "crypto-js is discontinued; use the Web Crypto API or node:crypto.",
    },
}


def canonical(name: str) -> str:
    key = name.upper().replace("_", "").replace("-", "")
    if key in _ALIASES:
        return _ALIASES[key]
    for algorithm in ALGORITHMS:
        if key == algorithm.replace("-", ""):
            return algorithm
    return name.upper()


def _asset(
    asset_type: str,
    name: str,
    path: str,
    line: int | None,
    evidence: str,
    *,
    algorithm: str | None = None,
    primitive: str | None = None,
    key_size: int | None = None,
    mode: str | None = None,
    details: dict[str, Any] | None = None,
) -> CryptoAsset:
    info = dict(details or {})
    if algorithm:
        info.setdefault("algorithm", algorithm)
        primitive = primitive or ALGORITHMS.get(algorithm, ("other", False))[0]
    quantum = ALGORITHMS.get(algorithm or "", ("", False))[1] or bool(info.get("quantum_vulnerable"))
    return CryptoAsset(
        asset_type=asset_type,
        name=name,
        path=path,
        line=line,
        primitive=primitive,
        key_size=key_size,
        mode=mode,
        evidence=redact_secrets(evidence)[:200],
        quantum_vulnerable=quantum,
        details=info,
    )


# ------------------------------------------------------------------ Python
class _PythonCrypto(ast.NodeVisitor):
    def __init__(self, imports: ImportMap, lines: list[str], path: str) -> None:
        self.imports, self.lines, self.path = imports, lines, path
        self.assets: list[CryptoAsset] = []
        self._functions: list[str] = []
        self._handled: set[int] = set()

    def _add(self, node: ast.AST, asset_type: str, name: str, **kwargs: Any) -> None:
        line = getattr(node, "lineno", None)
        self.assets.append(_asset(asset_type, name, self.path, line, line_at(self.lines, line), **kwargs))

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._functions.append(node.name)
        self.generic_visit(node)
        self._functions.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def _context(self, node: ast.Call) -> str:
        text = " ".join([*(ast.unparse(a) for a in node.args), *self._functions[-1:]])
        return "password" if PASSWORD_CONTEXT.search(text) else "general"

    def _last(self, node: ast.AST | None) -> str:
        target = node.func if isinstance(node, ast.Call) else node
        return (self.imports.qualname(target) or "").split(".")[-1] if target is not None else ""

    def visit_Call(self, node: ast.Call) -> None:
        qual = self.imports.qualname(node.func) or ""
        parts = qual.split(".")
        if parts[0] == "hashlib" and len(parts) == 2 and id(node) not in self._handled:
            name = parts[1] if parts[1] in HASHLIB_FUNCS else None
            if parts[1] == "new":
                name = const_str(node.args[0]) if node.args else const_str(kwarg(node, "name"))
            if name:
                algorithm = canonical(name)
                self._add(
                    node,
                    "algorithm",
                    algorithm,
                    algorithm=algorithm,
                    details={
                        "api": qual,
                        "context": self._context(node),
                        "usedforsecurity": not is_const(kwarg(node, "usedforsecurity"), False),
                    },
                )
        elif qual == "hmac.new":
            digest = kwarg(node, "digestmod") or (node.args[2] if len(node.args) > 2 else None)
            name = const_str(digest) or self._last(digest)
            if name:
                algorithm = canonical(name)
                self._handled.add(id(digest))
                self._add(
                    node, "algorithm", f"HMAC-{algorithm}", algorithm=algorithm, primitive="mac", details={"api": qual}
                )
        elif len(parts) >= 4 and parts[0] in {"Crypto", "Cryptodome"} and parts[-1] in {"new", "generate"}:
            algorithm = canonical(parts[2])
            if parts[1] == "Cipher":
                mode_node = node.args[1] if len(node.args) > 1 else kwarg(node, "mode")
                match = re.search(r"MODE_([A-Z0-9]+)$", self.imports.qualname(mode_node) or "") if mode_node else None
                mode = match.group(1) if match else None
                name = f"{algorithm}-{mode}" if mode else algorithm
                self._add(node, "algorithm", name, algorithm=algorithm, mode=mode, details={"api": qual})
            elif parts[1] == "Hash":
                self._add(
                    node, "algorithm", algorithm, algorithm=algorithm, details={"api": qual, "context": "general"}
                )
            elif parts[1] == "PublicKey":
                bits = const_int(node.args[0]) if node.args else const_int(kwarg(node, "bits"))
                self._add(
                    node,
                    "algorithm",
                    f"{algorithm}-{bits}" if bits else algorithm,
                    algorithm=algorithm,
                    key_size=bits,
                    details={"api": qual},
                )
        elif qual.endswith("primitives.ciphers.Cipher"):
            alg_node = node.args[0] if node.args else kwarg(node, "algorithm")
            mode_node = node.args[1] if len(node.args) > 1 else kwarg(node, "mode")
            algorithm = canonical(self._last(alg_node)) if alg_node is not None else "UNKNOWN"
            mode = self._last(mode_node).upper() if mode_node is not None else None
            self._handled.update({id(alg_node), id(mode_node)})
            name = f"{algorithm}-{mode}" if mode else algorithm
            self._add(node, "algorithm", name, algorithm=algorithm, mode=mode, details={"api": qual})
        elif ".ciphers.algorithms." in qual and id(node) not in self._handled:
            algorithm = canonical(parts[-1])
            self._add(node, "algorithm", algorithm, algorithm=algorithm, details={"api": qual})
        elif ".primitives.hashes." in qual and id(node) not in self._handled:
            algorithm = canonical(parts[-1])
            self._add(node, "algorithm", algorithm, algorithm=algorithm, details={"api": qual, "context": "general"})
        elif qual.endswith("asymmetric.rsa.generate_private_key") or qual.endswith(
            "asymmetric.dsa.generate_private_key"
        ):
            algorithm = "RSA" if ".rsa." in qual else "DSA"
            size_node = kwarg(node, "key_size")
            if size_node is None and node.args:
                size_node = node.args[1] if algorithm == "RSA" and len(node.args) > 1 else node.args[0]
            size = const_int(size_node)
            self._add(
                node,
                "algorithm",
                f"{algorithm}-{size}" if size else algorithm,
                algorithm=algorithm,
                key_size=size,
                details={"api": qual},
            )
        elif qual.endswith("asymmetric.ec.generate_private_key"):
            curve_node = node.args[0] if node.args else kwarg(node, "curve")
            curve = self._last(curve_node).upper()
            self._add(
                node,
                "algorithm",
                f"ECDSA-{curve}",
                algorithm="ECDSA",
                key_size=CURVE_SIZES.get(curve),
                details={"api": qual, "curve": curve},
            )
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        qual = self.imports.qualname(node) or ""
        if qual in SSL_PROTOCOLS:
            family, version = SSL_PROTOCOLS[qual]
            self._add(node, "protocol", f"{family.upper()} {version}", details={"protocol": family, "version": version})
        self.generic_visit(node)


def _python_assets(text: str, path: str) -> list[CryptoAsset]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    visitor = _PythonCrypto(ImportMap(tree), text.splitlines(), path)
    visitor.visit(tree)
    return visitor.assets


# ------------------------------------------------------- other languages
def _cipher_spec(spec: str, separator: str) -> tuple[str, str | None, int | None]:
    tokens = [t for t in spec.upper().split(separator) if t]
    key_size = next((int(t) for t in tokens if t.isdigit() and int(t) in {128, 192, 256}), None)
    mode = next((t for t in tokens if t in CIPHER_MODES), None)
    head = tokens[0] if tokens else spec.upper()
    if head == "DES" and any(t in {"EDE", "EDE3"} for t in tokens):
        head = "3DES"
    return canonical(head), mode, key_size


def _other_language_assets(text: str, path: str, suffix: str) -> list[CryptoAsset]:
    assets: list[CryptoAsset] = []
    lines = text.splitlines()

    def add(match: re.Match[str], asset_type: str, name: str, **kwargs: Any) -> None:
        line = text.count("\n", 0, match.start()) + 1
        assets.append(_asset(asset_type, name, path, line, line_at(lines, line), **kwargs))

    def window(match: re.Match[str], size: int = 600) -> str:
        return text[match.end() : match.end() + size]

    if suffix in {".java", ".kt", ".scala"}:
        for m in re.finditer(r'MessageDigest\.getInstance\(\s*"([\w-]+)"', text):
            algorithm = canonical(m.group(1))
            add(m, "algorithm", algorithm, algorithm=algorithm, details={"context": "general"})
        for m in re.finditer(r'Cipher\.getInstance\(\s*"([\w-]+)(?:/(\w+))?(?:/(\w+))?"', text):
            algorithm, mode = canonical(m.group(1)), (m.group(2) or "").upper() or None
            details = {}
            if mode is None and algorithm in {"AES", "DES", "3DES", "BLOWFISH"}:
                mode, details = "ECB", {"implicit_mode": "Java defaults to ECB when no mode is given"}
            add(
                m,
                "algorithm",
                f"{algorithm}-{mode}" if mode else algorithm,
                algorithm=algorithm,
                mode=mode,
                details=details,
            )
        for m in re.finditer(r'KeyPairGenerator\.getInstance\(\s*"(RSA|DSA|EC|DH)"', text):
            size = re.search(r"\.initialize\(\s*(\d+)", window(m))
            algorithm = canonical(m.group(1))
            bits = int(size.group(1)) if size else None
            add(m, "algorithm", f"{algorithm}-{bits}" if bits else algorithm, algorithm=algorithm, key_size=bits)
        for m in re.finditer(r'SSLContext\.getInstance\(\s*"(SSLv3|TLSv1(?:\.[123])?)"', text):
            family, version = _protocol_token(m.group(1)) or ("tls", "1.0")
            add(m, "protocol", f"{family.upper()} {version}", details={"protocol": family, "version": version})
        for m in re.finditer(r'Signature\.getInstance\(\s*"(\w+)with(RSA|DSA|ECDSA)"', text):
            digest, algorithm = canonical(m.group(1)), canonical(m.group(2))
            add(
                m,
                "algorithm",
                f"{algorithm}-{digest}",
                algorithm=algorithm,
                primitive="signature",
                details={"hash": digest},
            )
    elif suffix in {".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx"}:
        for m in re.finditer(r"""createHash\(\s*['"]([\w-]+)['"]""", text):
            algorithm = canonical(m.group(1))
            add(m, "algorithm", algorithm, algorithm=algorithm, details={"context": "general"})
        for m in re.finditer(r"""createHmac\(\s*['"]([\w-]+)['"]""", text):
            algorithm = canonical(m.group(1))
            add(m, "algorithm", f"HMAC-{algorithm}", algorithm=algorithm, primitive="mac")
        for m in re.finditer(r"""createCipher(?:iv)?\(\s*['"]([\w-]+)['"]""", text):
            algorithm, mode, size = _cipher_spec(m.group(1), "-")
            add(
                m,
                "algorithm",
                f"{algorithm}-{mode}" if mode else algorithm,
                algorithm=algorithm,
                mode=mode,
                key_size=size,
            )
        for m in re.finditer(r"""generateKeyPair(?:Sync)?\(\s*['"](rsa|dsa|ec)['"]""", text):
            size = re.search(r"modulusLength\s*:\s*(\d+)", window(m, 300))
            algorithm = canonical(m.group(1))
            bits = int(size.group(1)) if size else None
            add(m, "algorithm", f"{algorithm}-{bits}" if bits else algorithm, algorithm=algorithm, key_size=bits)
        for m in re.finditer(r"""(?:minVersion|maxVersion)\s*:\s*['"](TLSv1(?:\.[123])?)['"]""", text):
            family, version = _protocol_token(m.group(1)) or ("tls", "1.0")
            add(m, "protocol", f"TLS {version}", details={"protocol": family, "version": version})
    elif suffix == ".go":
        for m in re.finditer(r"\b(md5|sha1|sha256|sha512)\.(?:New|Sum\w*)\(", text):
            algorithm = canonical(m.group(1))
            add(m, "algorithm", algorithm, algorithm=algorithm, details={"context": "general"})
        for m in re.finditer(r"\b(des|rc4)\.New(TripleDES)?Cipher\(", text):
            algorithm = "3DES" if m.group(2) else canonical(m.group(1))
            add(m, "algorithm", algorithm, algorithm=algorithm)
        for m in re.finditer(r"rsa\.GenerateKey\(\s*[\w.]+\s*,\s*(\d+)\s*\)", text):
            add(m, "algorithm", f"RSA-{m.group(1)}", algorithm="RSA", key_size=int(m.group(1)))
        for m in re.finditer(r"tls\.Version(TLS1[0-3]|SSL30)\b", text):
            token = {"TLS10": "1.0", "TLS11": "1.1", "TLS12": "1.2", "TLS13": "1.3"}.get(m.group(1))
            family, version = ("tls", token) if token else ("ssl", "3.0")
            add(m, "protocol", f"{family.upper()} {version}", details={"protocol": family, "version": version})
    elif suffix == ".cs":
        for m in re.finditer(r"\b(MD5|SHA1|DES|TripleDES|RC2)\.Create\(", text):
            algorithm = canonical(m.group(1))
            add(m, "algorithm", algorithm, algorithm=algorithm, details={"context": "general"})
        for m in re.finditer(r"new\s+(MD5|SHA1|DES|TripleDES|RC2)(?:CryptoServiceProvider|Managed)\(", text):
            algorithm = canonical(m.group(1))
            add(m, "algorithm", algorithm, algorithm=algorithm, details={"context": "general"})
        for m in re.finditer(r"new\s+RSACryptoServiceProvider\(\s*(\d+)\s*\)", text):
            add(m, "algorithm", f"RSA-{m.group(1)}", algorithm="RSA", key_size=int(m.group(1)))
        for m in re.finditer(r"SslProtocols\.(Ssl3|Tls11|Tls)\b", text):
            family, version = {"Ssl3": ("ssl", "3.0"), "Tls": ("tls", "1.0"), "Tls11": ("tls", "1.1")}[m.group(1)]
            add(m, "protocol", f"{family.upper()} {version}", details={"protocol": family, "version": version})
    return assets


# ------------------------------------------------------------ TLS config
def _protocol_token(token: str) -> tuple[str, str] | None:
    token = token.strip().strip("'\"").lstrip("+")
    table = {
        "SSLV2": ("ssl", "2.0"),
        "SSLV3": ("ssl", "3.0"),
        "TLSV1": ("tls", "1.0"),
        "TLSV1.0": ("tls", "1.0"),
        "TLSV1.1": ("tls", "1.1"),
        "TLSV1.2": ("tls", "1.2"),
        "TLSV1.3": ("tls", "1.3"),
    }
    return table.get(token.upper())


WEAK_SUITE_MARKERS = {
    "RC4": "RC4",
    "DES-CBC3": "3DES",
    "3DES": "3DES",
    "DES-CBC": "DES",
    "MD5": "MD5",
    "NULL": "NULL",
    "EXPORT": "EXPORT",
    "EXP-": "EXPORT",
}


def _config_assets(text: str, path: str) -> list[CryptoAsset]:
    assets: list[CryptoAsset] = []
    lines = text.splitlines()
    patterns = [
        (re.compile(r"^\s*ssl_protocols\s+([^;]+);", re.M), " "),
        (re.compile(r"^\s*SSLProtocol\s+(.+)$", re.M | re.I), " "),
        (re.compile(r"enabled-protocols\s*[=:]\s*\[?([^\n\]]+)", re.I), ","),
    ]
    for pattern, separator in patterns:
        for m in pattern.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            for token in m.group(1).replace(",", separator).split(separator):
                if token.strip().startswith("-") or not token.strip():
                    continue
                parsed = _protocol_token(token)
                if token.strip().lower() == "all":
                    parsed = ("tls", "1.0")
                if parsed:
                    family, version = parsed
                    assets.append(
                        _asset(
                            "protocol",
                            f"{family.upper()} {version}",
                            path,
                            line,
                            line_at(lines, line),
                            details={"protocol": family, "version": version, "source": "config"},
                        )
                    )
    for m in re.finditer(r"^\s*(?:ssl_ciphers|SSLCipherSuite)\s+['\"]?([^;'\"\n]+)", text, re.M | re.I):
        line = text.count("\n", 0, m.start()) + 1
        for token in re.split(r"[:\s]+", m.group(1)):
            if not token or token.startswith(("!", "-")):
                continue
            for marker, algorithm in WEAK_SUITE_MARKERS.items():
                if marker in token.upper():
                    assets.append(
                        _asset(
                            "algorithm",
                            algorithm,
                            path,
                            line,
                            line_at(lines, line),
                            algorithm=canonical(algorithm) if algorithm in {"RC4", "3DES", "DES", "MD5"} else None,
                            primitive="other",
                            details={"suite": token, "source": "tls-cipher-suite"},
                        )
                    )
                    break
    return assets


# ------------------------------------------------------ certificates/keys
def _describe_key(key: Any) -> tuple[str | None, int | None, str | None]:
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size, None
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "ECDSA", key.curve.key_size, key.curve.name.upper()
    if isinstance(key, dsa.DSAPublicKey):
        return "DSA", key.key_size, None
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "ED25519", 256, None
    if isinstance(key, ed448.Ed448PublicKey):
        return "ED448", 456, None
    return None, None, None


def _certificate_assets(data: bytes, path: str) -> list[CryptoAsset]:
    certificates: list[x509.Certificate] = []
    lines_offsets: list[int] = []
    try:
        if b"-----BEGIN CERTIFICATE-----" in data:
            certificates = x509.load_pem_x509_certificates(data)
            text = data.decode("utf-8", errors="replace")
            lines_offsets = [
                text.count("\n", 0, m.start()) + 1 for m in re.finditer("-----BEGIN CERTIFICATE-----", text)
            ]
        elif Path(path).suffix.lower() in {".der", ".cer", ".crt"}:
            certificates = [x509.load_der_x509_certificate(data)]
    except ValueError:
        return []
    assets: list[CryptoAsset] = []
    for index, cert in enumerate(certificates):
        subject, issuer = cert.subject.rfc4514_string(), cert.issuer.rfc4514_string()
        names = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        common_name = str(names[0].value) if names else subject or "certificate"
        algorithm, size, curve = _describe_key(cert.public_key())
        signature_hash = cert.signature_hash_algorithm.name.upper() if cert.signature_hash_algorithm else None
        not_before, not_after = cert.not_valid_before_utc, cert.not_valid_after_utc
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        assets.append(
            _asset(
                "certificate",
                common_name,
                path,
                lines_offsets[index] if index < len(lines_offsets) else None,
                f"{common_name} (sha256:{fingerprint[:16]})",
                key_size=size,
                primitive="signature",
                details={
                    "subject": subject,
                    "issuer": issuer,
                    "serial": format(cert.serial_number, "x"),
                    "not_before": not_before.isoformat(),
                    "not_after": not_after.isoformat(),
                    "signature_hash": canonical(signature_hash) if signature_hash else None,
                    "public_key_algorithm": algorithm,
                    "curve": curve,
                    "self_signed": subject == issuer,
                    "validity_days": (not_after - not_before).days,
                    "sha256_fingerprint": fingerprint,
                    "quantum_vulnerable": algorithm in {"RSA", "ECDSA", "DSA", "ED25519", "ED448"},
                },
            )
        )
    return assets


def _private_key_assets(text: str, path: str) -> list[CryptoAsset]:
    assets: list[CryptoAsset] = []
    for m in PRIVATE_KEY.finditer(text):
        label = m.group(1)
        encrypted = label.startswith("ENCRYPTED")
        algorithm = size = None
        if not encrypted:
            try:
                if label.startswith("OPENSSH"):
                    key = serialization.load_ssh_private_key(m.group(0).encode(), password=None)
                else:
                    key = serialization.load_pem_private_key(m.group(0).encode(), password=None)
                algorithm, size, _ = _describe_key(key.public_key())
            except (ValueError, TypeError):
                pass
        line = text.count("\n", 0, m.start()) + 1
        assets.append(
            _asset(
                "related-crypto-material",
                f"{algorithm or 'unknown'} private key",
                path,
                line,
                f"-----BEGIN {label}----- (key material redacted)",
                key_size=size,
                algorithm=algorithm,
                primitive="other",
                details={"encrypted": encrypted, "format": "OpenSSH" if label.startswith("OPENSSH") else "PEM"},
            )
        )
    return assets


def _library_assets(deps: list[Dependency]) -> list[CryptoAsset]:
    assets: list[CryptoAsset] = []
    for dep in deps:
        known = CRYPTO_LIBRARIES.get(dep.ecosystem, {})
        key = dep.name.lower().replace("_", "-")
        if key in known:
            assets.append(
                _asset(
                    "library",
                    dep.name,
                    dep.path,
                    dep.line,
                    dep.spec,
                    details={
                        "ecosystem": dep.ecosystem,
                        "version": dep.version,
                        "deprecated_reason": known[key],
                    },
                )
            )
    return assets


def discover(root: Path, exclude: list[str], deps: list[Dependency] | None = None) -> list[CryptoAsset]:
    """Inventory cryptographic assets across code, configs, certificates, keys and dependencies."""
    assets: list[CryptoAsset] = []
    for file in iter_files(root, exclude):
        suffix = file.suffix.lower()
        path = rel(root, file)
        if suffix in CERT_SUFFIXES:
            try:
                assets.extend(_certificate_assets(file.read_bytes(), path))
            except OSError:
                continue
        text = read_text(file)
        if text is None:
            continue
        if suffix == ".py":
            assets.extend(_python_assets(text, path))
        elif suffix in OTHER_LANGUAGES:
            assets.extend(_other_language_assets(text, path, suffix))
        if suffix in CONFIG_SUFFIXES or file.name in {"nginx.conf", "httpd.conf", "ssl.conf"}:
            assets.extend(_config_assets(text, path))
        if "PRIVATE KEY-----" in text:
            assets.extend(_private_key_assets(text, path))
    assets.extend(_library_assets(deps or []))
    return assets


def file_age_days(root: Path, path: str, now: datetime) -> float | None:
    """Age of a file from its last git commit (falls back to filesystem mtime)."""
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "log", "-1", "--format=%ct", "--", path],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        stamp = float(result.stdout.strip()) if result.returncode == 0 and result.stdout.strip() else None
    except (OSError, ValueError, subprocess.TimeoutExpired):
        stamp = None
    if stamp is None:
        try:
            stamp = (root / path).stat().st_mtime
        except OSError:
            return None
    return max(0.0, (now.timestamp() - stamp) / 86400)


# ------------------------------------------------------------------ policy
class CryptoPolicy(BaseModel):
    name: str = "Baseline cryptography standard"
    disallowed_algorithms: list[str] = Field(
        default_factory=lambda: ["MD5", "SHA1", "DES", "3DES", "RC4", "RC2", "BLOWFISH"]
    )
    disallowed_modes: list[str] = Field(default_factory=lambda: ["ECB"])
    min_key_sizes: dict[str, int] = Field(
        default_factory=lambda: {"RSA": 2048, "DSA": 2048, "EC": 256, "ECDSA": 256, "DH": 2048}
    )
    min_tls_version: str = "1.2"
    cert_expiry_warning_days: int = 30
    cert_max_validity_days: int = 398
    disallowed_signature_hashes: list[str] = Field(default_factory=lambda: ["MD5", "SHA1"])
    flag_self_signed: bool = True
    forbid_private_keys_in_repo: bool = True
    key_rotation_days: int = 365
    deprecated_libraries: dict[str, list[str]] = Field(
        default_factory=lambda: {"PyPI": ["pycrypto"], "npm": ["crypto-js"]}
    )


def load_policy(path: str | Path | None) -> CryptoPolicy:
    if not path:
        return CryptoPolicy()
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return CryptoPolicy.model_validate(data)


def _version_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", version))


def _crypto_finding(
    rule_id: str, title: str, severity: Severity, cwe: str, asset: CryptoAsset, message: str, hint: str
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        category=Category.CRYPTO,
        severity=severity,
        source="vulnwarden-crypto",
        path=asset.path,
        line=asset.line,
        message=message,
        snippet=asset.evidence,
        cwe=[cwe],
        fix_hint=hint,
        sources=["vulnwarden-crypto"],
        details={
            "asset": asset.name,
            "asset_type": asset.asset_type,
            **{
                k: v for k, v in asset.details.items() if k in {"context", "suite", "not_after", "algorithm", "version"}
            },
        },
    )


def evaluate(
    assets: list[CryptoAsset], policy: CryptoPolicy, now: datetime | None = None, ages: dict[str, float] | None = None
) -> list[Finding]:
    """Evaluate the inventory against an enterprise crypto policy and return violations."""
    now = now or datetime.now(UTC)
    ages = ages or {}
    disallowed = {canonical(a) for a in policy.disallowed_algorithms}
    weak_signatures = {canonical(a) for a in policy.disallowed_signature_hashes}
    deprecated = {eco: {n.lower() for n in names} for eco, names in policy.deprecated_libraries.items()}
    minimum_tls = _version_tuple(policy.min_tls_version)
    findings: list[Finding] = []
    for asset in assets:
        algorithm = asset.details.get("algorithm")
        if asset.asset_type == "algorithm":
            if asset.details.get("source") == "tls-cipher-suite":
                findings.append(
                    _crypto_finding(
                        "VW-CRYPTO-WEAK-TLS-CIPHER",
                        "Weak TLS cipher suite enabled",
                        Severity.MEDIUM,
                        "CWE-327",
                        asset,
                        f"Cipher suite '{asset.details.get('suite')}' uses {asset.name}.",
                        "Remove RC4, 3DES, NULL, EXPORT and MD5 suites; prefer AES-GCM and ChaCha20-Poly1305.",
                    )
                )
                continue
            if asset.primitive in {"hash", "mac"} and algorithm in disallowed:
                if asset.details.get("usedforsecurity") is False:
                    continue
                password = asset.details.get("context") == "password"
                findings.append(
                    _crypto_finding(
                        "VW-CRYPTO-WEAK-HASH",
                        "Weak hash algorithm" + (" for passwords" if password else ""),
                        Severity.HIGH if password else Severity.MEDIUM,
                        "CWE-916" if password else "CWE-328",
                        asset,
                        f"{asset.name} is disallowed by policy '{policy.name}'.",
                        "Hash passwords with hashlib.scrypt, PBKDF2-HMAC-SHA256 (600k+ iterations), bcrypt or Argon2."
                        if password
                        else "Use SHA-256 or stronger.",
                    )
                )
            elif asset.primitive in {"block-cipher", "stream-cipher"} and algorithm in disallowed:
                findings.append(
                    _crypto_finding(
                        "VW-CRYPTO-WEAK-CIPHER",
                        "Weak or broken cipher",
                        Severity.HIGH,
                        "CWE-327",
                        asset,
                        f"{algorithm} is disallowed by policy '{policy.name}'.",
                        "Use AES-256-GCM or ChaCha20-Poly1305.",
                    )
                )
            if asset.mode and asset.mode.upper() in {m.upper() for m in policy.disallowed_modes}:
                findings.append(
                    _crypto_finding(
                        "VW-CRYPTO-ECB-MODE",
                        "Insecure block cipher mode (ECB)",
                        Severity.HIGH,
                        "CWE-327",
                        asset,
                        f"{asset.name} leaks plaintext patterns. {asset.details.get('implicit_mode', '')}".strip(),
                        "Use an authenticated mode such as GCM with a unique nonce per message.",
                    )
                )
            if asset.primitive == "signature" and asset.details.get("hash") in weak_signatures:
                findings.append(
                    _crypto_finding(
                        "VW-CRYPTO-WEAK-SIGNATURE",
                        "Signature uses a weak hash",
                        Severity.MEDIUM,
                        "CWE-327",
                        asset,
                        f"{asset.name} signs with {asset.details.get('hash')}.",
                        "Sign with SHA-256 or stronger.",
                    )
                )
        if asset.asset_type == "protocol":
            version = asset.details.get("version", "")
            if asset.details.get("protocol") == "ssl" or _version_tuple(version) < minimum_tls:
                findings.append(
                    _crypto_finding(
                        "VW-CRYPTO-LEGACY-TLS",
                        "Legacy TLS/SSL protocol version enabled",
                        Severity.HIGH,
                        "CWE-327",
                        asset,
                        f"{asset.name} is below the policy minimum of TLS {policy.min_tls_version}.",
                        "Allow only TLS 1.2 and TLS 1.3.",
                    )
                )
        if asset.key_size and algorithm in policy.min_key_sizes and asset.key_size < policy.min_key_sizes[algorithm]:
            findings.append(
                _crypto_finding(
                    "VW-CRYPTO-SHORT-KEY",
                    "Key too short",
                    Severity.HIGH,
                    "CWE-326",
                    asset,
                    f"{algorithm} {asset.key_size}-bit key is below the {policy.min_key_sizes[algorithm]}-bit minimum.",
                    f"Use at least {policy.min_key_sizes[algorithm]} bits (RSA 3072 for use beyond 2030).",
                )
            )
        if asset.asset_type == "certificate":
            details = asset.details
            public_key = details.get("public_key_algorithm")
            if (
                asset.key_size
                and public_key in policy.min_key_sizes
                and asset.key_size < policy.min_key_sizes[public_key]
            ):
                findings.append(
                    _crypto_finding(
                        "VW-CRYPTO-SHORT-KEY",
                        "Certificate key too short",
                        Severity.HIGH,
                        "CWE-326",
                        asset,
                        f"{public_key} {asset.key_size}-bit certificate key is below policy.",
                        "Re-issue with RSA 2048+ or P-256.",
                    )
                )
            days_left = (datetime.fromisoformat(details["not_after"]) - now).days
            if days_left < 0:
                findings.append(
                    _crypto_finding(
                        "VW-CERT-EXPIRED",
                        "Certificate expired",
                        Severity.HIGH,
                        "CWE-324",
                        asset,
                        f"Expired {-days_left} days ago ({details['not_after'][:10]}).",
                        "Renew and redeploy the certificate.",
                    )
                )
            elif days_left <= policy.cert_expiry_warning_days:
                findings.append(
                    _crypto_finding(
                        "VW-CERT-EXPIRING",
                        "Certificate expiring soon",
                        Severity.HIGH if days_left <= 7 else Severity.MEDIUM,
                        "CWE-324",
                        asset,
                        f"Expires in {days_left} days ({details['not_after'][:10]}).",
                        "Renew before expiry; automate renewal (ACME) where possible.",
                    )
                )
            if details.get("signature_hash") in weak_signatures:
                findings.append(
                    _crypto_finding(
                        "VW-CERT-WEAK-SIGNATURE",
                        "Certificate signed with a weak hash",
                        Severity.HIGH,
                        "CWE-327",
                        asset,
                        f"Signed with {details['signature_hash']}.",
                        "Re-issue with a SHA-256 signature.",
                    )
                )
            if details.get("validity_days", 0) > policy.cert_max_validity_days:
                findings.append(
                    _crypto_finding(
                        "VW-CERT-LONG-VALIDITY",
                        "Certificate validity too long",
                        Severity.LOW,
                        "CWE-324",
                        asset,
                        f"Valid for {details['validity_days']} days (policy max {policy.cert_max_validity_days}).",
                        "Issue shorter-lived certificates and automate renewal.",
                    )
                )
            if policy.flag_self_signed and details.get("self_signed"):
                findings.append(
                    _crypto_finding(
                        "VW-CERT-SELF-SIGNED",
                        "Self-signed certificate",
                        Severity.LOW,
                        "CWE-295",
                        asset,
                        "Self-signed certificates cannot be validated by clients.",
                        "Use a certificate from a trusted CA.",
                    )
                )
            age = (now - datetime.fromisoformat(details["not_before"])).days
            if age > policy.key_rotation_days:
                findings.append(
                    _crypto_finding(
                        "VW-CRYPTO-ROTATION-DUE",
                        "Certificate key rotation overdue",
                        Severity.MEDIUM,
                        "CWE-324",
                        asset,
                        f"Key in use for {age} days (policy {policy.key_rotation_days}).",
                        "Re-key and re-issue.",
                    )
                )
        if asset.asset_type == "related-crypto-material" and policy.forbid_private_keys_in_repo:
            encrypted = asset.details.get("encrypted")
            findings.append(
                _crypto_finding(
                    "VW-CRYPTO-PRIVATE-KEY",
                    "Private key committed to the repository",
                    Severity.HIGH if encrypted else Severity.CRITICAL,
                    "CWE-321",
                    asset,
                    f"{asset.name} is stored in source control{' (encrypted)' if encrypted else ' unencrypted'}.",
                    "Revoke and rotate the key, purge it from git history and load it from a secret manager.",
                )
            )
            age = ages.get(asset.path)
            if age is not None and age > policy.key_rotation_days:
                findings.append(
                    _crypto_finding(
                        "VW-CRYPTO-ROTATION-DUE",
                        "Key rotation overdue",
                        Severity.MEDIUM,
                        "CWE-324",
                        asset,
                        f"Key unchanged for {int(age)} days (policy {policy.key_rotation_days}).",
                        "Rotate the key.",
                    )
                )
        if asset.asset_type == "library":
            ecosystem = asset.details.get("ecosystem", "")
            if asset.name.lower() in deprecated.get(ecosystem, set()):
                findings.append(
                    _crypto_finding(
                        "VW-CRYPTO-DEPRECATED-LIB",
                        "Deprecated cryptography library",
                        Severity.HIGH,
                        "CWE-1104",
                        asset,
                        asset.details.get("deprecated_reason") or f"{asset.name} is deprecated by policy.",
                        "Migrate to a maintained library such as cryptography or pycryptodome.",
                    )
                )
    return findings


# --------------------------------------------------------------- lifecycle
def lifecycle(
    assets: list[CryptoAsset], policy: CryptoPolicy, now: datetime | None = None, ages: dict[str, float] | None = None
) -> dict[str, Any]:
    now = now or datetime.now(UTC)
    ages = ages or {}
    disallowed = {canonical(a) for a in policy.disallowed_algorithms}
    certificates = []
    for asset in assets:
        if asset.asset_type != "certificate":
            continue
        days_left = (datetime.fromisoformat(asset.details["not_after"]) - now).days
        status = "expired" if days_left < 0 else "expiring" if days_left <= policy.cert_expiry_warning_days else "ok"
        certificates.append(
            {
                "name": asset.name,
                "path": asset.path,
                "not_after": asset.details["not_after"][:10],
                "days_left": days_left,
                "status": status,
            }
        )
    deprecated = Counter(
        a.name
        for a in assets
        if a.asset_type == "algorithm"
        and (
            a.details.get("algorithm") in disallowed
            or (a.mode or "").upper() in {m.upper() for m in policy.disallowed_modes}
        )
    )
    rotation_due = [
        {"name": a.name, "path": a.path, "age_days": int(ages[a.path])}
        for a in assets
        if a.asset_type == "related-crypto-material" and ages.get(a.path, 0) > policy.key_rotation_days
    ]
    quantum = Counter(
        a.details.get("algorithm") or a.details.get("public_key_algorithm") or a.name
        for a in assets
        if a.quantum_vulnerable
    )
    return {
        "certificates": sorted(certificates, key=lambda c: c["days_left"]),
        "deprecated_algorithms": dict(sorted(deprecated.items())),
        "rotation_due": rotation_due,
        "pqc_candidates": {
            "count": sum(quantum.values()),
            "by_algorithm": dict(sorted(quantum.items())),
            "recommendation": "Plan migration to ML-KEM (FIPS 203) for key establishment and ML-DSA (FIPS 204) "
            "for signatures; prefer hybrid modes during transition.",
        },
    }


# --------------------------------------------------------------------- CBOM
_PRIMITIVES = {
    "drbg",
    "mac",
    "block-cipher",
    "stream-cipher",
    "signature",
    "hash",
    "pke",
    "xof",
    "kdf",
    "key-agree",
    "kem",
    "ae",
    "combiner",
    "other",
    "unknown",
}
_MODES = {"cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr"}


def to_cbom(assets: list[CryptoAsset], repo_name: str, now: datetime | None = None) -> dict[str, Any]:
    """Export the inventory as a CycloneDX 1.6 Cryptography Bill of Materials."""
    now = now or datetime.now(UTC)
    groups: dict[tuple[Any, ...], list[CryptoAsset]] = {}
    for asset in assets:
        key = (
            asset.asset_type,
            asset.name,
            asset.key_size,
            asset.mode,
            asset.details.get("sha256_fingerprint"),
            asset.details.get("version"),
        )
        groups.setdefault(key, []).append(asset)
    components: list[dict[str, Any]] = []
    for index, group in enumerate(groups.values(), start=1):
        asset = group[0]
        occurrences = [{"location": a.path, **({"line": a.line} if a.line else {})} for a in group]
        component: dict[str, Any] = {
            "bom-ref": f"crypto-{index}",
            "name": asset.name,
            "evidence": {"occurrences": occurrences},
        }
        if asset.asset_type == "library":
            ecosystem = "pypi" if asset.details.get("ecosystem") == "PyPI" else "npm"
            version = asset.details.get("version")
            component.update(
                {
                    "type": "library",
                    **({"version": version} if version else {}),
                    "purl": f"pkg:{ecosystem}/{asset.name.lower()}" + (f"@{version}" if version else ""),
                }
            )
        else:
            component["type"] = "cryptographic-asset"
            if asset.asset_type == "algorithm":
                properties: dict[str, Any] = {
                    "primitive": asset.primitive if asset.primitive in _PRIMITIVES else "other"
                }
                if asset.mode and asset.mode.lower() in _MODES:
                    properties["mode"] = asset.mode.lower()
                if asset.key_size:
                    properties["parameterSetIdentifier"] = str(asset.key_size)
                if asset.quantum_vulnerable:
                    properties["nistQuantumSecurityLevel"] = 0
                component["cryptoProperties"] = {"assetType": "algorithm", "algorithmProperties": properties}
            elif asset.asset_type == "certificate":
                details = asset.details
                component["cryptoProperties"] = {
                    "assetType": "certificate",
                    "certificateProperties": {
                        "subjectName": details["subject"],
                        "issuerName": details["issuer"],
                        "notValidBefore": details["not_before"],
                        "notValidAfter": details["not_after"],
                        "certificateFormat": "X.509",
                        "certificateExtension": Path(asset.path).suffix.lstrip(".") or "pem",
                    },
                }
            elif asset.asset_type == "protocol":
                family = asset.details.get("protocol", "tls")
                component["cryptoProperties"] = {
                    "assetType": "protocol",
                    "protocolProperties": {
                        "type": "tls" if family == "tls" else "other",
                        "version": asset.details.get("version", ""),
                    },
                }
            else:
                material: dict[str, Any] = {"type": "private-key", "format": asset.details.get("format", "PEM")}
                if asset.key_size:
                    material["size"] = asset.key_size
                component["cryptoProperties"] = {
                    "assetType": "related-crypto-material",
                    "relatedCryptoMaterialProperties": material,
                }
        components.append(component)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "tools": {"components": [{"type": "application", "name": "vulnwarden", "version": __version__}]},
            "component": {"type": "application", "name": repo_name, "bom-ref": "root-component"},
        },
        "components": components,
    }


def key_ages(root: Path, assets: list[CryptoAsset], now: datetime | None = None) -> dict[str, float]:
    now = now or datetime.now(UTC)
    ages: dict[str, float] = {}
    for asset in assets:
        if asset.asset_type == "related-crypto-material" and asset.path not in ages:
            age = file_age_days(root, asset.path, now)
            if age is not None:
                ages[asset.path] = age
    return ages


__all__ = ["CryptoPolicy", "canonical", "discover", "evaluate", "key_ages", "lifecycle", "load_policy", "to_cbom"]
