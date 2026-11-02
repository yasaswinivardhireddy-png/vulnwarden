"""Container analysis: Dockerfile hardening rules and Trivy image-scan import."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from ..files import redact_secrets
from ..intel import cvss_base_score
from ..models import Category, Finding, Severity

# End-of-life dates (upstream support) as of November 2026. Update as runtimes age.
EOL: dict[str, dict[str, date]] = {
    "python": {
        "2.7": date(2020, 1, 1),
        "3.5": date(2020, 9, 30),
        "3.6": date(2021, 12, 23),
        "3.7": date(2023, 6, 27),
        "3.8": date(2024, 10, 7),
        "3.9": date(2025, 10, 31),
        "3.10": date(2026, 10, 31),
        "3.11": date(2027, 10, 31),
        "3.12": date(2028, 10, 31),
        "3.13": date(2029, 10, 31),
        "3.14": date(2030, 10, 31),
    },
    "node": {
        "10": date(2021, 4, 30),
        "12": date(2022, 4, 30),
        "14": date(2023, 4, 30),
        "16": date(2023, 9, 11),
        "18": date(2025, 4, 30),
        "20": date(2026, 4, 30),
        "22": date(2027, 4, 30),
        "24": date(2028, 4, 30),
    },
    "debian": {
        "stretch": date(2022, 6, 30),
        "buster": date(2024, 6, 30),
        "bullseye": date(2026, 8, 31),
        "bookworm": date(2028, 6, 30),
        "trixie": date(2030, 6, 30),
    },
    "ubuntu": {
        "16.04": date(2021, 4, 30),
        "18.04": date(2023, 5, 31),
        "20.04": date(2025, 5, 31),
        "22.04": date(2027, 6, 1),
        "24.04": date(2029, 5, 31),
    },
}
DEBIAN_NUMBERS = {"9": "stretch", "10": "buster", "11": "bullseye", "12": "bookworm", "13": "trixie"}
UBUNTU_NAMES = {"xenial": "16.04", "bionic": "18.04", "focal": "20.04", "jammy": "22.04", "noble": "24.04"}
MIN_SUPPORT_DAYS = 365

SECRET_KEY = re.compile(r"(?i)(password|passwd|secret|token|api_?key|access_?key|private_?key)")
FROM_LINE = re.compile(r"^FROM\s+(?:--platform=\S+\s+)?(?P<image>\S+)(?:\s+AS\s+(?P<alias>\S+))?", re.I)


@dataclass
class Instruction:
    keyword: str
    args: str
    line: int
    raw: str


def parse_dockerfile(text: str) -> list[Instruction]:
    instructions: list[Instruction] = []
    buffer, start = "", 0
    for number, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not buffer and (not stripped or stripped.startswith("#")):
            continue
        if not buffer:
            start = number
        buffer += (" " if buffer else "") + stripped.rstrip("\\").strip()
        if stripped.endswith("\\"):
            continue
        keyword, _, args = buffer.partition(" ")
        instructions.append(Instruction(keyword.upper(), args.strip(), start, buffer))
        buffer = ""
    return instructions


def split_image(image: str) -> tuple[str, str | None]:
    name, _, _digest = image.partition("@")
    last = name.rsplit("/", 1)[-1]
    tag = None
    if ":" in last:
        last, tag = last.split(":", 1)
    repo_path = name.rsplit("/", 1)[0] + "/" if "/" in name else ""
    if repo_path in {"docker.io/library/", "library/", "docker.io/"}:
        repo_path = ""
    return repo_path + last, tag


def _python_or_node_version(base: str, tag: str) -> str | None:
    pattern = r"^(\d+\.\d+)" if base == "python" else r"^(\d+)"
    match = re.match(pattern, tag)
    return match.group(1) if match else None


def eol_status(image: str, today: date) -> tuple[str, date, str] | None:
    """Return (component, eol_date, recommended_image) when the base image is unsupported."""
    base, tag = split_image(image)
    if tag is None:
        return None
    if base in {"python", "node"}:
        version = _python_or_node_version(base, tag)
        if version and version in EOL[base] and EOL[base][version] <= today:
            target = recommend(base, today)
            suffix = tag[len(version) :]
            suffix = _upgrade_codename(suffix, today)
            return f"{base} {version}", EOL[base][version], f"{base}:{target}{suffix}"
        codename = next((c for c in EOL["debian"] if c in tag.split("-")), None)
        if codename and EOL["debian"][codename] <= today:
            return f"debian {codename}", EOL["debian"][codename], f"{base}:{_upgrade_codename(tag, today)}"
        return None
    if base == "debian":
        codename = DEBIAN_NUMBERS.get(tag.split(".")[0], tag.split("-")[0])
        if codename in EOL["debian"] and EOL["debian"][codename] <= today:
            return f"debian {codename}", EOL["debian"][codename], f"debian:{recommend('debian', today)}-slim"
    if base == "ubuntu":
        version = UBUNTU_NAMES.get(tag, tag)
        if version in EOL["ubuntu"] and EOL["ubuntu"][version] <= today:
            return f"ubuntu {version}", EOL["ubuntu"][version], f"ubuntu:{recommend('ubuntu', today)}"
    return None


def recommend(component: str, today: date) -> str:
    """Smallest upgrade that still has at least a year of upstream support left."""
    for version, end in EOL[component].items():
        if (end - today).days >= MIN_SUPPORT_DAYS:
            return version
    return list(EOL[component])[-1]


def _upgrade_codename(tag_suffix: str, today: date) -> str:
    for codename, end in EOL["debian"].items():
        if codename in tag_suffix and end <= today:
            return tag_suffix.replace(codename, recommend("debian", today))
    return tag_suffix


def _finding(
    rule_id: str,
    title: str,
    severity: Severity,
    cwe: str,
    path: str,
    ins: Instruction,
    message: str,
    hint: str,
    details: dict | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        category=Category.CONTAINER,
        severity=severity,
        source="vulnwarden-container",
        path=path,
        line=ins.line,
        message=message,
        snippet=redact_secrets(ins.raw)[:200],
        cwe=[cwe],
        fix_hint=hint,
        sources=["vulnwarden-container"],
        details=details or {},
    )


def scan_dockerfile(text: str, path: str, today: date | None = None) -> list[Finding]:
    today = today or date.today()
    instructions = parse_dockerfile(text)
    findings: list[Finding] = []
    stages = [i for i, ins in enumerate(instructions) if ins.keyword == "FROM"]
    if not stages:
        return findings
    final_start = stages[-1]
    stage_aliases: set[str] = set()
    for ins in instructions:
        match = FROM_LINE.match(f"FROM {ins.args}") if ins.keyword == "FROM" else None
        if match and match.group("alias"):
            stage_aliases.add(match.group("alias"))

    for index, ins in enumerate(instructions):
        if ins.keyword == "FROM":
            match = FROM_LINE.match(f"FROM {ins.args}")
            image = match.group("image") if match else ins.args.split()[0]
            if image.lower() == "scratch" or image in stage_aliases:
                continue
            base, tag = split_image(image)
            if index == final_start:
                status = eol_status(image, today)
                if status:
                    component, end, target = status
                    findings.append(
                        _finding(
                            "VW-DOCKER-EOL-BASE",
                            "End-of-life base image",
                            Severity.HIGH,
                            "CWE-1104",
                            path,
                            ins,
                            f"{component} reached end of life on {end.isoformat()} and no longer gets security fixes.",
                            f"Rebuild on {target}.",
                            {"recommended_image": target, "image": image},
                        )
                    )
            if "@" not in image and (tag is None or tag == "latest"):
                findings.append(
                    _finding(
                        "VW-DOCKER-UNPINNED-BASE",
                        "Base image is not pinned",
                        Severity.MEDIUM,
                        "CWE-1357",
                        path,
                        ins,
                        f"{image} floats to whatever 'latest' is, so builds are not reproducible or reviewable.",
                        "Pin a supported version tag or an image digest.",
                    )
                )
        elif ins.keyword in {"ENV", "ARG"}:
            pairs = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*[= ]\s*(\"[^\"]*\"|'[^']*'|\S+)", ins.args)
            for key, value in pairs:
                if SECRET_KEY.search(key) and len(value.strip("'\"")) >= 6 and "$" not in value:
                    findings.append(
                        _finding(
                            "VW-DOCKER-SECRET",
                            "Secret baked into image layer",
                            Severity.HIGH,
                            "CWE-798",
                            path,
                            ins,
                            f"{ins.keyword} {key} stores a credential in the image history.",
                            "Use build secrets (RUN --mount=type=secret) or inject at runtime.",
                        )
                    )
        elif ins.keyword == "ADD" and re.search(r"\bhttps?://", ins.args):
            findings.append(
                _finding(
                    "VW-DOCKER-REMOTE-ADD",
                    "Remote download without integrity check",
                    Severity.MEDIUM,
                    "CWE-494",
                    path,
                    ins,
                    "ADD fetches a remote file without verifying a checksum.",
                    "Download with a pinned checksum (ADD --checksum=sha256:...) or COPY a vendored file.",
                )
            )
        elif ins.keyword == "RUN" and re.search(r"\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba)?sh\b", ins.args):
            findings.append(
                _finding(
                    "VW-DOCKER-PIPE-SHELL",
                    "Remote script piped to shell",
                    Severity.MEDIUM,
                    "CWE-494",
                    path,
                    ins,
                    "A script is downloaded and executed without verification.",
                    "Download, verify a checksum or signature, then execute.",
                )
            )

    final_users = [ins for ins in instructions[final_start:] if ins.keyword == "USER"]
    last_user = final_users[-1].args.split(":")[0].strip() if final_users else "root"
    if last_user in {"root", "0"}:
        anchor = final_users[-1] if final_users else instructions[final_start]
        findings.append(
            _finding(
                "VW-DOCKER-ROOT",
                "Container runs as root",
                Severity.MEDIUM,
                "CWE-250",
                path,
                anchor,
                "The final image has no non-root USER, so a compromise gets root inside the container.",
                "Add a non-root USER before CMD/ENTRYPOINT.",
            )
        )
        # Anchor identity to the stage's user, not the FROM line, so base-image upgrades keep the same fingerprint.
        findings[-1].snippet = f"final stage user: {last_user}"
    return findings


def load_trivy(path: Path) -> list[Finding]:
    """Import a Trivy JSON report (image, filesystem or repository scan)."""
    data = json.loads(path.read_text(encoding="utf-8"))
    artifact = data.get("ArtifactName") or path.name
    ecosystem_map = {
        "pip": "PyPI",
        "python-pkg": "PyPI",
        "pipenv": "PyPI",
        "poetry": "PyPI",
        "npm": "npm",
        "node-pkg": "npm",
        "yarn": "npm",
        "pnpm": "npm",
    }
    findings: list[Finding] = []
    for result in data.get("Results") or []:
        target = result.get("Target", artifact)
        kind = result.get("Type", "")
        is_os = result.get("Class") == "os-pkgs"
        for vuln in result.get("Vulnerabilities") or []:
            vuln_id = vuln.get("VulnerabilityID", "UNKNOWN")
            vector, score = None, None
            for source in ("nvd", "ghsa", "redhat"):
                entry = (vuln.get("CVSS") or {}).get(source) or {}
                vector = entry.get("V3Vector") or entry.get("V40Vector")
                score = entry.get("V3Score") or entry.get("V40Score") or cvss_base_score(vector)
                if vector:
                    break
            fixed = [v.strip() for v in (vuln.get("FixedVersion") or "").split(",") if v.strip()]
            package = vuln.get("PkgName", "")
            findings.append(
                Finding(
                    rule_id=vuln_id,
                    title=f"{package} {vuln.get('InstalledVersion', '')}: {vuln.get('Title') or vuln_id}",
                    category=Category.CONTAINER if is_os else Category.DEPENDENCY,
                    severity=Severity.parse(vuln.get("Severity")),
                    source="trivy",
                    path=artifact if is_os else target,
                    snippet=f"{package}@{vuln.get('InstalledVersion', '')}",
                    cwe=list(vuln.get("CweIDs") or []),
                    aliases=[vuln_id],
                    package=package,
                    ecosystem=kind if is_os else ecosystem_map.get(kind, kind),
                    installed_version=vuln.get("InstalledVersion"),
                    fixed_versions=fixed,
                    cvss_vector=vector,
                    cvss_score=float(score) if score is not None else None,
                    fix_hint=f"Upgrade {package} to {fixed[0]}." if fixed else "No fix published; mitigate or replace.",
                    sources=["trivy"],
                    details={"trivy_target": target, "trivy_type": kind},
                )
            )
    return findings
