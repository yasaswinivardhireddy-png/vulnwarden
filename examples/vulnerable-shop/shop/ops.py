"""Operational helpers."""

import subprocess


def tool_version(tool: str) -> str:
    return subprocess.check_output(f"{tool} --version", shell=True, text=True).strip()
