"""Export helpers."""

import tempfile


def export_path() -> str:
    return tempfile.mktemp(suffix=".csv")
