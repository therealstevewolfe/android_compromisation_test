from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from android_forensic_suite.core import AdbInterface, AndroidForensicAnalyzer, DeviceConnectionError


@pytest.fixture(autouse=True)
def fake_adb_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure the fake adb shim is used for every test."""

    fake_dir = Path(__file__).parent / "fake_adb"
    monkeypatch.setenv("PATH", f"{fake_dir}:{os.environ.get('PATH', '')}")
    monkeypatch.delenv("FAKE_ADB_MODE", raising=False)


def test_ensure_device_connected_success() -> None:
    analyzer = AndroidForensicAnalyzer(AdbInterface())
    analyzer.ensure_device_connected()  # Should not raise


def test_ensure_device_connected_unauthorized(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_ADB_MODE", "unauthorized")

    analyzer = AndroidForensicAnalyzer(AdbInterface())

    with pytest.raises(DeviceConnectionError):
        analyzer.ensure_device_connected()


def test_run_pipeline_exports_reports(tmp_path: Path) -> None:
    analyzer = AndroidForensicAnalyzer(AdbInterface())

    report, json_path, html_path = analyzer.run(tmp_path, skip_logs=False)

    assert report.summary["Status"] == "CLEAN"
    assert report.summary["SecurityScore"] == 100
    assert report.logs["AuthenticationEvents"] == 1
    assert Path(report.logs["FullLogPath"]).exists()
    assert Path(report.logs["SuspiciousLogPath"]).exists()
    assert json_path.exists()
    assert html_path.exists()

    json_data = json.loads(json_path.read_text(encoding="utf-8"))
    assert json_data["Device"]["Model"] == "Pixel 5"

    html_text = html_path.read_text(encoding="utf-8")
    assert "Android Device Forensic Analysis Report" in html_text


def test_run_with_skip_logs(tmp_path: Path) -> None:
    analyzer = AndroidForensicAnalyzer(AdbInterface())

    report, _, _ = analyzer.run(tmp_path, skip_logs=True)

    assert report.logs["Status"] == "Skipped by user"
    assert "FullLogPath" not in report.logs
