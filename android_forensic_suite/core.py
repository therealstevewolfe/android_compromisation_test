from __future__ import annotations

import html
import json
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple


@dataclass
class CommandResult:
    """Represents the outcome of a command invocation."""

    stdout: str
    stderr: str
    returncode: int


class AdbError(RuntimeError):
    """Raised when an ADB invocation fails."""


class DeviceConnectionError(RuntimeError):
    """Raised when a connected Android device cannot be confirmed."""


CommandRunner = Callable[[Sequence[str], Optional[int]], CommandResult]


class AdbInterface:
    """Wrapper around the adb executable with optional device scoping."""

    def __init__(self, serial: str | None = None, runner: CommandRunner | None = None) -> None:
        self.serial = serial
        self._runner: CommandRunner = runner or self._default_runner

    def _default_runner(self, args: Sequence[str], timeout: Optional[int]) -> CommandResult:
        try:
            completed = subprocess.run(  # noqa: PLW1510 - we want to capture output
                list(args),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:  # pragma: no cover - defensive guard
            raise AdbError(f"Command timed out: {' '.join(args)}") from exc
        return CommandResult(stdout=completed.stdout, stderr=completed.stderr, returncode=completed.returncode)

    def _build_args(self, base_args: Iterable[str]) -> List[str]:
        command = ["adb"]
        if self.serial:
            command.extend(["-s", self.serial])
        command.extend(base_args)
        return command

    def run(
        self,
        *base_args: str,
        timeout: int | None = 30,
        check: bool = True,
    ) -> CommandResult:
        """Execute an adb command and return the raw command result."""

        command = self._build_args(base_args)
        result = self._runner(command, timeout)
        if check and result.returncode != 0:
            message = result.stderr.strip() or result.stdout.strip() or "Unknown error"
            raise AdbError(f"Command {' '.join(command)} failed: {message}")
        return result

    def run_text(
        self,
        *base_args: str,
        timeout: int | None = 30,
        check: bool = True,
        strip: bool = True,
    ) -> str:
        """Execute an adb command and return its textual output."""

        result = self.run(*base_args, timeout=timeout, check=check)
        output = result.stdout
        return output.strip() if strip else output

    def shell(
        self,
        *shell_args: str,
        timeout: int | None = 30,
        check: bool = True,
        strip: bool = True,
    ) -> str:
        """Execute an adb shell command."""

        result = self.run("shell", *shell_args, timeout=timeout, check=check)
        output = result.stdout
        return output.strip() if strip else output

    def shell_result(
        self,
        *shell_args: str,
        timeout: int | None = 30,
        check: bool = True,
    ) -> CommandResult:
        """Execute an adb shell command and return the raw command result."""

        return self.run("shell", *shell_args, timeout=timeout, check=check)


@dataclass
class AnalysisReport:
    """Aggregate representation of a forensic run."""

    timestamp: datetime = field(default_factory=datetime.utcnow)
    device: Dict[str, str] = field(default_factory=dict)
    security: Dict[str, str] = field(default_factory=dict)
    activity: Dict[str, object] = field(default_factory=dict)
    packages: Dict[str, object] = field(default_factory=dict)
    logs: Dict[str, object] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    summary: Dict[str, object] = field(default_factory=dict)

    @property
    def timestamp_label(self) -> str:
        return self.timestamp.strftime("%Y-%m-%d %H:%M:%S")

    @property
    def file_stem(self) -> str:
        return self.timestamp.strftime("forensic-report-%Y%m%d-%H%M%S")

    def to_dict(self) -> Dict[str, object]:
        return {
            "Timestamp": self.timestamp_label,
            "Device": self.device,
            "Security": self.security,
            "Activity": self.activity,
            "Packages": self.packages,
            "Logs": self.logs,
            "Errors": self.errors,
            "Summary": self.summary,
        }


class AndroidForensicAnalyzer:
    """High level orchestration for the forensic workflow."""

    def __init__(self, adb: AdbInterface) -> None:
        self.adb = adb

    # Device connection -------------------------------------------------
    def ensure_device_connected(self) -> None:
        result = self.adb.run("devices", "-l", check=False)
        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if any("unauthorized" in line.lower() for line in lines):
            raise DeviceConnectionError("Device is unauthorized. Please authorize this computer on the device.")

        device_lines = [line for line in lines if not line.startswith("List of devices")]
        if not device_lines:
            raise DeviceConnectionError("No connected device detected.")

        if not any(re.search(r"\bdevice\b", line) for line in device_lines):
            raise DeviceConnectionError("No authorized device found.")

    # Data collection ----------------------------------------------------
    def collect_device_info(self, report: AnalysisReport) -> None:
        properties: Dict[str, str] = {
            "Model": "ro.product.model",
            "Manufacturer": "ro.product.manufacturer",
            "AndroidVersion": "ro.build.version.release",
            "BuildFingerprint": "ro.build.fingerprint",
            "BuildTags": "ro.build.tags",
            "BuildType": "ro.build.type",
            "SecurityPatch": "ro.build.version.security_patch",
            "Bootloader": "ro.bootloader",
            "Hardware": "ro.hardware",
        }

        for label, prop in properties.items():
            try:
                report.device[label] = self.adb.shell("getprop", prop)
            except AdbError as exc:
                report.device[label] = f"Error: {exc}"
                report.errors.append(f"Failed to get {label}")

    def collect_security_status(self, report: AnalysisReport) -> None:
        security_checks: List[Tuple[str, Tuple[str, ...]]] = [
            ("VerifiedBootState", ("getprop", "ro.boot.verifiedbootstate")),
            ("VerityMode", ("getprop", "ro.boot.veritymode")),
            ("BootloaderState", ("getprop", "ro.boot.vbmeta.device_state")),
            ("SELinux", ("getenforce",)),
            ("AdbEnabled", ("settings", "get", "global", "adb_enabled")),
            ("DeveloperOptions", ("settings", "get", "global", "development_settings_enabled")),
        ]

        for label, args in security_checks:
            try:
                report.security[label] = self.adb.shell(*args)
            except AdbError as exc:
                report.security[label] = f"Error: {exc}"
                report.errors.append(f"Failed security check: {label}")

        su_result = self.adb.shell_result("which", "su", check=False)
        if su_result.returncode == 0 and su_result.stdout.strip():
            report.security["SuBinary"] = "DETECTED - Device may be rooted!"
            report.security["SuBinaryPath"] = su_result.stdout.strip()
        else:
            report.security["SuBinary"] = "Not found (Good)"

        try:
            report.security["UserContext"] = self.adb.shell("id")
        except AdbError as exc:
            report.security["UserContext"] = f"Error: {exc}"
            report.errors.append("Failed to get user context")

    def collect_activity(self, report: AnalysisReport) -> None:
        try:
            report.activity["Uptime"] = self.adb.shell("uptime")
        except AdbError as exc:
            report.activity["Uptime"] = f"Error: {exc}"
            report.errors.append("Failed to retrieve uptime")

        try:
            battery_output = self.adb.shell("dumpsys", "battery", strip=False)
            battery_info: Dict[str, str] = {}
            for line in battery_output.splitlines()[:20]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    battery_info[key.strip()] = value.strip()
            report.activity["Battery"] = battery_info
        except AdbError as exc:
            report.activity["Battery"] = {}
            report.errors.append(f"Battery stats unavailable: {exc}")

        try:
            usb_output = self.adb.shell("dumpsys", "usb", strip=False)
            relevant = []
            for raw_line in usb_output.splitlines()[:30]:
                line = raw_line.strip()
                if re.search(r"current_functions|connected|configured", line, re.IGNORECASE):
                    relevant.append(line)
            report.activity["USBConnection"] = "; ".join(relevant)
        except AdbError as exc:
            report.activity["USBConnection"] = f"Error: {exc}"
            report.errors.append("USB status unavailable")

    def collect_packages(self, report: AnalysisReport) -> None:
        try:
            all_packages_output = self.adb.shell("pm", "list", "packages", "--user", "0", strip=False)
            packages = [line.split(":", 1)[1] for line in all_packages_output.splitlines() if line.startswith("package:")]
            report.packages["TotalCount"] = len(packages)
            report.packages["SamplePackages"] = packages[:10]
        except AdbError as exc:
            report.packages["TotalCount"] = 0
            report.packages["SamplePackages"] = []
            report.errors.append(f"Package list retrieval failed: {exc}")

        try:
            third_party_output = self.adb.shell("pm", "list", "packages", "-3", "--user", "0", strip=False)
            third_party = [line for line in third_party_output.splitlines() if line.startswith("package:")]
            report.packages["ThirdPartyCount"] = len(third_party)
        except AdbError as exc:
            report.packages["ThirdPartyCount"] = 0
            report.errors.append(f"Third-party package retrieval failed: {exc}")

    def collect_logs(self, report: AnalysisReport, output_path: Path, skip_logs: bool) -> None:
        if skip_logs:
            report.logs["Status"] = "Skipped by user"
            return

        log_path = output_path / f"logcat-{report.timestamp.strftime('%Y%m%d-%H%M%S')}.txt"
        suspicious_path = output_path / f"suspicious-{report.timestamp.strftime('%Y%m%d-%H%M%S')}.txt"

        try:
            result = self.adb.run("logcat", "-d", check=False)
        except AdbError as exc:  # pragma: no cover - defensive
            report.logs["Error"] = f"Failed to collect logs: {exc}"
            report.errors.append("Log collection failed")
            return

        log_output = result.stdout
        try:
            log_path.write_text(log_output, encoding="utf-8")
            size_mb = round(log_path.stat().st_size / (1024 * 1024), 2)
            report.logs["FullLogPath"] = str(log_path)
            report.logs["LogSizeMB"] = size_mb
        except OSError as exc:
            report.logs["FullLogPath"] = ""
            report.errors.append(f"Unable to write logcat output: {exc}")

        suspicious_pattern = re.compile(r"(adbd|usb|debug|reboot|panic|auth|root|su)", re.IGNORECASE)
        suspicious_lines = [line for line in log_output.splitlines() if suspicious_pattern.search(line)]
        suspicious_text = "\n".join(suspicious_lines[:100])
        try:
            suspicious_path.write_text(suspicious_text, encoding="utf-8")
            report.logs["SuspiciousLogPath"] = str(suspicious_path)
        except OSError as exc:
            report.logs["SuspiciousLogPath"] = ""
            report.errors.append(f"Unable to write suspicious log file: {exc}")

        auth_pattern = re.compile(r"authenticated|authorization", re.IGNORECASE)
        report.logs["AuthenticationEvents"] = sum(1 for line in log_output.splitlines() if auth_pattern.search(line))

    # Analysis -----------------------------------------------------------
    def analyze(self, report: AnalysisReport) -> None:
        warnings: List[str] = []
        score = 100

        if "detected" in report.security.get("SuBinary", "").lower():
            warnings.append("Device appears to be rooted")
            score -= 50

        if report.security.get("VerifiedBootState", "").lower() != "green":
            warnings.append("Boot verification not in secure state")
            score -= 20

        if report.security.get("BootloaderState", "").lower() != "locked":
            warnings.append("Bootloader is unlocked")
            score -= 30

        if report.security.get("SELinux", "").lower() != "enforcing":
            warnings.append("SELinux not enforcing")
            score -= 20

        if report.device.get("BuildTags") not in ("release-keys", "release-keys\n"):
            warnings.append("Non-release build detected")
            score -= 10

        score = max(0, score)
        status = "CLEAN" if not warnings else "SUSPICIOUS"

        report.summary = {
            "Warnings": warnings,
            "SecurityScore": score,
            "Status": status,
            "IsSecure": not warnings,
        }

    # Export -------------------------------------------------------------
    def export_reports(self, report: AnalysisReport, output_path: Path) -> Tuple[Path, Path]:
        json_path = output_path / f"{report.file_stem}.json"
        html_path = output_path / f"{report.file_stem}.html"

        try:
            json_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        except OSError as exc:
            raise AdbError(f"Unable to write JSON report: {exc}") from exc

        try:
            html_path.write_text(self._build_html_report(report), encoding="utf-8")
        except OSError as exc:
            raise AdbError(f"Unable to write HTML report: {exc}") from exc

        return json_path, html_path

    def _build_html_report(self, report: AnalysisReport) -> str:
        def render_table(title: str, values: Dict[str, object]) -> str:
            rows = "\n".join(
                f"<tr><td>{html.escape(str(key))}</td><td>{html.escape(json.dumps(value) if isinstance(value, (dict, list)) else str(value))}</td></tr>"
                for key, value in values.items()
            )
            return f"<h2>{title}</h2><table><tr><th>Key</th><th>Value</th></tr>{rows}</table>"

        score = report.summary.get("SecurityScore", 0)
        score_class = "score-high" if score >= 80 else "score-medium" if score >= 50 else "score-low"
        status_class = "status-clean" if report.summary.get("Status") == "CLEAN" else "status-suspicious"

        warnings_html = "".join(
            f"<div class='warning'>{html.escape(warning)}</div>" for warning in report.summary.get("Warnings", [])
        )
        if warnings_html:
            warnings_html = f"<h3>⚠️ Warnings</h3>{warnings_html}"

        errors_html = "".join(f"<li>{html.escape(error)}</li>" for error in report.errors)
        if errors_html:
            errors_html = f"<h2>❌ Errors</h2><ul>{errors_html}</ul>"

        logs_section = ""
        if report.logs.get("Status") == "Skipped by user":
            logs_section = "<p>Log collection was skipped.</p>"
        else:
            log_size = report.logs.get("LogSizeMB", "N/A")
            auth_events = report.logs.get("AuthenticationEvents", "N/A")
            logs_section = (
                f"<p><strong>Log Size:</strong> {html.escape(str(log_size))} MB</p>"
                f"<p><strong>Authentication Events:</strong> {html.escape(str(auth_events))}</p>"
            )

        return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Android Forensic Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: auto; background: white; padding: 20px; border-radius: 10px; }}
        h1 {{ color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .status-clean {{ color: green; font-weight: bold; }}
        .status-suspicious {{ color: red; font-weight: bold; }}
        .warning {{ background: #fff3cd; padding: 10px; border-left: 4px solid #ffc107; margin: 10px 0; }}
        .info-grid {{ display: grid; grid-template-columns: 1fr 2fr; gap: 10px; }}
        .info-label {{ font-weight: bold; color: #666; }}
        .score {{ font-size: 48px; font-weight: bold; }}
        .score-high {{ color: green; }}
        .score-medium {{ color: orange; }}
        .score-low {{ color: red; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f8f9fa; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Android Device Forensic Analysis Report</h1>
        <p><strong>Generated:</strong> {html.escape(report.timestamp_label)}</p>

        <h2>📊 Summary</h2>
        <div class="info-grid">
            <div class="info-label">Status:</div>
            <div class="{status_class}">{html.escape(report.summary.get('Status', 'UNKNOWN'))}</div>
            <div class="info-label">Security Score:</div>
            <div class="score {score_class}">{html.escape(str(score))}/100</div>
        </div>

        {warnings_html}

        {render_table('📱 Device Information', report.device)}
        {render_table('🔒 Security Status', report.security)}

        <h2>📦 Package Information</h2>
        <p><strong>Total Packages:</strong> {html.escape(str(report.packages.get('TotalCount', 'N/A')))}</p>
        <p><strong>Third-party Packages:</strong> {html.escape(str(report.packages.get('ThirdPartyCount', 'N/A')))}</p>
        <p><strong>Sample Packages:</strong> {html.escape(', '.join(report.packages.get('SamplePackages', [])))} </p>

        <h2>📝 Logs</h2>
        {logs_section}

        {errors_html}
    </div>
</body>
</html>
"""

    # Main orchestration -------------------------------------------------
    def run(self, output_path: Path | str, skip_logs: bool = False) -> Tuple[AnalysisReport, Path, Path]:
        output_dir = Path(output_path)
        output_dir.mkdir(parents=True, exist_ok=True)

        self.ensure_device_connected()

        report = AnalysisReport()
        self.collect_device_info(report)
        self.collect_security_status(report)
        self.collect_activity(report)
        self.collect_packages(report)
        self.collect_logs(report, output_dir, skip_logs)
        self.analyze(report)
        json_path, html_path = self.export_reports(report, output_dir)
        return report, json_path, html_path
