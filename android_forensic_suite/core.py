from __future__ import annotations

import html
import json
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple


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
    network: Dict[str, object] = field(default_factory=dict)
    performance: Dict[str, object] = field(default_factory=dict)
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
            "Network": self.network,
            "Performance": self.performance,
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
            ("UnknownSources", ("settings", "get", "secure", "install_non_market_apps")),
            ("Debugger", ("getprop", "ro.debuggable")),
            ("SecureMode", ("getprop", "ro.secure")),
            ("OemUnlockAllowed", ("getprop", "persist.sys.oem_unlock_allowed")),
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
            for line in battery_output.splitlines()[:40]:
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
            for raw_line in usb_output.splitlines()[:40]:
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
            third_party = [line.split(":", 1)[1] for line in third_party_output.splitlines() if line.startswith("package:")]
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

    def collect_network(self, report: AnalysisReport) -> None:
        try:
            interface_output = self.adb.shell("ip", "addr", "show", "wlan0", strip=False)
            report.network["Interfaces"] = self._parse_ip_addr_output(interface_output, interface_name="wlan0")
        except AdbError as exc:
            report.network["Interfaces"] = []
            report.errors.append(f"Unable to read network interfaces: {exc}")

        try:
            wifi_output = self.adb.shell("dumpsys", "wifi", strip=False)
            report.network["WifiStatus"] = self._extract_wifi_summary(wifi_output)
        except AdbError as exc:
            report.network["WifiStatus"] = {"Error": str(exc)}
            report.errors.append(f"Wi-Fi status unavailable: {exc}")

    def collect_performance(self, report: AnalysisReport) -> None:
        try:
            top_output = self.adb.shell("top", "-n", "1", "-b", strip=False)
            report.performance["TopProcesses"] = self._parse_top_output(top_output)
        except AdbError as exc:
            report.performance["TopProcesses"] = []
            report.errors.append(f"Process inspection failed: {exc}")

        try:
            storage_output = self.adb.shell("df", "/data", strip=False)
            report.performance["DataPartition"] = self._parse_df_output(storage_output)
        except AdbError as exc:
            report.performance["DataPartition"] = {}
            report.errors.append(f"Storage inspection failed: {exc}")

    # Analysis -----------------------------------------------------------
    def analyze(self, report: AnalysisReport) -> None:
        warnings: List[str] = []
        risk_factors: List[Dict[str, Any]] = []
        breakdown: List[Dict[str, Any]] = []
        score = 100

        def register_check(
            label: str,
            passed: bool,
            failure_message: str,
            impact: int,
            severity: str,
            metadata: Optional[Dict[str, Any]] = None,
        ) -> None:
            nonlocal score
            breakdown.append({
                "check": label,
                "passed": passed,
                "impact": 0 if passed else impact,
            })
            if passed:
                return
            score -= impact
            warnings.append(failure_message)
            risk_entry: Dict[str, Any] = {
                "name": label,
                "severity": severity,
                "detail": failure_message,
                "scoreImpact": impact,
            }
            if metadata:
                risk_entry.update(metadata)
            risk_factors.append(risk_entry)

        register_check(
            "Verified boot integrity",
            report.security.get("VerifiedBootState", "").lower() == "green",
            "Boot verification not in secure state",
            impact=20,
            severity="high",
        )
        register_check(
            "Bootloader locked",
            report.security.get("BootloaderState", "").lower() == "locked",
            "Bootloader is unlocked",
            impact=30,
            severity="critical",
        )
        register_check(
            "SELinux enforcing",
            report.security.get("SELinux", "").lower() == "enforcing",
            "SELinux not enforcing",
            impact=20,
            severity="high",
        )
        register_check(
            "Release build tags",
            report.device.get("BuildTags", "").strip() == "release-keys",
            "Non-release build detected",
            impact=10,
            severity="medium",
        )
        register_check(
            "Root binaries absent",
            "detected" not in report.security.get("SuBinary", "").lower(),
            "Device appears to be rooted",
            impact=50,
            severity="critical",
        )
        register_check(
            "ADB debugging disabled",
            report.security.get("AdbEnabled", "0").strip() in {"0", "false"},
            "ADB debugging is enabled",
            impact=10,
            severity="medium",
        )
        register_check(
            "Developer options disabled",
            report.security.get("DeveloperOptions", "0").strip() in {"0", "false"},
            "Developer options are enabled",
            impact=5,
            severity="low",
        )
        register_check(
            "Unknown sources disabled",
            report.security.get("UnknownSources", "0").strip() in {"0", "false"},
            "Unknown sources installation is enabled",
            impact=10,
            severity="medium",
        )
        register_check(
            "Debugger disabled",
            report.security.get("Debugger", "0").strip() in {"0", "false"},
            "System debug mode is enabled",
            impact=10,
            severity="medium",
        )
        register_check(
            "Secure mode enabled",
            report.security.get("SecureMode", "1").strip() in {"1", "true"},
            "System secure mode is disabled",
            impact=15,
            severity="high",
        )
        register_check(
            "OEM unlocking disabled",
            report.security.get("OemUnlockAllowed", "0").strip() in {"0", "false"},
            "OEM unlocking allowed",
            impact=15,
            severity="high",
        )

        score = max(0, min(100, score))
        status = "CLEAN" if not warnings else "SUSPICIOUS"

        report.summary = {
            "Warnings": warnings,
            "SecurityScore": score,
            "Status": status,
            "IsSecure": not warnings,
            "RiskFactors": risk_factors,
            "ScoreBreakdown": breakdown,
            "Visualization": {
                "RiskCount": len(risk_factors),
                "ThirdPartyPackages": report.packages.get("ThirdPartyCount", 0),
                "AuthenticationEvents": report.logs.get("AuthenticationEvents", 0),
            },
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
        def render_table(title: str, values: Dict[str, Any]) -> str:
            if not values:
                return f"<h2>{title}</h2><p>No data collected.</p>"
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

        risk_html = "".join(
            """
            <div class='risk-card'>
                <div class='risk-header'>
                    <span class='risk-name'>{name}</span>
                    <span class='risk-severity risk-{severity}'>{severity}</span>
                </div>
                <p>{detail}</p>
                <small>Score impact: -{impact}</small>
            </div>
            """.format(
                name=html.escape(risk.get("name", "")),
                severity=html.escape(risk.get("severity", "medium")),
                detail=html.escape(risk.get("detail", "")),
                impact=html.escape(str(risk.get("scoreImpact", 0))),
            )
            for risk in report.summary.get("RiskFactors", [])
        )
        if risk_html:
            risk_html = f"<h2>🚨 Risk Factors</h2><div class='risk-grid'>{risk_html}</div>"
        else:
            risk_html = "<h2>🚨 Risk Factors</h2><p>No elevated risk factors detected.</p>"

        breakdown_rows = "".join(
            """
            <tr>
                <td>{name}</td>
                <td class='center'>{status}</td>
                <td class='center'>{impact}</td>
            </tr>
            """.format(
                name=html.escape(item.get("check", "")),
                status="✅" if item.get("passed") else "⚠️",
                impact=html.escape(str(item.get("impact", 0))),
            )
            for item in report.summary.get("ScoreBreakdown", [])
        )

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

        interfaces_html = "".join(
            """
            <div class='interface-card'>
                <h4>{name}</h4>
                <p><strong>State:</strong> {state}</p>
                <p><strong>Addresses:</strong> {addresses}</p>
            </div>
            """.format(
                name=html.escape(interface.get("name", "unknown")),
                state=html.escape(interface.get("state", "unknown")),
                addresses=html.escape(", ".join(interface.get("addresses", []))),
            )
            for interface in report.network.get("Interfaces", [])
        )
        if interfaces_html:
            interfaces_html = f"<h2>🌐 Network Interfaces</h2><div class='interface-grid'>{interfaces_html}</div>"

        top_process_rows = "".join(
            """
            <tr>
                <td>{pid}</td>
                <td>{user}</td>
                <td class='center'>{cpu}</td>
                <td>{name}</td>
            </tr>
            """.format(
                pid=html.escape(str(proc.get("pid", ""))),
                user=html.escape(str(proc.get("user", ""))),
                cpu=html.escape(str(proc.get("cpu", ""))),
                name=html.escape(str(proc.get("name", ""))),
            )
            for proc in report.performance.get("TopProcesses", [])
        )
        performance_section = ""
        if top_process_rows:
            performance_section += (
                "<h2>🧠 Top Processes</h2>"
                "<table><tr><th>PID</th><th>User</th><th>CPU%</th><th>Name</th></tr>"
                f"{top_process_rows}</table>"
            )
        if report.performance.get("DataPartition"):
            performance_section += render_table("💾 /data Partition", report.performance["DataPartition"])
        if performance_section:
            performance_section = f"<section class='performance-section'>{performance_section}</section>"

        wifi_status = report.network.get("WifiStatus")
        wifi_html = ""
        if isinstance(wifi_status, dict) and wifi_status:
            wifi_html = render_table("📶 Wi-Fi Status", wifi_status)

        return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Android Forensic Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: linear-gradient(135deg, #eef2f3, #f9f9f9); }}
        .container {{ max-width: 1200px; margin: auto; background: white; padding: 30px; border-radius: 16px; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1); }}
        h1 {{ color: #222; border-bottom: 4px solid #4CAF50; padding-bottom: 10px; }}
        h2 {{ color: #444; margin-top: 40px; }}
        h3 {{ color: #444; margin-top: 30px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid #e6e6e6; }}
        th {{ background: #f1f5f9; font-weight: 600; }}
        .status-clean {{ color: #1B5E20; font-weight: bold; }}
        .status-suspicious {{ color: #C62828; font-weight: bold; }}
        .warning {{ background: #fff3cd; padding: 12px 16px; border-left: 4px solid #ffc107; margin: 12px 0; border-radius: 8px; }}
        .score {{ font-size: 54px; font-weight: bold; }}
        .score-high {{ color: #2E7D32; }}
        .score-medium {{ color: #FF8F00; }}
        .score-low {{ color: #C62828; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 20px; margin-top: 20px; }}
        .summary-card {{ background: #f8fafc; padding: 20px; border-radius: 12px; box-shadow: inset 0 0 0 1px #e2e8f0; }}
        .risk-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 20px; margin-top: 20px; }}
        .risk-card {{ background: #fff5f5; border-radius: 14px; padding: 18px; border: 1px solid #fecaca; box-shadow: 0 6px 16px rgba(254, 202, 202, 0.5); }}
        .risk-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }}
        .risk-name {{ font-weight: 600; font-size: 1.05rem; }}
        .risk-severity {{ text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.08em; padding: 4px 8px; border-radius: 999px; background: #fee2e2; color: #b91c1c; }}
        .risk-critical {{ background: #fee2e2; color: #b91c1c; }}
        .risk-high {{ background: #fef3c7; color: #b45309; }}
        .risk-medium {{ background: #ede9fe; color: #5b21b6; }}
        .risk-low {{ background: #dcfce7; color: #166534; }}
        .interface-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; }}
        .interface-card {{ background: #f1f5f9; padding: 16px; border-radius: 12px; border: 1px solid #cbd5f5; }}
        .center {{ text-align: center; }}
        .performance-section table {{ margin-top: 0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Android Device Forensic Analysis Report</h1>
        <p><strong>Generated:</strong> {html.escape(report.timestamp_label)}</p>

        <h2>📊 Summary</h2>
        <div class="summary-grid">
            <div class="summary-card">
                <div class="info-label">Status</div>
                <div class="{status_class}">{html.escape(report.summary.get('Status', 'UNKNOWN'))}</div>
            </div>
            <div class="summary-card">
                <div class="info-label">Security Score</div>
                <div class="score {score_class}">{html.escape(str(score))}/100</div>
            </div>
            <div class="summary-card">
                <div class="info-label">Warnings</div>
                <div>{len(report.summary.get('Warnings', []))}</div>
            </div>
            <div class="summary-card">
                <div class="info-label">Authentication Events</div>
                <div>{html.escape(str(report.logs.get('AuthenticationEvents', 'N/A')))}</div>
            </div>
        </div>

        {warnings_html}
        {risk_html}

        <h2>🛡️ Score Breakdown</h2>
        <table>
            <tr><th>Check</th><th class="center">Status</th><th class="center">Impact</th></tr>
            {breakdown_rows}
        </table>

        {render_table('📱 Device Information', report.device)}
        {render_table('🔒 Security Status', report.security)}

        <h2>📦 Package Information</h2>
        <p><strong>Total Packages:</strong> {html.escape(str(report.packages.get('TotalCount', 'N/A')))}</p>
        <p><strong>Third-party Packages:</strong> {html.escape(str(report.packages.get('ThirdPartyCount', 'N/A')))}</p>
        <p><strong>Sample Packages:</strong> {html.escape(', '.join(report.packages.get('SamplePackages', [])))} </p>

        <h2>📝 Logs</h2>
        {logs_section}

        {wifi_html}
        {interfaces_html}
        {performance_section}

        {errors_html}
    </div>
</body>
</html>
"""

    def _parse_ip_addr_output(self, output: str, interface_name: str) -> List[Dict[str, Any]]:
        interfaces: List[Dict[str, Any]] = []
        addresses: List[str] = []
        state = "unknown"
        mac = ""
        for line in output.splitlines():
            stripped = line.strip()
            if re.match(r"\d+: ", stripped):
                if addresses or state != "unknown" or mac:
                    interfaces.append({
                        "name": interface_name,
                        "addresses": addresses,
                        "state": state,
                        "mac": mac,
                    })
                addresses = []
                mac = ""
                state_match = re.search(r"state ([A-Z]+)", stripped)
                state = state_match.group(1).upper() if state_match else "unknown"
            elif stripped.startswith("link/"):
                parts = stripped.split()
                if len(parts) >= 2:
                    mac = parts[1]
            elif stripped.startswith("inet "):
                parts = stripped.split()
                if len(parts) >= 2:
                    addresses.append(parts[1])
        if addresses or state != "unknown" or mac:
            interfaces.append({
                "name": interface_name,
                "addresses": addresses,
                "state": state,
                "mac": mac,
            })
        return interfaces

    def _extract_wifi_summary(self, output: str) -> Dict[str, Any]:
        summary: Dict[str, Any] = {}
        enabled_match = re.search(r"Wi-Fi is (enabled|disabled)", output, re.IGNORECASE)
        if enabled_match:
            summary["WifiEnabled"] = enabled_match.group(1).lower()
        ssid_match = re.search(r"SSID: (.+)", output)
        if ssid_match:
            summary["ConnectedSsid"] = ssid_match.group(1).strip()
        state_match = re.search(r"Supplicant State: (.+)", output)
        if state_match:
            summary["SupplicantState"] = state_match.group(1).strip()
        bssid_match = re.search(r"BSSID: ([0-9a-fA-F:\-]+)", output)
        if bssid_match:
            summary["BSSID"] = bssid_match.group(1)
        return summary

    def _parse_top_output(self, output: str, limit: int = 5) -> List[Dict[str, Any]]:
        processes: List[Dict[str, Any]] = []
        for line in output.splitlines():
            stripped = line.strip()
            if not stripped or stripped.lower().startswith(("tasks", "%cpu", "load", "pid")):
                continue
            columns = re.split(r"\s+", stripped, maxsplit=3)
            if len(columns) < 4:
                continue
            pid, user, cpu_segment, name = columns
            cpu_value = cpu_segment.rstrip("%")
            processes.append({
                "pid": pid,
                "user": user,
                "cpu": cpu_value,
                "name": name,
            })
            if len(processes) >= limit:
                break
        return processes

    def _parse_df_output(self, output: str) -> Dict[str, Any]:
        lines = [line for line in output.splitlines() if line.strip()]
        if len(lines) < 2:
            return {}
        header = re.split(r"\s+", lines[0].strip())
        values = re.split(r"\s+", lines[1].strip())
        data = {header[idx]: values[idx] for idx in range(min(len(header), len(values)))}
        return data

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
        self.collect_network(report)
        self.collect_performance(report)
        self.analyze(report)
        json_path, html_path = self.export_reports(report, output_dir)
        return report, json_path, html_path
