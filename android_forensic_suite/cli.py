from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .core import AdbError, AdbInterface, AndroidForensicAnalyzer, DeviceConnectionError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Android Device Forensic Analysis Suite")
    parser.add_argument("-s", "--device-serial", dest="device_serial", help="ADB device serial number", default=None)
    parser.add_argument(
        "-o", "--output", dest="output", default=".", help="Directory where reports and logs will be written"
    )
    parser.add_argument("--skip-logs", dest="skip_logs", action="store_true", help="Skip logcat collection")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    output_dir = Path(args.output).expanduser()
    adb = AdbInterface(serial=args.device_serial)
    analyzer = AndroidForensicAnalyzer(adb)

    print("╔══════════════════════════════════════════════════╗")
    print("║     Android Device Forensic Analysis Suite      ║")
    print("╚══════════════════════════════════════════════════╝")
    print()

    try:
        report, json_path, html_path = analyzer.run(output_dir, skip_logs=args.skip_logs)
    except DeviceConnectionError as exc:
        print(f"[ERROR] {exc}")
        return 1
    except AdbError as exc:
        print(f"[ERROR] {exc}")
        return 1

    print("═══════════════════════════════════════════════════")
    print("Analysis Complete!")
    print(f"Status: {report.summary.get('Status')}")
    print(f"Security Score: {report.summary.get('SecurityScore')}/100")

    warnings = report.summary.get("Warnings", [])
    if warnings:
        print()
        print("Warnings detected:")
        for warning in warnings:
            print(f"  - {warning}")

    if report.errors:
        print()
        print("Errors encountered:")
        for error in report.errors:
            print(f"  - {error}")

    print()
    print("Reports saved to:")
    print(f"  JSON: {json_path}")
    print(f"  HTML: {html_path}")

    return 0 if report.summary.get("Status") == "CLEAN" else 1


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(main())
