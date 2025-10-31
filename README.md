# 🔍 Android Device Forensic Analysis Suite

A comprehensive forensic analysis toolkit for Android devices that performs deep security assessments, produces actionable
reports, and now ships with a modern React dashboard for effortless visualization. The suite can be run locally or automated
through GitHub Actions.

## ✨ Features

- **Complete Device Analysis** – Collects rich metadata about the connected Android device, including build, hardware, and
  runtime characteristics.
- **Security & Integrity Checks** – Validates verified boot, bootloader lock status, SELinux, debugging options, OEM
  unlocking, unknown sources, and more to build a holistic risk profile.
- **Root Detection** – Detects SU binaries and captures the executing user context to highlight privilege escalation risks.
- **Network & Performance Insights** – Captures Wi-Fi state, interface metadata, storage utilisation, and the top CPU-hungry
  processes for quick triage and visual analytics.
- **Package Intelligence** – Summarises installed applications, highlights third-party apps, and surfaces quick samples.
- **Log Collection** – Harvests logcat output, extracts authentication events, and curates a suspicious activity subset.
- **Rich Reporting** – Generates JSON and HTML reports with responsive visual styling, risk factor cards, and score
  breakdown tables ready for presentations.
- **Interactive Web Dashboard** – React + Vite frontend for importing reports, exploring visualisations, and preparing
  shareable insights; deployable on free hosting providers.
- **CI/CD Ready** – GitHub Actions workflow for scheduled or on-demand assessments.

## 📋 Prerequisites

- **ADB (Android Debug Bridge)** must be installed and in the system `PATH`.
  - Download from: [Android SDK Platform Tools](https://developer.android.com/studio/releases/platform-tools)
  - Or install via package manager:
    ```bash
    # Windows (Chocolatey)
    choco install adb

    # macOS (Homebrew)
    brew install android-platform-tools

    # Linux (Debian/Ubuntu)
    sudo apt-get install android-tools-adb
    ```
- **PowerShell 7+** for the cross-platform automation scripts.
- **Android Device Setup**
  1. Enable Developer Options (tap Build Number 7 times in *Settings → About*).
  2. Enable USB Debugging in Developer Options.
  3. Connect the device via USB and authorise the computer when prompted.

## 🚀 Quick Start

### Local Usage (PowerShell)

1. **Clone the repository**
   ```powershell
   git clone https://github.com/yourusername/android-forensic-suite.git
   cd android-forensic-suite
   ```
2. **Run the analysis**
   ```powershell
   # Analyse the first detected device
   .\android-forensic-suite.ps1

   # Specify device serial and output directory
   .\android-forensic-suite.ps1 -DeviceSerial "R5CT331ZS4Z" -OutputPath "C:\\forensics"

   # Skip log collection for faster execution
   .\android-forensic-suite.ps1 -SkipLogCollection
   ```

### GitHub Actions Usage

1. Fork the repository.
2. Configure a self-hosted runner connected to your target Android device.
3. Trigger the **Android Forensic Analysis** workflow from the Actions tab (manual or scheduled).

## 📊 Security Checks Performed

| Category               | Checks                                                                                                                                 |
|-----------------------|----------------------------------------------------------------------------------------------------------------------------------------|
| **Boot Security**     | Verified boot state, VBMeta device state, verity mode, bootloader lock, SELinux enforcement                                            |
| **Root Detection**    | SU binary lookup and path capture, runtime user context                                                                                |
| **Build Integrity**   | Build tags, build type, manufacturer & hardware identifiers, security patch level                                                      |
| **Device Settings**   | ADB debugging toggle, developer options, unknown sources, debugger state, OEM unlock allowance, secure mode flag                       |
| **Activity Analysis** | Uptime, battery summary, USB connection insights                                                                                       |
| **Performance**       | /data partition utilisation, top CPU-intensive processes                                                                               |
| **Network Analysis**  | Wi-Fi enablement, supplicant state, SSID/BSSID, interface state, MAC, and assigned IP addresses                                        |
| **Log Analysis**      | Authentication events, suspicious log sampling                                                                                         |
| **Package Analysis**  | Total package count, third-party applications, quick sample list                                                                      |

## 📈 Security Scoring System

The analyser now maintains a granular score breakdown ideal for dashboards.

| Impact | Condition (deducted when **false**)                     |
|-------:|---------------------------------------------------------|
|  50 pts| Root binaries absent                                    |
|  30 pts| Bootloader locked                                       |
|  20 pts| Verified boot integrity                                 |
|  20 pts| SELinux enforcing                                       |
|  15 pts| Secure mode enabled                                     |
|  15 pts| OEM unlocking disabled                                  |
|  10 pts| Release build tags                                      |
|  10 pts| ADB debugging disabled                                  |
|  10 pts| Unknown sources disabled                                |
|  10 pts| System debugger disabled                                |
|   5 pts| Developer options disabled                              |

**Score Interpretation**
- 🟢 **80-100** – Device appears secure.
- 🟡 **50-79** – Review highlighted warnings.
- 🔴 **0-49** – Critical actions required.

Each failed check is surfaced as a risk card with severity, description, and score impact for effortless charting in the
frontend dashboard.

## 📁 Output Files

- `forensic-report-[timestamp].json` – Machine-readable report containing every collected datum.
- `forensic-report-[timestamp].html` – Elegant HTML with responsive styling, score breakdown, and risk highlights.
- `logcat-[timestamp].txt` – Full logcat capture (when enabled).
- `suspicious-[timestamp].txt` – Filtered log subset with suspicious keywords.

## 🖥️ React Dashboard

The `/frontend` directory hosts a Vite-powered React application tailor-made for visualising forensic reports.

### Run the Dashboard Locally

```bash
cd frontend
npm install
npm run dev
```

Navigate to `http://localhost:5173` (default Vite port) and use the **Upload Report** button or **Load Sample** action to see
interactive cards, charts, and network/process tables.

### Build for Production

```bash
npm run build
npm run preview  # Optional local verification
```

The build output is emitted to `frontend/dist/` and can be hosted on any static site service.

### Free Hosting Options

- **GitHub Pages** – Add `"homepage": "https://<user>.github.io/<repo>"` to `package.json`, install `gh-pages`, and run
  `npm run deploy`.
- **Netlify** – Drag the `dist/` folder into the Netlify dashboard or connect the repo with build command `npm run build` and
  publish directory `frontend/dist`.
- **Vercel** – Import the repository, set framework to *Vite*, build command `npm run build`, output `frontend/dist`.

## 🧪 Testing

The Python suite uses a deterministic fake ADB shim to validate risk scoring, network parsing, and exporting routines. Run:

```bash
pytest
```

## 🤖 GitHub Actions Workflow

Use the provided workflow to schedule regular scans, trigger manual runs, upload reports as artefacts, and alert on
suspicious findings. Adjust `.github/workflows/android-forensic.yml` to tweak triggers, output paths, or retention policies.

## 🛠️ Advanced Usage

### Multiple Device Analysis

```powershell
# Analyse multiple devices sequentially
@("device1_serial", "device2_serial") | ForEach-Object {
    .\android-forensic-suite.ps1 -DeviceSerial $_ -OutputPath "reports\$_"
}
```

### Automated Monitoring

```powershell
# Run analysis hourly
while ($true) {
    .\android-forensic-suite.ps1 -OutputPath "monitoring\$(Get-Date -Format 'yyyyMMdd-HH')"
    Start-Sleep -Seconds 3600
}
```

### Parse JSON Results in PowerShell

```powershell
$report = Get-Content "forensic-report-*.json" | ConvertFrom-Json
if ($report.Summary.Status -eq "SUSPICIOUS") {
    Write-Warning "Security issues detected!"
    $report.Summary.Warnings | ForEach-Object { Write-Warning $_ }
}
```

## 🔒 Security Considerations

This repository is safe for public use. See [SECURITY.md](SECURITY.md) for detailed policies.

- **Public Repository Safe** – No hardcoded credentials; runs read-only checks.
- **Local Data Control** – Reports stay on your machine unless you share them.
- **Fork Friendly** – Bring your own secrets for CI.
- **Privacy Mindful** – Log scrubbing keeps sensitive material minimal.

## 🐛 Troubleshooting

| Issue                  | Solution                                                                 |
|------------------------|--------------------------------------------------------------------------|
| "No devices found"     | Ensure the device is connected, unlocked, and authorised.               |
| "Unauthorized device"  | Check the device screen for the debugging authorisation prompt.         |
| "ADB not found"        | Install ADB and add it to `PATH`, or provide the absolute executable.    |
| "Permission denied"    | Run the script with appropriate privileges or re-check device policies. |
| "Package list error"   | Some OEM builds restrict listing; rerun with `-SkipLogCollection` etc.  |

## 🤝 Contributing

1. Fork the repository.
2. Create a feature branch.
3. Implement your changes (with tests when possible).
4. Submit a pull request.

## 📄 License

MIT License – see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- Android Open Source Project for ADB.
- PowerShell and Python communities for cross-platform tooling.
- Security researchers whose techniques inspired the risk modelling.

## 🗺️ Roadmap

- [x] Create web-based dashboard for report exploration.
- [ ] Add network traffic capture and analysis.
- [ ] Implement malware signature detection.
- [ ] Introduce real-time monitoring mode.
- [ ] Provide encrypted report storage.
- [ ] Offer customisable rule definitions.
- [ ] Localise reports into additional languages.

---

**⚠️ Disclaimer**: Use this tool responsibly and only on devices you have permission to analyse. The authors are not liable
for misuse.
