# 🔍 Android Device Forensic Analysis Suite

A comprehensive PowerShell-based forensic analysis tool for Android devices that performs security assessments and generates detailed reports. This tool can be run locally or automated via GitHub Actions.

## ✨ Features

- **Complete Device Analysis**: Comprehensive security assessment of Android devices
- **Root Detection**: Identifies if device has been rooted or modified
- **Boot Security Verification**: Checks verified boot state, SELinux, and bootloader status
- **Package Analysis**: Lists and analyzes installed applications
- **Activity Monitoring**: Tracks device uptime, battery status, and USB connections
- **Log Collection**: Captures and filters device logs for suspicious activities
- **Multiple Report Formats**: Generates both JSON and HTML reports
- **GitHub Actions Integration**: Run forensic analysis in CI/CD pipelines
- **Security Scoring**: Provides a 0-100 security score based on findings

## 📋 Prerequisites

- **ADB (Android Debug Bridge)**: Must be installed and in system PATH
  - Download from: [Android SDK Platform Tools](https://developer.android.com/studio/releases/platform-tools)
  - Or install via package manager:
    ```bash
    # Windows (with Chocolatey)
    choco install adb
    
    # macOS (with Homebrew)
    brew install android-platform-tools
    
    # Linux (Debian/Ubuntu)
    sudo apt-get install android-tools-adb
    ```

- **PowerShell 7+**: Required for cross-platform compatibility
  - [Download PowerShell](https://github.com/PowerShell/PowerShell/releases)

- **Android Device Setup**:
  1. Enable Developer Options (tap Build Number 7 times in Settings > About)
  2. Enable USB Debugging in Developer Options
  3. Connect device via USB and authorize the computer

## 🚀 Quick Start

### Local Usage

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/android-forensic-suite.git
   cd android-forensic-suite
   ```

2. **Run the analysis:**
   ```powershell
   # Basic usage (analyzes first connected device)
   .\android-forensic-suite.ps1
   
   # Specify device serial and output directory
   .\android-forensic-suite.ps1 -DeviceSerial "R5CT331ZS4Z" -OutputPath "C:\forensics"
   
   # Skip log collection for faster analysis
   .\android-forensic-suite.ps1 -SkipLogCollection
   ```

### GitHub Actions Usage

1. **Fork this repository**

2. **Add your device to GitHub Actions (self-hosted runner):**
   - Set up a self-hosted runner on a machine with the Android device connected
   - Follow [GitHub's self-hosted runner guide](https://docs.github.com/en/actions/hosting-your-own-runners)

3. **Run the workflow:**
   - Go to Actions tab
   - Select "Android Forensic Analysis"
   - Click "Run workflow"
   - Optionally specify device serial

## 📊 Security Checks Performed

| Category | Checks |
|----------|--------|
| **Boot Security** | Verified boot state, Verity mode, Bootloader lock status, SELinux enforcement |
| **Root Detection** | SU binary presence, User context verification |
| **Build Integrity** | Build tags, Build type, Security patch level |
| **Device Settings** | Developer options status, ADB enablement |
| **Activity Analysis** | Uptime monitoring, Battery statistics, USB connection logs |
| **Package Analysis** | Total package count, Third-party app detection |
| **Log Analysis** | Authentication events, Suspicious activity patterns |

## 📈 Security Scoring System

The tool assigns a security score from 0-100 based on:

- **-50 points**: Root detection
- **-30 points**: Unlocked bootloader
- **-20 points**: Non-green boot verification state
- **-20 points**: SELinux not enforcing
- **-10 points**: Non-release build keys

**Score Interpretation:**
- 🟢 **80-100**: Device appears secure
- 🟡 **50-79**: Some security concerns detected
- 🔴 **0-49**: Significant security issues found

## 📁 Output Files

The suite generates the following files:

- `forensic-report-[timestamp].json` - Detailed JSON report with all findings
- `forensic-report-[timestamp].html` - User-friendly HTML report with visualizations
- `logcat-[timestamp].txt` - Complete device logs (if not skipped)
- `suspicious-[timestamp].txt` - Filtered logs showing potential security issues

## 🤖 GitHub Actions Workflow

The included GitHub Actions workflow allows you to:

1. **Schedule regular scans** of connected devices
2. **Trigger manual scans** on demand
3. **Upload reports** as artifacts
4. **Get notifications** for security issues

### Workflow Configuration

Edit `.github/workflows/android-forensic.yml` to customize:

- Trigger conditions (push, pull request, schedule)
- Device serial numbers
- Report retention period
- Notification settings

## 🛠️ Advanced Usage

### Multiple Device Analysis

```powershell
# Analyze multiple devices in sequence
@("device1_serial", "device2_serial") | ForEach-Object {
    .\android-forensic-suite.ps1 -DeviceSerial $_ -OutputPath "reports\$_"
}
```

### Automated Monitoring

```powershell
# Run analysis every hour
while ($true) {
    .\android-forensic-suite.ps1 -OutputPath "monitoring\$(Get-Date -Format 'yyyyMMdd-HH')"
    Start-Sleep -Seconds 3600
}
```

### Parse JSON Results

```powershell
# Load and analyze JSON report
$report = Get-Content "forensic-report-*.json" | ConvertFrom-Json
if ($report.Summary.Status -eq "SUSPICIOUS") {
    Write-Warning "Security issues detected!"
    $report.Summary.Warnings | ForEach-Object { Write-Warning $_ }
}
```

## 🔒 Security Considerations

This repository is designed to be **safe for public use**. For detailed security information, see [SECURITY.md](SECURITY.md).

**Key Points:**
- **Public Repository Safe** - No hardcoded credentials, read-only analysis
- **Local Data Control** - Reports stay on your machine unless you share them
- **Fork-Friendly** - Each user runs workflows independently with their own secrets
- **Privacy Focused** - Sensitive data is filtered from logs and reports

**Usage Options:**
- **Fork the repository** (recommended for GitHub Actions)
- **Download and run locally** (maximum privacy control)

- **Privacy**: Reports may contain sensitive device information
- **Storage**: Secure report files appropriately
- **Credentials**: Never commit device credentials or tokens
- **Network**: Use secure connections when transferring reports

## 📝 Report Sections

### HTML Report
- Visual security score with color coding
- Device specifications and build information
- Security status table with all checks
- Warning highlights for issues found
- Package statistics
- Log analysis summary

### JSON Report
- Machine-readable format
- Complete raw data from all checks
- Timestamped entries
- Error logging
- Suitable for automated processing

## 🐛 Troubleshooting

| Issue | Solution |
|-------|----------|
| "No devices found" | Ensure device is connected and USB debugging is authorized |
| "Unauthorized device" | Check device screen for authorization prompt |
| "ADB not found" | Add ADB to system PATH or specify full path |
| "Permission denied" | Run with appropriate privileges or check device permissions |
| "Package list error" | Some devices restrict package listing - use `-SkipPackages` flag |

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details

## 🙏 Acknowledgments

- Android Open Source Project for ADB
- PowerShell team for cross-platform support
- Security research community for forensic techniques

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/android-forensic-suite/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/android-forensic-suite/discussions)
- **Security**: Report security issues privately via GitHub Security tab

## 🗺️ Roadmap

- [ ] Add network traffic analysis
- [ ] Implement malware detection
- [ ] Add support for iOS devices
- [ ] Create web-based dashboard
- [ ] Add real-time monitoring mode
- [ ] Implement encrypted report storage
- [ ] Add custom rule definitions
- [ ] Support for multiple report languages

---

**⚠️ Disclaimer**: This tool is for legitimate security analysis only. Always obtain proper authorization before analyzing devices. The authors are not responsible for misuse of this tool.
