#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Android Device Forensic Analysis Suite
.DESCRIPTION
    Comprehensive forensic analysis tool for Android devices via ADB
.PARAMETER DeviceSerial
    Optional device serial number for specific device targeting
.PARAMETER OutputPath
    Path where reports and logs will be saved (default: current directory)
.PARAMETER SkipLogCollection
    Skip full logcat collection to save time/space
.EXAMPLE
    .\android-forensic-suite.ps1
    .\android-forensic-suite.ps1 -DeviceSerial "R5CT331ZS4Z" -OutputPath "C:\forensics"
#>

param(
    [string]$DeviceSerial = "",
    [string]$OutputPath = ".",
    [switch]$SkipLogCollection
)

# Configuration
$script:AdbCommand = "adb"
$script:AdbArguments = @()
if ($DeviceSerial) {
    $script:AdbArguments += @("-s", $DeviceSerial)
}

function Invoke-AdbCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [switch]$AllowFailure
    )

    $fullArgs = @()
    if ($script:AdbArguments.Count -gt 0) {
        $fullArgs += $script:AdbArguments
    }
    $fullArgs += $Arguments

    $output = & $script:AdbCommand @fullArgs 2>&1

    if (-not $AllowFailure -and $LASTEXITCODE -ne 0) {
        throw "ADB command failed with exit code $LASTEXITCODE: $output"
    }

    return $output
}

# Ensure output directory exists
if (Test-Path $OutputPath) {
    $OutputPath = (Resolve-Path $OutputPath).Path
} else {
    $OutputPath = (New-Item -Path $OutputPath -ItemType Directory -Force).FullName
}
$script:RunTimestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$ReportPath = Join-Path $OutputPath "forensic-report-$script:RunTimestamp.json"
$HtmlReportPath = Join-Path $OutputPath "forensic-report-$script:RunTimestamp.html"

# Initialize report structure
$Report = @{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Device = @{}
    Security = @{}
    Activity = @{}
    Packages = @{}
    Logs = @{}
    Errors = @()
    Summary = @{}
}

function Write-Status {
    param([string]$Message, [string]$Type = "Info")
    $colors = @{
        "Info" = "Cyan"
        "Success" = "Green"
        "Warning" = "Yellow"
        "Error" = "Red"
    }
    Write-Host "[$Type] $Message" -ForegroundColor $colors[$Type]
}

function Test-AdbConnection {
    Write-Status "Checking ADB connection..."
    try {
        $devices = Invoke-AdbCommand -Arguments @("devices", "-l") -AllowFailure
        if ($devices -match "unauthorized") {
            Write-Status "Device is unauthorized. Please authorize this computer on your device." "Warning"
            return $false
        }
        if ($devices -match "device product:") {
            Write-Status "Device connected successfully" "Success"
            return $true
        }
        Write-Status "No authorized device found" "Error"
        return $false
    } catch {
        Write-Status "ADB command failed: $_" "Error"
        return $false
    }
}

function Get-DeviceInfo {
    Write-Status "Collecting device information..."
    $deviceInfo = @{}
    
    $properties = @{
        "Model" = "ro.product.model"
        "Manufacturer" = "ro.product.manufacturer"
        "AndroidVersion" = "ro.build.version.release"
        "BuildFingerprint" = "ro.build.fingerprint"
        "BuildTags" = "ro.build.tags"
        "BuildType" = "ro.build.type"
        "SecurityPatch" = "ro.build.version.security_patch"
        "Bootloader" = "ro.bootloader"
        "Hardware" = "ro.hardware"
    }
    
    foreach ($key in $properties.Keys) {
        try {
            $value = Invoke-AdbCommand -Arguments @("shell", "getprop", $properties[$key])
            $deviceInfo[$key] = $value.Trim()
        } catch {
            $deviceInfo[$key] = "Error: $_"
            $Report.Errors += "Failed to get $key"
        }
    }
    
    $Report.Device = $deviceInfo
    Write-Status "Device info collected" "Success"
}

function Get-SecurityStatus {
    Write-Status "Checking security status..."
    $security = @{}
    
    # Boot verification
    $security["VerifiedBootState"] = (Invoke-AdbCommand -Arguments @("shell", "getprop", "ro.boot.verifiedbootstate")).Trim()
    $security["VerityMode"] = (Invoke-AdbCommand -Arguments @("shell", "getprop", "ro.boot.veritymode")).Trim()
    $security["BootloaderState"] = (Invoke-AdbCommand -Arguments @("shell", "getprop", "ro.boot.vbmeta.device_state")).Trim()
    $security["SELinux"] = (Invoke-AdbCommand -Arguments @("shell", "getenforce")).Trim()

    # Developer settings
    $security["AdbEnabled"] = (Invoke-AdbCommand -Arguments @("shell", "settings", "get", "global", "adb_enabled")).Trim()
    $security["DeveloperOptions"] = (Invoke-AdbCommand -Arguments @("shell", "settings", "get", "global", "development_settings_enabled")).Trim()

    # Root detection
    $suCheck = Invoke-AdbCommand -Arguments @("shell", "sh", "-c", "which su 2>/dev/null") -AllowFailure
    $security["SuBinary"] = if ($suCheck) { "DETECTED - Device may be rooted!" } else { "Not found (Good)" }

    # User context
    $security["UserContext"] = (Invoke-AdbCommand -Arguments @("shell", "id")).Trim()
    
    $Report.Security = $security
    Write-Status "Security check completed" "Success"
}

function Get-DeviceActivity {
    Write-Status "Collecting device activity information..."
    $activity = @{}
    
    # Uptime
    $uptime = Invoke-AdbCommand -Arguments @("shell", "uptime")
    $activity["Uptime"] = $uptime.Trim()

    # Battery status
    $battery = Invoke-AdbCommand -Arguments @("shell", "dumpsys", "battery") | Select-Object -First 20
    $batteryInfo = @{}
    foreach ($line in $battery) {
        if ($line -match "^\s*(.+?):\s*(.+)$") {
            $batteryInfo[$matches[1]] = $matches[2]
        }
    }
    $activity["Battery"] = $batteryInfo
    
    # USB status
    $usbStatus = Invoke-AdbCommand -Arguments @("shell", "dumpsys", "usb") | Select-Object -First 30
    $activity["USBConnection"] = ($usbStatus | Where-Object { $_ -match "current_functions|connected|configured" }) -join "; "
    
    $Report.Activity = $activity
    Write-Status "Activity information collected" "Success"
}

function Get-PackageInfo {
    Write-Status "Collecting package information..."
    $packages = @{}
    
    try {
        # Get all packages for main user
        $allPackages = Invoke-AdbCommand -Arguments @("shell", "pm", "list", "packages", "--user", "0")
        $packages["TotalCount"] = ($allPackages | Measure-Object).Count

        # Get third-party packages
        $thirdParty = Invoke-AdbCommand -Arguments @("shell", "pm", "list", "packages", "-3", "--user", "0")
        $packages["ThirdPartyCount"] = ($thirdParty | Where-Object { $_ -match "^package:" } | Measure-Object).Count

        # Sample of installed packages
        $packages["SamplePackages"] = $allPackages | Select-Object -First 10 | ForEach-Object { 
            if ($_ -match "package:(.+)") { $matches[1] } 
        }
    } catch {
        $packages["Error"] = "Failed to retrieve package list: $_"
        $Report.Errors += "Package list retrieval failed"
    }
    
    $Report.Packages = $packages
    Write-Status "Package information collected" "Success"
}

function Collect-Logs {
    if ($SkipLogCollection) {
        Write-Status "Skipping full log collection (flag set)" "Warning"
        $Report.Logs["Status"] = "Skipped by user"
        return
    }
    
    Write-Status "Collecting device logs..."
    $logs = @{}

    try {
        # Save full logcat
        $logcatPath = Join-Path $OutputPath "logcat-$script:RunTimestamp.txt"
        $logOutput = Invoke-AdbCommand -Arguments @("logcat", "-d") -AllowFailure
        Set-Content -Path $logcatPath -Value $logOutput -Encoding UTF8
        $logSize = (Get-Item $logcatPath).Length / 1MB
        $logs["FullLogPath"] = $logcatPath
        $logs["LogSizeMB"] = [math]::Round($logSize, 2)

        # Extract suspicious entries
        $suspiciousPath = Join-Path $OutputPath "suspicious-$script:RunTimestamp.txt"
        Select-String -Path $logcatPath -Pattern 'adbd|usb|debug|reboot|panic|auth|root|su' -SimpleMatch:$false |
            Select-Object -First 100 |
            Out-File -FilePath $suspiciousPath -Encoding UTF8
        $logs["SuspiciousLogPath"] = $suspiciousPath

        # Count authentication events
        $authEvents = Select-String -Path $logcatPath -Pattern 'authenticated|authorization' | Measure-Object
        $logs["AuthenticationEvents"] = $authEvents.Count

    } catch {
        $logs["Error"] = "Failed to collect logs: $_"
        $Report.Errors += "Log collection failed"
    }
    
    $Report.Logs = $logs
    Write-Status "Log collection completed" "Success"
}

function Analyze-Results {
    Write-Status "Analyzing results..."
    $summary = @{
        "IsSecure" = $true
        "Warnings" = @()
        "SecurityScore" = 100
    }
    
    # Check for root
    if ($Report.Security.SuBinary -match "DETECTED") {
        $summary.Warnings += "Device appears to be rooted"
        $summary.IsSecure = $false
        $summary.SecurityScore -= 50
    }
    
    # Check boot state
    if ($Report.Security.VerifiedBootState -ne "green") {
        $summary.Warnings += "Boot verification not in secure state"
        $summary.SecurityScore -= 20
    }
    
    # Check bootloader
    if ($Report.Security.BootloaderState -ne "locked") {
        $summary.Warnings += "Bootloader is unlocked"
        $summary.SecurityScore -= 30
    }
    
    # Check SELinux
    if ($Report.Security.SELinux -ne "Enforcing") {
        $summary.Warnings += "SELinux not enforcing"
        $summary.SecurityScore -= 20
    }
    
    # Check build type
    if ($Report.Device.BuildTags -ne "release-keys") {
        $summary.Warnings += "Non-release build detected"
        $summary.SecurityScore -= 10
    }
    
    if ($summary.Warnings.Count -gt 0) {
        $summary.IsSecure = $false
    }

    $summary.SecurityScore = [Math]::Max(0, $summary.SecurityScore)
    $summary.Status = if ($summary.IsSecure) { "CLEAN" } else { "SUSPICIOUS" }
    
    $Report.Summary = $summary
    Write-Status "Analysis completed" "Success"
}

function Export-Report {
    Write-Status "Exporting reports..."
    
    # JSON report
    $Report | ConvertTo-Json -Depth 10 | Out-File $ReportPath
    Write-Status "JSON report saved to: $ReportPath" "Success"
    
    # HTML report
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Android Forensic Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: auto; background: white; padding: 20px; border-radius: 10px; }
        h1 { color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        .status-clean { color: green; font-weight: bold; }
        .status-suspicious { color: red; font-weight: bold; }
        .warning { background: #fff3cd; padding: 10px; border-left: 4px solid #ffc107; margin: 10px 0; }
        .info-grid { display: grid; grid-template-columns: 1fr 2fr; gap: 10px; }
        .info-label { font-weight: bold; color: #666; }
        .score { font-size: 48px; font-weight: bold; }
        .score-high { color: green; }
        .score-medium { color: orange; }
        .score-low { color: red; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Android Device Forensic Analysis Report</h1>
        <p><strong>Generated:</strong> $($Report.Timestamp)</p>
        
        <h2>📊 Summary</h2>
        <div class="info-grid">
            <div class="info-label">Status:</div>
            <div class="$(if ($Report.Summary.Status -eq 'CLEAN') { 'status-clean' } else { 'status-suspicious' })">
                $($Report.Summary.Status)
            </div>
            <div class="info-label">Security Score:</div>
            <div class="score $(if ($Report.Summary.SecurityScore -ge 80) { 'score-high' } elseif ($Report.Summary.SecurityScore -ge 50) { 'score-medium' } else { 'score-low' })">
                $($Report.Summary.SecurityScore)/100
            </div>
        </div>
        
        $(if ($Report.Summary.Warnings.Count -gt 0) {
            "<h3>⚠️ Warnings</h3>"
            $Report.Summary.Warnings | ForEach-Object { "<div class='warning'>$_</div>" }
        })
        
        <h2>📱 Device Information</h2>
        <table>
            <tr><th>Property</th><th>Value</th></tr>
            $(foreach ($key in $Report.Device.Keys) {
                "<tr><td>$key</td><td>$($Report.Device[$key])</td></tr>"
            })
        </table>
        
        <h2>🔒 Security Status</h2>
        <table>
            <tr><th>Check</th><th>Result</th></tr>
            $(foreach ($key in $Report.Security.Keys) {
                "<tr><td>$key</td><td>$($Report.Security[$key])</td></tr>"
            })
        </table>
        
        <h2>📦 Package Information</h2>
        <p><strong>Total Packages:</strong> $($Report.Packages.TotalCount)</p>
        <p><strong>Third-party Packages:</strong> $($Report.Packages.ThirdPartyCount)</p>
        
        <h2>📝 Logs</h2>
        $(if ($Report.Logs.Status -eq "Skipped by user") {
            "<p>Log collection was skipped.</p>"
        } else {
            "<p><strong>Log Size:</strong> $($Report.Logs.LogSizeMB) MB</p>"
            "<p><strong>Authentication Events:</strong> $($Report.Logs.AuthenticationEvents)</p>"
        })
        
        $(if ($Report.Errors.Count -gt 0) {
            "<h2>❌ Errors</h2>"
            "<ul>"
            $Report.Errors | ForEach-Object { "<li>$_</li>" }
            "</ul>"
        })
    </div>
</body>
</html>
"@
    
    $html | Out-File $HtmlReportPath
    Write-Status "HTML report saved to: $HtmlReportPath" "Success"
}

# Main execution
function Start-ForensicAnalysis {
    Write-Host "╔══════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║     Android Device Forensic Analysis Suite      ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    # Check ADB connection
    if (-not (Test-AdbConnection)) {
        Write-Status "Please connect and authorize your device, then run the script again." "Error"
        exit 1
    }
    
    # Run analysis modules
    Get-DeviceInfo
    Get-SecurityStatus
    Get-DeviceActivity
    Get-PackageInfo
    Collect-Logs
    Analyze-Results
    Export-Report
    
    # Display summary
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "Analysis Complete!" -ForegroundColor Green
    Write-Host "Status: $($Report.Summary.Status)" -ForegroundColor $(if ($Report.Summary.Status -eq 'CLEAN') { 'Green' } else { 'Red' })
    Write-Host "Security Score: $($Report.Summary.SecurityScore)/100" -ForegroundColor $(if ($Report.Summary.SecurityScore -ge 80) { 'Green' } elseif ($Report.Summary.SecurityScore -ge 50) { 'Yellow' } else { 'Red' })
    
    if ($Report.Summary.Warnings.Count -gt 0) {
        Write-Host ""
        Write-Host "Warnings detected:" -ForegroundColor Yellow
        $Report.Summary.Warnings | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
    }
    
    Write-Host ""
    Write-Host "Reports saved to:" -ForegroundColor Cyan
    Write-Host "  JSON: $ReportPath" -ForegroundColor White
    Write-Host "  HTML: $HtmlReportPath" -ForegroundColor White
    
    # Return exit code based on security status
    exit $(if ($Report.Summary.Status -eq 'CLEAN') { 0 } else { 1 })
}

# Run the analysis
Start-ForensicAnalysis
