# =====================================
# THVO Tweaks - Windows Optimization
# =====================================

# ---------- Admin Check ----------
If (-NOT ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Start-Process powershell "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

$Host.UI.RawUI.WindowTitle = "THVO Tweaks - Windows Optimization Tool"

# ---------- Globals ----------
$BackupPath = "$env:SystemDrive\THVO_Tweaks_Backup"
New-Item -ItemType Directory -Force -Path $BackupPath | Out-Null

# ---------- UI ----------
function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host " ████████╗██╗  ██╗██╗   ██╗ ██████╗ "
    Write-Host " ╚══██╔══╝██║  ██║██║   ██║██╔═══██╗"
    Write-Host "    ██║   ███████║██║   ██║██║   ██║"
    Write-Host "    ██║   ██╔══██║██║   ██║██║   ██║"
    Write-Host "    ██║   ██║  ██║╚██████╔╝╚██████╔╝"
    Write-Host "    ╚═╝   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ "
    Write-Host ""
    Write-Host " THVO Tweaks - Performance | Privacy | Control"
    Write-Host ""
}

# ---------- Backup Helpers ----------
function Backup-Reg {
    param ($Path, $Name)
    reg query $Path /v $Name > "$BackupPath\$($Name).regbak" 2>$null
}

function Restore-Reg {
    param ($Path, $Name, $Default)
    reg add $Path /v $Name /t REG_DWORD /d $Default /f
}

# ---------- Core Tweaks ----------
function Reduce-Processes {
    $services = @(
        "SysMain","DiagTrack","WSearch",
        "MapsBroker","Fax","XboxGipSvc",
        "XblGameSave","XboxNetApiSvc"
    )
    foreach ($s in $services) {
        Set-Service $s -StartupType Disabled -ErrorAction SilentlyContinue
        Stop-Service $s -Force -ErrorAction SilentlyContinue
    }
}

function Undo-Processes {
    $services = @("SysMain","WSearch")
    foreach ($s in $services) {
        Set-Service $s -StartupType Automatic -ErrorAction SilentlyContinue
    }
}

# ---------- Performance Tweaks ----------
function Apply-Performance {
    # Telemetry
    Backup-Reg "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry"
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f

    # Cortana
    Backup-Reg "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana"
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f

    # Background apps
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" `
        /v GlobalUserDisabled /t REG_DWORD /d 1 /f

    # Hibernation off
    powercfg -h off

    # High performance plan
    powercfg -setactive SCHEME_MIN

    # Game DVR off
    reg add "HKCU\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f
}

function Undo-Performance {
    Restore-Reg "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 1
    Restore-Reg "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana" 1
    powercfg -h on
}

# ---------- Debloat ----------
function Debloat-Windows {
    $apps = @(
        "Microsoft.Xbox*",
        "Microsoft.GetHelp",
        "Microsoft.Getstarted",
        "Microsoft.Microsoft3DViewer",
        "Microsoft.MixedReality.Portal",
        "Microsoft.ZuneMusic",
        "Microsoft.ZuneVideo",
        "Microsoft.BingNews",
        "Microsoft.BingWeather",
        "Microsoft.People"
    )

    foreach ($app in $apps) {
        Get-AppxPackage -AllUsers $app | Remove-AppxPackage -ErrorAction SilentlyContinue
    }
}

# ---------- Profiles ----------
function LowEnd-PC {
    Reduce-Processes
    Apply-Performance
    Debloat-Windows
    reg add "HKCU\Control Panel\Desktop" /v MenuShowDelay /t REG_SZ /d 0 /f
}

function HighEnd-PC {
    Apply-Performance
    reg add "HKCU\Software\Microsoft\GameBar" /v AllowAutoGameMode /t REG_DWORD /d 1 /f
}

# ---------- UNDO ALL ----------
function Undo-All {
    Undo-Processes
    Undo-Performance
    Write-Host "Undo complete. Restart recommended."
}

# ---------- MENU ----------
function Show-Menu {
    Write-Host " [1] Reduce Background Processes"
    Write-Host " [2] Apply Performance Tweaks"
    Write-Host " [3] Windows Debloat"
    Write-Host " [4] Low-End PC Profile"
    Write-Host " [5] High-End PC Profile"
    Write-Host " [6] UNDO ALL Tweaks"
    Write-Host " [0] Exit"
    Write-Host ""
}

# ---------- LOOP ----------
do {
    Show-Banner
    Show-Menu
    $choice = Read-Host "Select an option"

    switch ($choice) {
        "1" { Reduce-Processes; Pause }
        "2" { Apply-Performance; Pause }
        "3" { Debloat-Windows; Pause }
        "4" { LowEnd-PC; Pause }
        "5" { HighEnd-PC; Pause }
        "6" { Undo-All; Pause }
        "0" { Exit }
        default { Write-Host "Invalid choice"; Pause }
    }
} while ($true)
