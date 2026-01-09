# ===============================
# THVO Tweaks 1-Click Installer
# ===============================

# --- Require Admin ---
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {

    Start-Process powershell `
        -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" `
        -Verb RunAs
    exit
}

Write-Host "Installing THVO Tweaks..." -ForegroundColor Cyan

# --- Install Path ---
$InstallDir = "$env:ProgramData\THVO-Tweaks"
$ScriptPath = "$InstallDir\THVO-Tweaks-GUI.ps1"

# --- Create Folder ---
if (!(Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir | Out-Null
}

# --- Download Main Script ---
$Url = "https://raw.githubusercontent.com/uwukittensx3-prog/THVO-Tweaks/main/THVO-Tweaks-GUI.ps1"

Invoke-WebRequest -Uri $Url -OutFile $ScriptPath -UseBasicParsing

# --- Create Desktop Shortcut ---
$ShortcutPath = "$env:Public\Desktop\THVO Tweaks.lnk"
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)

$Shortcut.TargetPath = "powershell.exe"
$Shortcut.Arguments = "-ExecutionPolicy Bypass -File `"$ScriptPath`""
$Shortcut.WorkingDirectory = $InstallDir
$Shortcut.IconLocation = "powershell.exe"
$Shortcut.Save()

# --- Launch App ---
Start-Process powershell `
    -ArgumentList "-ExecutionPolicy Bypass -File `"$ScriptPath`"" `
    -Verb RunAs

Write-Host "THVO Tweaks installed successfully!" -ForegroundColor Green
