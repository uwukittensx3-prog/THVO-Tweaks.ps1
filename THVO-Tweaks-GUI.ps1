# ==============================
# THVO Tweaks - Full GUI Edition
# ==============================

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ---------- ADMIN ----------
if (-not ([Security.Principal.WindowsPrincipal]
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# ---------- GLOBAL BACKUP ----------
$Global:Backup = @{
    Registry = @{}
    Services = @{}
}

# ---------- BACKUP HELPERS ----------
function Backup-RegValue($Path,$Name){
    $key = "$Path|$Name"
    if (-not $Global:Backup.Registry.ContainsKey($key)) {
        try {
            $val = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
            $Global:Backup.Registry[$key] = $val
        } catch {
            $Global:Backup.Registry[$key] = $null
        }
    }
}

function Set-RegDWORD($Path,$Name,$Value){
    Backup-RegValue $Path $Name
    New-Item -Path $Path -Force | Out-Null
    Set-ItemProperty -Path $Path -Name $Name -Type DWord -Value $Value
}

function Backup-Service($Name){
    if (-not $Global:Backup.Services.ContainsKey($Name)) {
        $svc = Get-Service $Name -ErrorAction SilentlyContinue
        if ($svc) { $Global:Backup.Services[$Name] = $svc.StartType }
    }
}

function Disable-Service($Name){
    Backup-Service $Name
    Stop-Service $Name -Force -ErrorAction SilentlyContinue
    Set-Service $Name -StartupType Disabled -ErrorAction SilentlyContinue
}

# ---------- GUI ----------
$form = New-Object System.Windows.Forms.Form
$form.Text = "THVO Tweaks - Performance Control Center"
$form.Size = "1100,700"
$form.StartPosition = "CenterScreen"

$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Dock = "Fill"
$form.Controls.Add($tabs)

function Add-Tab($name){
    $tab = New-Object System.Windows.Forms.TabPage
    $tab.Text = $name
    $tabs.TabPages.Add($tab)
    return $tab
}

function Add-Button($tab,$text,$x,$y,$action){
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = $text
    $btn.Size = "300,40"
    $btn.Location = New-Object System.Drawing.Point($x,$y)
    $btn.Add_Click($action)
    $tab.Controls.Add($btn)
}

# ================= FPS / GAMING =================
$fps = Add-Tab "FPS / Gaming"

Add-Button $fps "Disable Game DVR" 20 20 {
    Set-RegDWORD "HKCU:\System\GameConfigStore" "GameDVR_Enabled" 0
}

Add-Button $fps "Disable Xbox Services" 20 70 {
    "XboxGipSvc","XblGameSave","XboxNetApiSvc" | ForEach-Object { Disable-Service $_ }
}

Add-Button $fps "Enable Hardware GPU Scheduling" 20 120 {
    Set-RegDWORD "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" "HwSchMode" 2
}

Add-Button $fps "Disable Fullscreen Optimizations" 20 170 {
    Set-RegDWORD "HKCU:\System\GameConfigStore" "GameDVR_FSEBehaviorMode" 2
}

# ================= INTERNET =================
$net = Add-Tab "Internet / Network"

Add-Button $net "Disable Nagle Algorithm" 20 20 {
    Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" |
    ForEach-Object {
        Set-RegDWORD $_.PSPath "TcpAckFrequency" 1
        Set-RegDWORD $_.PSPath "TCPNoDelay" 1
    }
}

Add-Button $net "Optimize TCP (Gaming)" 20 70 {
    netsh int tcp set global autotuninglevel=normal
    netsh int tcp set global congestionprovider=ctcp
}

Add-Button $net "Disable Network Throttling" 20 120 {
    Set-RegDWORD "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" `
    "NetworkThrottlingIndex" 4294967295
}

# ================= INTERNET ADV =================
$netAdv = Add-Tab "Internet (Advanced)"

Add-Button $netAdv "Disable QoS Bandwidth Limit" 20 20 {
    Set-RegDWORD "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" "NonBestEffortLimit" 0
}

Add-Button $netAdv "Multimedia Network Priority" 20 70 {
    Set-RegDWORD "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" `
    "SystemResponsiveness" 0
}

Add-Button $netAdv "Flush DNS Cache" 20 120 {
    ipconfig /flushdns
}

# ================= WI-FI =================
$wifi = Add-Tab "Wi-Fi Tweaks"

Add-Button $wifi "Disable Wi-Fi Power Saving" 20 20 {
    powercfg -setacvalueindex SCHEME_CURRENT SUB_WIFI WLANPOWER 0
    powercfg -setactive SCHEME_CURRENT
}

Add-Button $wifi "Disable Roaming Aggressiveness" 20 70 {
    Get-NetAdapter -Physical | ForEach-Object {
        Set-NetAdapterAdvancedProperty -Name $_.Name `
        -DisplayName "Roaming Aggressiveness" -DisplayValue "Lowest" `
        -ErrorAction SilentlyContinue
    }
}

Add-Button $wifi "Disable Packet Coalescing" 20 120 {
    Get-NetAdapter -Physical | ForEach-Object {
        Set-NetAdapterAdvancedProperty -Name $_.Name `
        -DisplayName "Packet Coalescing" -DisplayValue "Disabled" `
        -ErrorAction SilentlyContinue
    }
}

# ================= USB =================
$usb = Add-Tab "USB Tweaks"

# ================= USB =================
$usb = Add-Tab "USB Tweaks"

Add-Button $usb "Disable USB Selective Suspend" 20 20 {
    Set-RegDWORD "HKLM:\SYSTEM\CurrentControlSet\Services\USB" "DisableSelectiveSuspend" 1
    powercfg -setacvalueindex SCHEME_CURRENT SUB_USB USBSELECTIVE SUSPEND 0
    powercfg -setactive SCHEME_CURRENT
}

Add-Button $usb "Disable USB Power Saving (All Hubs)" 20 70 {
    Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Enum\USB" -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.PSChildName -eq "Device Parameters" } |
    ForEach-Object {
        Set-RegDWORD $_.PSPath "EnhancedPowerManagementEnabled" 0
    }
}

Add-Button $usb "Improve USB Input Stability (Basic)" 20 120 {
    Set-RegDWORD "HKLM:\SYSTEM\CurrentControlSet\Services\HidUsb\Parameters" `
        "SelectiveSuspendEnabled" 0
}

Add-Button $usb "Prevent USB Random Disconnects (Advanced)" 20 170 {
    # Disable USB hub idle power down
    Set-RegDWORD "HKLM:\SYSTEM\CurrentControlSet\Services\USBHUB3\Parameters" `
        "DisableOnSoftRemove" 1

    # Prevent Windows from suspending USB devices
    Set-RegDWORD "HKLM:\SYSTEM\CurrentControlSet\Services\USBHUB3\Parameters" `
        "EnableSelectiveSuspend" 0

    # Disable USB idle timeout
    Set-RegDWORD "HKLM:\SYSTEM\CurrentControlSet\Services\USBHUB3\Parameters" `
        "IdleTimeout" 0
}

Add-Button $usb "Improve USB Input Stability (HID)" 20 220 {
    # Disable HID selective suspend
    Set-RegDWORD "HKLM:\SYSTEM\CurrentControlSet\Services\HidUsb\Parameters" `
        "SelectiveSuspendEnabled" 0

    # Improve input device responsiveness
    Set-RegDWORD "HKLM:\SYSTEM\CurrentControlSet\Services\HidUsb\Parameters" `
        "IdleEnabled" 0

    # Prevent input device power saving
    Set-RegDWORD "HKLM:\SYSTEM\CurrentControlSet\Services\HidUsb\Parameters" `
        "AutoSuspend" 0
}


# ================= PROCESSES =================
$proc = Add-Tab "Processes & Services"

Add-Button $proc "Disable SysMain" 20 20 { Disable-Service "SysMain" }
Add-Button $proc "Disable Search Indexing" 20 70 { Disable-Service "WSearch" }
Add-Button $proc "Disable Telemetry Services" 20 120 {
    "DiagTrack","dmwappushservice" | ForEach-Object { Disable-Service $_ }
}

# ================= PRIVACY =================
$privacy = Add-Tab "Privacy & Telemetry"

Add-Button $privacy "Disable Telemetry" 20 20 {
    Set-RegDWORD "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0
}

Add-Button $privacy "Disable Advertising ID" 20 70 {
    Set-RegDWORD "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" 0
}

Add-Button $privacy "Disable Activity History" 20 120 {
    Set-RegDWORD "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableActivityFeed" 0
}

# ================= POWER =================
$power = Add-Tab "Power / Latency"

Add-Button $power "High Performance Power Plan" 20 20 {
    powercfg -setactive SCHEME_MIN
}

Add-Button $power "Disable Hibernation" 20 70 {
    powercfg -h off
}

Add-Button $power "Reduce UI/Input Latency" 20 120 {
    Set-RegDWORD "HKCU:\Control Panel\Desktop" "MenuShowDelay" 0
}

# ================= DEBLOAT =================
$debloat = Add-Tab "Debloat"

Add-Button $debloat "Remove Xbox / Bing / Consumer Apps" 20 20 {
    "Microsoft.Xbox*","Microsoft.Bing*","Microsoft.GetHelp","Microsoft.People" |
    ForEach-Object {
        Get-AppxPackage -AllUsers $_ | Remove-AppxPackage -ErrorAction SilentlyContinue
    }
}

# ================= PROFILES =================
$profiles = Add-Tab "Profiles"

Add-Button $profiles "Low-End PC" 20 20 {
    Disable-Service "SysMain"
    Disable-Service "WSearch"
    powercfg -setactive SCHEME_MIN
}

Add-Button $profiles "High-End Gaming PC" 20 70 {
    Set-RegDWORD "HKCU:\Software\Microsoft\GameBar" "AllowAutoGameMode" 1
}

Add-Button $profiles "Laptop / Battery" 20 120 {
    powercfg -setactive SCHEME_BALANCED
}

# ================= UNDO =================
$undo = Add-Tab "Undo / Restore"

Add-Button $undo "UNDO ALL THVO TWEAKS" 20 20 {
    foreach ($k in $Global:Backup.Registry.Keys) {
        $split = $k.Split("|")
        if ($Global:Backup.Registry[$k] -eq $null) {
            Remove-ItemProperty -Path $split[0] -Name $split[1] -ErrorAction SilentlyContinue
        } else {
            Set-ItemProperty -Path $split[0] -Name $split[1] -Value $Global:Backup.Registry[$k]
        }
    }

    foreach ($s in $Global:Backup.Services.Keys) {
        Set-Service $s -StartupType $Global:Backup.Services[$s] -ErrorAction SilentlyContinue
    }

    powercfg -h on
    [System.Windows.Forms.MessageBox]::Show("Undo complete. Restart recommended.")
}

# ---------- RUN ----------
[void]$form.ShowDialog()
