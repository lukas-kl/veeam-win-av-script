# -----------------------------------
# Veeam Windows AV Script v1.0 (Optimized for Windows Server 2022/2025)
# -----------------------------------
# by Lukas Klostermann
#
# Run this script as Administrator

#region Initialization and Helper Functions

# Check for Administrator rights
$adminCheck = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $adminCheck.IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    exit 1
}

# Ensure the Install directory exists for the log
$logFile = "C:\Install\Output-Veeam-Win-AV-Script.log"
if (-not (Test-Path -Path "C:\Install")) {
    New-Item -Path "C:\Install" -ItemType Directory -Force | Out-Null
}

function Write-Log($Message) {
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Add-Content -Path $logFile -Value "$timestamp`t$Message"
}

Write-Log "=== Script started. ==="

#endregion Initialization

# Enable Windows Defender Firewall (all profiles)
$firewallProfiles = Get-NetFirewallProfile
foreach ($profile in $firewallProfiles) {
    if (-not $profile.Enabled) {
        Write-Host "Firewall ($($profile.Name)) is disabled. Enabling..." -ForegroundColor Yellow
        Set-NetFirewallProfile -Profile $profile.Name -Enabled True
    }
}
Write-Host "Windows Defender Firewall is enabled for all profiles." -ForegroundColor Green

# Enable Windows Defender AV Real-Time Protection
try {
    # If Real-Time Protection is disabled, this value is $true
    $rtpDisabled = (Get-MpPreference).DisableRealtimeMonitoring
    if ($rtpDisabled) {
        Write-Host "Windows Defender AV Real-Time Protection is disabled. Enabling..." -ForegroundColor Yellow
        Set-MpPreference -DisableRealtimeMonitoring $false
        Write-Host "Windows Defender AV Real-Time Protection is now enabled." -ForegroundColor Green
    } else {
        Write-Host "Windows Defender AV Real-Time Protection is already enabled." -ForegroundColor Green
    }
} catch {
    Write-Host "Could not determine or set Defender AV real-time protection (is Defender installed?)." -ForegroundColor Red
}

#region Defender and Firewall Helper Functions

function Add-DefenderFolderExclusion([string]$path, [ref]$statusList) {
    $expandedPath = [Environment]::ExpandEnvironmentVariables($path)
    $isFolder = $expandedPath -ne "" -and $expandedPath -notlike "*`**" -and ([System.IO.Path]::GetExtension($expandedPath.TrimEnd("\\")) -eq "")
    if ($isFolder) {
        if (-not (Test-Path $expandedPath)) {
            try {
                New-Item -Path $expandedPath -ItemType Directory -Force | Out-Null
                Write-Log "Created folder: $expandedPath"
                Write-Host ("[Created]   " + $expandedPath) -ForegroundColor Green
                $statusList.Value += "[Created]   $expandedPath"
            } catch {
                Write-Log "Failed to create folder: $expandedPath"
                Write-Host ("[Failed]    " + $expandedPath) -ForegroundColor Red
                $statusList.Value += "[Failed]    $expandedPath"
            }
        } else {
            Write-Host ("[Exists]    " + $expandedPath) -ForegroundColor Yellow
            $statusList.Value += "[Exists]    $expandedPath"
        }
    }
    try {
        $current = (Get-MpPreference).ExclusionPath
        if ($null -eq $current) { $current = @() }
    } catch { $current = @() }
    if ($current -contains $path) {
        Write-Host ("[AV Already] " + $path) -ForegroundColor Cyan
        $statusList.Value += "[AV Already] $path"
        Write-Log "Defender exclusion exists (Folder): $path"
    } else {
        try {
            Add-MpPreference -ExclusionPath $path -Force
            Write-Host ("[AV Added]   " + $path) -ForegroundColor Green
            $statusList.Value += "[AV Added]   $path"
            Write-Log "Added Defender exclusion (Folder): $path"
        } catch {
            Write-Host ("[AV Failed]  " + $path) -ForegroundColor Red
            $statusList.Value += "[AV Failed]  $path"
            Write-Log "Failed to add Defender exclusion (Folder): $path"
        }
    }
}

function Add-DefenderProcessExclusion([string]$processName, [ref]$statusList) {
    try {
        $currentP = (Get-MpPreference).ExclusionProcess
        if ($null -eq $currentP) { $currentP = @() }
    } catch { $currentP = @() }
    if ($currentP -contains $processName) {
        Write-Host ("[Proc Already] " + $processName) -ForegroundColor Cyan
        $statusList.Value += "[Proc Already] $processName"
        Write-Log "Defender exclusion exists (Process): $processName"
    } else {
        try {
            Add-MpPreference -ExclusionProcess $processName -Force
            Write-Host ("[Proc Added]   " + $processName) -ForegroundColor Green
            $statusList.Value += "[Proc Added]   $processName"
            Write-Log "Added Defender exclusion (Process): $processName"
        } catch {
            Write-Host ("[Proc Failed]  " + $processName) -ForegroundColor Red
            $statusList.Value += "[Proc Failed]  $processName"
            Write-Log "Failed to add Defender exclusion (Process): $processName"
        }
    }
}

function Add-DefenderExtensionExclusion([string]$extension, [ref]$statusList) {
    try {
        $currentE = (Get-MpPreference).ExclusionExtension
        if ($null -eq $currentE) { $currentE = @() }
    } catch { $currentE = @() }
    if ($currentE -contains $extension) {
        Write-Host ("[Ext Already] " + $extension) -ForegroundColor Cyan
        $statusList.Value += "[Ext Already] $extension"
        Write-Log "Defender exclusion exists (Extension): $extension"
    } else {
        try {
            Add-MpPreference -ExclusionExtension $extension -Force
            Write-Host ("[Ext Added]   " + $extension) -ForegroundColor Green
            $statusList.Value += "[Ext Added]   $extension"
            Write-Log "Added Defender exclusion (Extension): $extension"
        } catch {
            Write-Host ("[Ext Failed]  " + $extension) -ForegroundColor Red
            $statusList.Value += "[Ext Failed]  $extension"
            Write-Log "Failed to add Defender exclusion (Extension): $extension"
        }
    }
}

function Add-FirewallRule([string]$ruleName, [string]$protocol, [string]$ports, [ref]$statusList) {
    $portList = $ports -split ','
    foreach ($port in $portList) {
        $displayName = "$ruleName ($protocol $port)"
        if (Get-NetFirewallRule -DisplayName $displayName -ErrorAction SilentlyContinue) {
            Write-Host ("[FW Already] " + $displayName) -ForegroundColor Cyan
            $statusList.Value += "[FW Already] $displayName"
            Write-Log "Firewall rule exists: $displayName"
        } else {
            try {
                New-NetFirewallRule -DisplayName $displayName -Direction Inbound -Protocol $protocol -LocalPort $port -Action Allow -Profile Domain,Private | Out-Null
                Write-Host ("[FW Added]   " + $displayName) -ForegroundColor Green
                $statusList.Value += "[FW Added]   $displayName"
                Write-Log "Added firewall rule: $displayName"
            } catch {
                Write-Host ("[FW Failed]  " + $displayName) -ForegroundColor Red
                $statusList.Value += "[FW Failed]  $displayName"
                Write-Log "Failed to add firewall rule: $displayName"
            }
        }
    }
}

#endregion Defender and Firewall Helper Functions

#region Component Configuration Functions

function Configure-BackupServer {
    $status = @()
    $folders = @(
        "C:\Program Files\Veeam\",
        "C:\Program Files (x86)\Veeam\",
        "C:\Program Files\Common Files\Veeam\",
        "C:\Program Files (x86)\Common Files\Veeam\",
        "C:\Program Files\Veeam\Backup and Replication\Threat Hunter\",
        "C:\Program Files\Common Files\Veeam\Backup and Replication\Log Backup Service\",
        "C:\VeeamFLR\",
        "C:\Windows\Veeam\",
        "C:\ProgramData\Veeam\",
        "C:\Windows\Temp\*\veeamflr-*.flat",
        "C:\Windows\Temp\VeeamBackup\",
        "C:\Windows\Temp\VeeamBackupTemp\",
        "C:\Windows\Temp\veeamdumprecorder\",
        "C:\Windows\Temp\VeeamForeignSessionContext*\",
        "%localappdata%\Veeam\Backup\"
    )
    if (Test-Path 'HKLM:\SOFTWARE\Veeam\Veeam Backup Catalog') {
        $cat = (Get-ItemProperty 'HKLM:\SOFTWARE\Veeam\Veeam Backup Catalog').CatalogPath
        if ($cat) { $folders += $cat }
    }
    if (Test-Path 'HKLM:\SOFTWARE\Wow6432Node\Veeam\Veeam NFS') {
        $nfs = (Get-ItemProperty 'HKLM:\SOFTWARE\Wow6432Node\Veeam\Veeam NFS').RootFolder
        if ($nfs) { $folders += $nfs }
    }
    Write-Host "`n=== Folder Exclusions ===" -ForegroundColor White
    foreach ($f in $folders) { Add-DefenderFolderExclusion $f ([ref]$status) }

    Write-Host "`n=== Process Exclusions ===" -ForegroundColor White
    $procFolders = @(
        "C:\Program Files\Veeam\",
        "C:\Program Files (x86)\Veeam\",
        "C:\Program Files\Common Files\Veeam\",
        "C:\Program Files (x86)\Common Files\Veeam\",
        "C:\Windows\Veeam\"
    )
    $procList = @()
    foreach ($pf in $procFolders) {
        if (Test-Path $pf) {
            Get-ChildItem -Path $pf -Filter *.exe -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $procList += $_.Name }
        }
    }
    $procList | Select-Object -Unique | ForEach-Object { Add-DefenderProcessExclusion $_ ([ref]$status) }

    Write-Host "`n=== Firewall Rules ===" -ForegroundColor White
    Add-FirewallRule "Veeam Exclusion - Backup Server - Backup Service" TCP "9392" ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Backup Server - Catalog Service" TCP "9393" ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Backup Server - Mount Service" TCP "9401" ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Backup Server - vPower NFS" TCP "111" ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Backup Server - vPower NFS" TCP "1058-1068" ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Backup Server - vPower NFS" TCP "2049-2059" ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Backup Server - vPower NFS" UDP "111" ([ref]$status)

    Write-Host "`n=== Summary for Backup Server ===" -ForegroundColor Magenta
    $status | ForEach-Object { Write-Host $_ }
}

function Configure-ProxyServer {
    $status = @()
    $folders = @(
        "C:\ProgramData\Veeam\",
        "C:\Windows\Temp\Veeam\",
        "C:\Windows\Temp\VeeamBackupTemp\",
        "C:\Windows\Veeam\Backup\",
        "C:\Program Files (x86)\Veeam\Backup Transport\",
        "C:\Program Files\Veeam\CDP Proxy Service\",
        "C:\Program Files\Veeam\Hyper-V Integration\",
        "C:\Program Files\Common Files\Veeam\Backup and Replication\"
    )
    Write-Host "`n=== Folder Exclusions ===" -ForegroundColor White
    foreach ($f in $folders) { Add-DefenderFolderExclusion $f ([ref]$status) }

    Write-Host "`n=== Process Exclusions ===" -ForegroundColor White
    $procFolders = @(
        "C:\Windows\Veeam\Backup\",
        "C:\Program Files (x86)\Veeam\Backup Transport\",
        "C:\Program Files\Veeam\CDP Proxy Service\",
        "C:\Program Files\Veeam\Hyper-V Integration\",
        "C:\Program Files\Common Files\Veeam\Backup and Replication\"
    )
    $procList = @()
    foreach ($pf in $procFolders) {
        if (Test-Path $pf) {
            Get-ChildItem -Path $pf -Filter *.exe -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $procList += $_.Name }
        }
    }
    $procList | Select-Object -Unique | ForEach-Object { Add-DefenderProcessExclusion $_ ([ref]$status) }

    Write-Host "`n=== Firewall Rules ===" -ForegroundColor White
    Add-FirewallRule "Veeam Exclusion - Proxy Server - RPC/SMB" TCP "135,137-139,445" ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Proxy Server - RPC/SMB" UDP "135,137-139,445" ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Proxy Server - Installer Service" TCP "6160" ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Proxy Server - Transport Service" TCP "6162" ([ref]$status)

    Write-Host "`n=== Summary for Proxy Server ===" -ForegroundColor Magenta
    $status | ForEach-Object { Write-Host $_ }
}

function Configure-RepositoryServer {
    $status = @()
    $folders = @(
        "C:\ProgramData\Veeam\",
        "C:\Windows\Temp\Veeam\",
        "C:\Windows\Temp\VeeamBackupTemp\",
        "C:\Windows\Veeam\Backup\",
        "C:\Program Files (x86)\Veeam\Backup Transport\",
        "C:\Program Files\Common Files\Veeam\Backup and Replication\",
        "C:\Program Files (x86)\Veeam\vPowerNFS\",
        "C:\VeeamFLR\"
    )
    Write-Host "`n=== Folder Exclusions ===" -ForegroundColor White
    foreach ($f in $folders) { Add-DefenderFolderExclusion $f ([ref]$status) }

    Write-Host "`n=== Process Exclusions ===" -ForegroundColor White
    $procFolders = @(
        "C:\Windows\Veeam\Backup\",
        "C:\Program Files (x86)\Veeam\Backup Transport\",
        "C:\Program Files\Common Files\Veeam\Backup and Replication\",
        "C:\Program Files (x86)\Veeam\vPowerNFS\"
    )
    $procList = @()
    foreach ($pf in $procFolders) {
        if (Test-Path $pf) {
            Get-ChildItem -Path $pf -Filter *.exe -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $procList += $_.Name }
        }
    }
    $procList | Select-Object -Unique | ForEach-Object { Add-DefenderProcessExclusion $_ ([ref]$status) }

    Write-Host "`n=== Extension Exclusions ===" -ForegroundColor White
    $extensions = @(
        "*.erm","*.flat","*.vab","*.vacm","*.vacm_*tmp","*.vasm","*.vasm_*tmp",
        "*.vbk","*.vbk.tmp","*.vblob","*.vbm","*.vbm.temp","*.vbm_*tmp",
        "*.vcache","*.vib","*.vindex","*.vlb","*.vmdk","*.vom","*.vom_*tmp",
        "*.vrb","*.vsb","*.vslice","*.vsm","*.vsm_*tmp","*.vsource","*.vsourcecopy",
        "*.vsourcetemp","*.vstore","*.vstorecopy","*.vstoretemp"
    )
    foreach ($ext in $extensions) { Add-DefenderExtensionExclusion $ext ([ref]$status) }

    Write-Host "`n=== Firewall Rules ===" -ForegroundColor White
    Add-FirewallRule "Veeam Exclusion - Repository Server - RPC/SMB" TCP "135,137-139,445" ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Repository Server - RPC/SMB" UDP "135,137-139,445" ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Repository Server - Installer Service" TCP "6160" ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Repository Server - Transport Service" TCP "6162" ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Repository Server - Mount Service" TCP "9401" ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Repository Server - vPower NFS Service" TCP "6161" ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Repository Server - vPower NFS" TCP "111" ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Repository Server - vPower NFS" TCP "1058-1068" ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Repository Server - vPower NFS" TCP "2049-2059" ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Repository Server - vPower NFS" UDP "111" ([ref]$status)

    Write-Host "`n=== Summary for Repository Server ===" -ForegroundColor Magenta
    $status | ForEach-Object { Write-Host $_ }
}

function Configure-WANAccelerator {
    $status = @()
    $folders = @(
        "C:\ProgramData\Veeam\",
        "C:\Windows\Temp\Veeam\",
        "C:\Windows\Temp\VeeamBackupTemp\",
        "C:\Windows\Veeam\Backup\",
        "C:\Program Files (x86)\Veeam\Backup Transport\",
        "C:\Program Files\Veeam\WAN Accelerator Service\"
    )
    Write-Host "`n=== Folder Exclusions ===" -ForegroundColor White
    foreach ($f in $folders) { Add-DefenderFolderExclusion $f ([ref]$status) }

    Write-Host "`n=== Process Exclusions ===" -ForegroundColor White
    $procFolders = @(
        "C:\Windows\Veeam\Backup\",
        "C:\Program Files (x86)\Veeam\Backup Transport\",
        "C:\Program Files\Veeam\WAN Accelerator Service\"
    )
    $procList = @()
    foreach ($pf in $procFolders) {
        if (Test-Path $pf) {
            Get-ChildItem -Path $pf -Filter *.exe -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $procList += $_.Name }
        }
    }
    $procList | Select-Object -Unique | ForEach-Object { Add-DefenderProcessExclusion $_ ([ref]$status) }

    Write-Host "`n=== Firewall Rules ===" -ForegroundColor White
    Add-FirewallRule "Veeam Exclusion - WAN Accelerator - RPC/SMB" TCP "135,137-139,445" ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - WAN Accelerator - RPC/SMB" UDP "135,137-139,445" ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - WAN Accelerator - Installer Service" TCP "6160" ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - WAN Accelerator - Transport Service" TCP "6162" ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - WAN Accelerator - WAN Control" TCP "6164" ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - WAN Accelerator - WAN Data" TCP "6165" ([ref]$status)

    Write-Host "`n=== Summary for WAN Accelerator ===" -ForegroundColor Magenta
    $status | ForEach-Object { Write-Host $_ }
}

function Configure-TapeServer {
    $status = @()
    $folders = @(
        "C:\ProgramData\Veeam\",
        "C:\Windows\Temp\Veeam\",
        "C:\Windows\Temp\VeeamBackupTemp\",
        "C:\Windows\Veeam\Backup\",
        "C:\Program Files (x86)\Veeam\Backup Transport\",
        "C:\Program Files (x86)\Veeam\Backup Tape\"
    )
    Write-Host "`n=== Folder Exclusions ===" -ForegroundColor White
    foreach ($f in $folders) { Add-DefenderFolderExclusion $f ([ref]$status) }

    Write-Host "`n=== Process Exclusions ===" -ForegroundColor White
    $procFolders = @(
        "C:\Windows\Veeam\Backup\",
        "C:\Program Files (x86)\Veeam\Backup Transport\",
        "C:\Program Files (x86)\Veeam\Backup Tape\"
    )
    $procList = @()
    foreach ($pf in $procFolders) {
        if (Test-Path $pf) {
            Get-ChildItem -Path $pf -Filter *.exe -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $procList += $_.Name }
        }
    }
    $procList | Select-Object -Unique | ForEach-Object { Add-DefenderProcessExclusion $_ ([ref]$status) }

    Write-Host "`n=== Firewall Rules ===" -ForegroundColor White
    Add-FirewallRule "Veeam Exclusion - Tape Server - RPC/SMB" TCP "135,137-139,445" ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Tape Server - RPC/SMB" UDP "135,137-139,445" ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Tape Server - Installer Service" TCP "6160" ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Tape Server - Transport Service" TCP "6162" ([ref]$status)

    Write-Host "`n=== Summary for Tape Server ===" -ForegroundColor Magenta
    $status | ForEach-Object { Write-Host $_ }
}

function Configure-EnterpriseManager {
    $status = @()
    $folders = @(
        "C:\Program Files\Veeam\",
        "C:\Program Files\Common Files\Veeam\",
        "C:\ProgramData\Veeam\"
    )
    if (Test-Path 'HKLM:\SOFTWARE\Veeam\Veeam Backup Catalog') {
        $cat = (Get-ItemProperty 'HKLM:\SOFTWARE\Veeam\Veeam Backup Catalog').CatalogPath
        if ($cat) { $folders += $cat }
    } else {
        $folders += "C:\VBRCatalog"
    }
    Write-Host "`n=== Folder Exclusions ===" -ForegroundColor White
    foreach ($f in $folders) { Add-DefenderFolderExclusion $f ([ref]$status) }

    Write-Host "`n=== Process Exclusions ===" -ForegroundColor White
    $procFolders = @(
        "C:\Program Files\Veeam\",
        "C:\Program Files\Common Files\Veeam\"
    )
    $procList = @()
    foreach ($pf in $procFolders) {
        if (Test-Path $pf) {
            Get-ChildItem -Path $pf -Filter *.exe -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $procList += $_.Name }
        }
    }
    $procList | Select-Object -Unique | ForEach-Object { Add-DefenderProcessExclusion $_ ([ref]$status) }

    Write-Host "`n=== Firewall Rules ===" -ForegroundColor White
    Add-FirewallRule "Veeam Exclusion - Enterprise Manager - Web UI" TCP "9443" ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Enterprise Manager - Web UI (HTTP)" TCP "9080" ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Enterprise Manager - Service" TCP "9394" ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Enterprise Manager - REST API" TCP "9399" ([ref]$status)

    Write-Host "`n=== Summary for Enterprise Manager ===" -ForegroundColor Magenta
    $status | ForEach-Object { Write-Host $_ }
}

function Configure-Console {
    $status = @()
    $folders = @(
        "C:\Program Files\Veeam\",
        "C:\Program Files (x86)\Veeam\"
    )
    Write-Host "`n=== Folder Exclusions ===" -ForegroundColor White
    foreach ($f in $folders) { Add-DefenderFolderExclusion $f ([ref]$status) }

    Write-Host "`n=== Process Exclusions ===" -ForegroundColor White
    $procFolders = @(
        "C:\Program Files\Veeam\",
        "C:\Program Files (x86)\Veeam\"
    )
    $procList = @()
    foreach ($pf in $procFolders) {
        if (Test-Path $pf) {
            Get-ChildItem -Path $pf -Filter *.exe -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $procList += $_.Name }
        }
    }
    $procList | Select-Object -Unique | ForEach-Object { Add-DefenderProcessExclusion $_ ([ref]$status) }

    Write-Host "`n=== Summary for Console ===" -ForegroundColor Magenta
    $status | ForEach-Object { Write-Host $_ }
}

function Configure-CloudGateway {
    $status = @()
    $folders = @(
        "C:\ProgramData\Veeam\",
        "C:\Windows\Temp\Veeam\",
        "C:\Windows\Veeam\Backup\",
        "C:\Program Files (x86)\Veeam\Backup Transport\",
        "C:\Program Files (x86)\Veeam\Backup Gate\"
    )
    Write-Host "`n=== Folder Exclusions ===" -ForegroundColor White
    foreach ($f in $folders) { Add-DefenderFolderExclusion $f ([ref]$status) }

    Write-Host "`n=== Process Exclusions ===" -ForegroundColor White
    $procFolders = @(
        "C:\Windows\Veeam\Backup\",
        "C:\Program Files (x86)\Veeam\Backup Gate\"
    )
    $procList = @()
    foreach ($pf in $procFolders) {
        if (Test-Path $pf) {
            Get-ChildItem -Path $pf -Filter *.exe -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $procList += $_.Name }
        }
    }
    $procList | Select-Object -Unique | ForEach-Object { Add-DefenderProcessExclusion $_ ([ref]$status) }

    Write-Host "`n=== Firewall Rules ===" -ForegroundColor White
    Add-FirewallRule "Veeam Exclusion - Cloud Gateway - RPC/SMB" TCP "135,137-139,445" ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Cloud Gateway - RPC/SMB" UDP "135,137-139,445" ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Cloud Gateway - Installer Service" TCP "6160" ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Cloud Gateway - Cloud Gateway" TCP "6180" ([ref]$status)

    Write-Host "`n=== Summary for Cloud Gateway ===" -ForegroundColor Magenta
    $status | ForEach-Object { Write-Host $_ }
}

function Configure-VeeamOne {
    $status = @()
    $folders = @(
        "C:\Program Files\Veeam\",
        "C:\Program Files (x86)\Veeam\",
        "C:\Program Files\Common Files\Veeam\",
        "C:\Program Files (x86)\Common Files\Veeam\",
        "%PROGRAMDATA%\Veeam\",
        "%LOCALAPPDATA%\Veeam\"
    )
    Write-Host "`n=== Folder Exclusions ===" -ForegroundColor White
    foreach ($f in $folders) { Add-DefenderFolderExclusion $f ([ref]$status) }

    Write-Host "`n=== Process Exclusions ===" -ForegroundColor White
    $processes = @("VeeamOneMonitorSvc.exe","VeeamOneReporterSvc.exe","VeeamDCS.exe","VeeamOneSettings.exe")
    foreach ($p in $processes) { Add-DefenderProcessExclusion $p ([ref]$status) }

    Write-Host "`n=== Firewall Rules ===" -ForegroundColor White
    Add-FirewallRule "Veeam Exclusion - Veeam ONE Server - Web UI" TCP "1239" ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Veeam ONE Server - RPC/SMB" TCP "135,137-139,445" ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Veeam ONE Server - RPC/SMB" UDP "135,137-139,445" ([ref]$status)

    Write-Host "`n=== Summary for Veeam ONE Server ===" -ForegroundColor Magenta
    $status | ForEach-Object { Write-Host $_ }
}

function Configure-BackupM365 {
    $status = @()
    $folders = @(
        "C:\Program Files\Veeam\",
        "C:\Program Files (x86)\Veeam\",
        "C:\Program Files\Common Files\Veeam\",
        "C:\Program Files (x86)\Common Files\Veeam\",
        "%WINDIR%\Veeam\",
        "%PROGRAMDATA%\Veeam\"
    )
    Write-Host "`n=== Folder Exclusions ===" -ForegroundColor White
    foreach ($f in $folders) { Add-DefenderFolderExclusion $f ([ref]$status) }

    Write-Host "`n=== Process Exclusions ===" -ForegroundColor White
    $processes = @("Veeam.Archiver.Service.exe","Veeam.Archiver.Proxy.exe","Veeam.Archiver.RestSvc.exe")
    foreach ($p in $processes) { Add-DefenderProcessExclusion $p ([ref]$status) }

    Write-Host "`n=== Extension Exclusions ===" -ForegroundColor White
    $extensions = @("adb","jrs")
    foreach ($e in $extensions) { Add-DefenderExtensionExclusion $e ([ref]$status) }

    Write-Host "`n=== Firewall Rules ===" -ForegroundColor White
    Add-FirewallRule "Veeam Exclusion - Backup for M365 - RPC/DCOM" TCP "135" ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Backup for M365 - LLMNR" UDP "5355" ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Backup for M365 - REST API" TCP "4443" ([ref]$status)

    Write-Host "`n=== Summary for Backup for Microsoft 365 Server ===" -ForegroundColor Magenta
    $status | ForEach-Object { Write-Host $_ }
}

#endregion Component Configuration Functions

#region Main Menu Loop

do {
    Write-Host ""
    Write-Host "============= Veeam Exclusion Configuration =============" -ForegroundColor White
    Write-Host "1  - Veeam Backup Server"
    Write-Host "2  - Veeam Proxy Server"
    Write-Host "3  - Veeam Backup Repository (Windows)"
    Write-Host "4  - Veeam WAN Accelerator"
    Write-Host "5  - Veeam Tape Server"
    Write-Host "6  - Veeam Backup Enterprise Manager"
    Write-Host "7  - Veeam Backup & Replication Console"
    Write-Host "8  - Veeam Cloud Gateway Server"
    Write-Host "9  - Veeam ONE Server"
    Write-Host "10 - Veeam Backup for Microsoft 365 Server"
    Write-Host "0  - Exit"
    Write-Host "--------------------------------------------------------" -ForegroundColor White
    $choice = Read-Host "Please select the component to configure (0-10)"
    switch ($choice) {
        "1"  { Configure-BackupServer    }
        "2"  { Configure-ProxyServer     }
        "3"  { Configure-RepositoryServer}
        "4"  { Configure-WANAccelerator  }
        "5"  { Configure-TapeServer      }
        "6"  { Configure-EnterpriseManager}
        "7"  { Configure-Console         }
        "8"  { Configure-CloudGateway    }
        "9"  { Configure-VeeamOne        }
        "10" { Configure-BackupM365      }
        "0"  { Write-Host "Exiting..." -ForegroundColor Cyan; Write-Log "Script terminated by user."; break }
        default { Write-Host "Invalid selection. Please enter 0-10." -ForegroundColor Red }
    }
    if ($choice -ne "0") { Read-Host -Prompt "Press [Enter] to return to the menu..." }
} while ($choice -ne "0")

#endregion Main Menu Loop

Write-Host "The output file is located at C:\Install."