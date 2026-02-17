# -----------------------------------
# Veeam Windows AV Script v1.1 (Optimized for Windows Server 2022/2025 and VBR v13)
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
    Write-Host "ERROR enabling Real-Time Protection: $_" -ForegroundColor Red
    Write-Log "ERROR enabling Real-Time Protection: $_"
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
        if ($current -contains $expandedPath) {
            Write-Host ("[Already]   " + $expandedPath) -ForegroundColor Cyan
            $statusList.Value += "[Already]   $expandedPath"
        } else {
            Add-MpPreference -ExclusionPath $expandedPath -ErrorAction Stop
            Write-Log "Added Defender folder exclusion: $expandedPath"
            Write-Host ("[Added]     " + $expandedPath) -ForegroundColor Green
            $statusList.Value += "[Added]     $expandedPath"
        }
    } catch {
        Write-Log "Failed to add Defender folder exclusion: $expandedPath"
        Write-Host ("[Failed]    " + $expandedPath) -ForegroundColor Red
        $statusList.Value += "[Failed]    $expandedPath"
    }
}

function Add-DefenderProcessExclusion([string]$processName, [ref]$statusList) {
    try {
        $current = (Get-MpPreference).ExclusionProcess
        if ($null -eq $current) { $current = @() }
        if ($current -contains $processName) {
            Write-Host ("[Already]   " + $processName) -ForegroundColor Cyan
            $statusList.Value += "[Already]   $processName"
        } else {
            Add-MpPreference -ExclusionProcess $processName -ErrorAction Stop
            Write-Log "Added Defender process exclusion: $processName"
            Write-Host ("[Added]     " + $processName) -ForegroundColor Green
            $statusList.Value += "[Added]     $processName"
        }
    } catch {
        Write-Log "Failed to add Defender process exclusion: $processName"
        Write-Host ("[Failed]    " + $processName) -ForegroundColor Red
        $statusList.Value += "[Failed]    $processName"
    }
}

function Add-DefenderExtensionExclusion([string]$extension, [ref]$statusList) {
    try {
        $current = (Get-MpPreference).ExclusionExtension
        if ($null -eq $current) { $current = @() }
        if ($current -contains $extension) {
            Write-Host ("[Already]   ." + $extension) -ForegroundColor Cyan
            $statusList.Value += "[Already]   .$extension"
        } else {
            Add-MpPreference -ExclusionExtension $extension -ErrorAction Stop
            Write-Log "Added Defender extension exclusion: .$extension"
            Write-Host ("[Added]     ." + $extension) -ForegroundColor Green
            $statusList.Value += "[Added]     .$extension"
        }
    } catch {
        Write-Log "Failed to add Defender extension exclusion: .$extension"
        Write-Host ("[Failed]    ." + $extension) -ForegroundColor Red
        $statusList.Value += "[Failed]    .$extension"
    }
}

function Add-FirewallRule([string]$ruleName, [string]$protocol, $ports, [ref]$statusList) {
    try {
        $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Write-Host ("[Exists]    Firewall rule: " + $ruleName) -ForegroundColor Yellow
            $statusList.Value += "[Exists]    Firewall rule: $ruleName"
            return
        }

        # Normalize ports:
        # - if caller passes an array -> keep it
        # - if caller passes a string with commas -> split to array
        $localPorts = $ports
        if ($ports -is [string] -and $ports -match ",") {
            $localPorts = $ports.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        }

        New-NetFirewallRule `
            -DisplayName $ruleName `
            -Direction Inbound `
            -Action Allow `
            -Protocol $protocol `
            -LocalPort $localPorts `
            -Profile Any `
            -ErrorAction Stop | Out-Null

        Write-Log "Created firewall rule: $ruleName ($protocol/$ports)"
        Write-Host ("[Added]     Firewall rule: " + $ruleName) -ForegroundColor Green
        $statusList.Value += "[Added]     Firewall rule: $ruleName"
    }
    catch {
        $err = $_.Exception.Message
        Write-Log "Failed to create firewall rule: $ruleName ($protocol/$ports) - $err"
        Write-Host ("[Failed]    Firewall rule: " + $ruleName + " - " + $err) -ForegroundColor Red
        $statusList.Value += "[Failed]    Firewall rule: $ruleName - $err"
    }
}


#endregion Additional Helper Functions (v13+)

function Add-DefenderFolderExclusionOptional([string]$path, [ref]$statusList) {
    $expandedPath = [Environment]::ExpandEnvironmentVariables($path)
    if ([string]::IsNullOrWhiteSpace($expandedPath)) { return }
    if (Test-Path -Path $expandedPath) {
        try {
            $current = (Get-MpPreference).ExclusionPath
            if ($null -eq $current) { $current = @() }
            if ($current -contains $expandedPath) {
                Write-Host ("[Already]   " + $expandedPath) -ForegroundColor Cyan
                $statusList.Value += "[Already]   $expandedPath"
            } else {
                Add-MpPreference -ExclusionPath $expandedPath -ErrorAction Stop
                Write-Log "Added Defender folder exclusion (optional): $expandedPath"
                Write-Host ("[Added]     " + $expandedPath) -ForegroundColor Green
                $statusList.Value += "[Added]     $expandedPath"
            }
        } catch {
            Write-Log "Failed to add optional folder exclusion: $expandedPath"
            Write-Host ("[Failed]    " + $expandedPath) -ForegroundColor Red
            $statusList.Value += "[Failed]    $expandedPath"
        }
    } else {
        Write-Host ("[Skipped]   " + $expandedPath + " (path not found)") -ForegroundColor DarkYellow
        $statusList.Value += "[Skipped]   $expandedPath (path not found)"
    }
}

function Get-VeeamBackupTransportFolderCandidates {
    # VBR <= 12.3.x: Program Files (x86)
    # VBR 13+:      Program Files
    return @(
        "C:\Program Files\Veeam\Backup Transport\",
        "C:\Program Files (x86)\Veeam\Backup Transport\"
    )
}

function Prompt-AndAddCustomFolderExclusions {
    param(
        [Parameter(Mandatory=$true)][string]$PromptText,
        [Parameter(Mandatory=$true)][ref]$statusList
    )
    $input = Read-Host $PromptText
    if ([string]::IsNullOrWhiteSpace($input)) { return }

    $paths = $input.Split(";") | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
    foreach ($p in $paths) {
        Add-DefenderFolderExclusionOptional $p ([ref]$statusList)
    }
}

#endregion Additional Helper Functions (v13+)

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
        "C:\Windows\SystemTemp\veeam-*.json",
        "%localappdata%\Veeam\Backup\",
        "C:\Program Files\PostgreSQL\",
        "C:\Windows\VeeamOneAgent\",
        "C:\Windows\VeeamOneDeploymentService\",
        "C:\Program Files\Veeam\Veeam ONE\Veeam Analytics Service\",
        "C:\ProgramData\Veeam\Veeam ONE\AnalyticsService\"
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
        "C:\Windows\Veeam\",
        "C:\Program Files\PostgreSQL\17\bin"
    )
    $procList = @()
    foreach ($pf in $procFolders) {
        if (Test-Path $pf) {
            Get-ChildItem -Path $pf -Filter *.exe -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $procList += $_.Name }
        }
    }
    $procList | Select-Object -Unique | ForEach-Object { Add-DefenderProcessExclusion $_ ([ref]$status) }

    Write-Host "`n=== Extension Exclusions ===" -ForegroundColor White
        $extensions = @("erm","flat","vab","vacm","vacm_tmp","vasm","vasm_tmp","vbk","vbk.tmp","vblob","vbm","vbm.temp","vbm_tmp","vcache","vib","vindex","vlb","vmdk","vom","vom_tmp","vrb","vsb","vslice","vsm","vsm_*tmp","vsource","vsourcecopy","vsourcetemp","vstore","vstorecopy","vstoretemp","key","crt","conf","pid")
        foreach ($e in $extensions) { Add-DefenderExtensionExclusion $e ([ref]$status) }

    Write-Host "`n=== Firewall Rules ===" -ForegroundColor White
    Add-FirewallRule "Veeam Exclusion - Backup Server - Backup Service" TCP 9392 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Backup Server - Catalog Service" TCP 9393 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Backup Server - Mount Server" TCP 9401 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Backup Server - Rest API" TCP 9419 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Backup Server - Mount Service" TCP 2500-3300 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Backup Server - Data Mover" TCP 2500-5000 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Backup Server - vPowerNFS" TCP 1058-1110 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Backup Server - vPowerNFS" UDP 1058-1110 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Backup Server - RPC and SMB" TCP 135,445 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Backup Server - NetBIOS TCP" TCP 137 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Backup Server - NetBIOS UDP" UDP 138-139 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Backup Server - WebUI" TCP 443 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Backup Server - CDP" TCP 33034-33035 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Backup Server - Enterprise Manager" TCP 9405,9392,10005,49152-65535 ([ref]$status)

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
        "C:\Program Files\Veeam\Backup Transport",
        "C:\Program Files\Veeam\CDP Proxy Service\",
        "C:\Program Files\Common Files\Veeam\Backup and Replication\",
        "C:\Program Files (x86)\Veeam\vPowerNFS\",
        "C:\Program Files\Veeam\Hyper-V Integration\",
        "C:\Program Files\Veeam\Veeam Guest Interaction Service\",
        "C:\VeeamFLR\"
    )
    $folders += Get-VeeamBackupTransportFolderCandidates
    Write-Host "`n=== Folder Exclusions ===" -ForegroundColor White
    foreach ($f in $folders) {
        if ($f -like "*Backup Transport*") { Add-DefenderFolderExclusionOptional $f ([ref]$status) } else { Add-DefenderFolderExclusion $f ([ref]$status) }
    }

    Write-Host "`n=== Process Exclusions ===" -ForegroundColor White
    $procFolders = @(
        "C:\Windows\Veeam\Backup\",
        "C:\Program Files\Veeam\CDP Proxy Service\",
        "C:\Program Files\Common Files\Veeam\Backup and Replication\",
        "C:\Program Files (x86)\Veeam\vPowerNFS\",
        "C:\Program Files\Veeam\Hyper-V Integration\"
    )
    $procFolders += Get-VeeamBackupTransportFolderCandidates
    $procList = @()
    foreach ($pf in $procFolders) {
        if (Test-Path $pf) {
            Get-ChildItem -Path $pf -Filter *.exe -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $procList += $_.Name }
        }
    }
    $procList | Select-Object -Unique | ForEach-Object { Add-DefenderProcessExclusion $_ ([ref]$status) }

    Write-Host "`n=== Firewall Rules ===" -ForegroundColor White
    Add-FirewallRule "Veeam Exclusion - Proxy - Data Mover" TCP 2500-5000 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Proxy - RPC and SMB" TCP 135,445 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Proxy - NetBIOS TCP" TCP 137 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Proxy - NetBIOS UDP" UDP 138-139 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Proxy - Veeam Installer" TCP 6160,6162 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Proxy - VSS Integration" UDP 6210 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Proxy - vPowerNFS" TCP 1058-1110 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Proxy - vPowerNFS" UDP 1058-1110 ([ref]$status)

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
        "C:\Program Files\Veeam\Backup Transport",
        "C:\Program Files\Veeam\CDP Proxy Service\",
        "C:\Program Files\Common Files\Veeam\Backup and Replication\",
        "C:\Program Files (x86)\Veeam\vPowerNFS\",
        "C:\Program Files\Veeam\Hyper-V Integration\",
        "C:\Program Files\Veeam\Veeam Guest Interaction Service\",
        "C:\VeeamFLR\"
    )
    $folders += Get-VeeamBackupTransportFolderCandidates
    Write-Host "`n=== Folder Exclusions ===" -ForegroundColor White
    foreach ($f in $folders) {
        if ($f -like "*Backup Transport*") { Add-DefenderFolderExclusionOptional $f ([ref]$status) } else { Add-DefenderFolderExclusion $f ([ref]$status) }
    }

      Write-Host "`n=== Process Exclusions ===" -ForegroundColor White
    $procFolders = @(
        "C:\Windows\Veeam\Backup\",
        "C:\Program Files (x86)\Veeam\Backup Transport\",
        "C:\Program Files\Common Files\Veeam\Backup and Replication\",
        "C:\Program Files (x86)\Veeam\vPowerNFS\"
    )
    $procFolders += Get-VeeamBackupTransportFolderCandidates
    $procList = @()
    foreach ($pf in $procFolders) {
        if (Test-Path $pf) {
            Get-ChildItem -Path $pf -Filter *.exe -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $procList += $_.Name }
        }
    }
    $procList | Select-Object -Unique | ForEach-Object { Add-DefenderProcessExclusion $_ ([ref]$status) }

    Write-Host "`n=== Extension Exclusions ===" -ForegroundColor White
    $extensions = @("erm","flat","vab","vacm","vacm_tmp","vasm","vasm_tmp","vbk","vbk.tmp","vblob","vbm","vbm.temp","vbm_tmp","vcache","vib","vindex","vlb","vmdk","vom","vom_tmp","vrb","vsb","vslice","vsm","vsm_*tmp","vsource","vsourcecopy","vsourcetemp","vstore","vstorecopy","vstoretemp")
    foreach ($e in $extensions) { Add-DefenderExtensionExclusion $e ([ref]$status) }

    Write-Host "`n=== Firewall Rules ===" -ForegroundColor White
    Add-FirewallRule "Veeam Exclusion - Repository Server - RPC and SMB" TCP 135,445 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Repository Server - NetBIOS TCP" TCP 137 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Repository Server - NetBIOS UDP" UDP 138-139 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Repository Server - Installer Service" TCP 6160 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Repository Server - vPower NFS" TCP 6161 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Repository Server - Transport Service" TCP 6162 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Repository Server - Mount Service" TCP 9401 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Repository Server - Transmission Ports" TCP 2500-3300 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Repository Server - vPower NFS" TCP 111 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Repository Server - vPower NFS" UDP 111 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Repository Server - vPower NFS" TCP 1058-1100,2049-2069 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Repository Server - vPower NFS" UDP 1058-1100 ([ref]$status)

    Write-Host "`n=== Summary for Backup Repository ===" -ForegroundColor Magenta
    $status | ForEach-Object { Write-Host $_ }
}

function Configure-WANAccelerator {
    $status = @()
    $folders = @(
        "C:\ProgramData\Veeam\",
        "C:\Windows\Temp\Veeam\",
        "C:\Windows\Temp\VeeamBackupTemp\",
        "C:\Windows\Veeam\Backup\",
        "C:\Program Files\Veeam\WAN Accelerator Service\"
    )
    $folders += Get-VeeamBackupTransportFolderCandidates
    Write-Host "`n=== Folder Exclusions ===" -ForegroundColor White
    foreach ($f in $folders) {
        if ($f -like "*Backup Transport*") { Add-DefenderFolderExclusionOptional $f ([ref]$status) } else { Add-DefenderFolderExclusion $f ([ref]$status) }
    }

    Write-Host "`n=== Process Exclusions ===" -ForegroundColor White
    $procFolders = @(
        "C:\Windows\Veeam\Backup\",
        "C:\Program Files\Veeam\WAN Accelerator Service\"
    )
    $procFolders += Get-VeeamBackupTransportFolderCandidates
    $procList = @()
    foreach ($pf in $procFolders) {
        if (Test-Path $pf) {
            Get-ChildItem -Path $pf -Filter *.exe -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $procList += $_.Name }
        }
    }
    $procList | Select-Object -Unique | ForEach-Object { Add-DefenderProcessExclusion $_ ([ref]$status) }

    Write-Host "`n=== Firewall Rules ===" -ForegroundColor White
    Add-FirewallRule "Veeam Exclusion - WAN Accelerator - RPC and SMB" TCP 135,445 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - WAN Accelerator - NetBIOS TCP" TCP 137 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - WAN Accelerator - NetBIOS UDP" UDP 138-139 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - WAN Accelerator - Installer Service" TCP 6160,6162,6164,6165,6220 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - WAN Accelerator - Transmission Ports" TCP 2500-3300 ([ref]$status)

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
        "C:\Program Files (x86)\Veeam\Backup Tape\",
        "C:\Program Files\Veeam\Backup Tape\"
    )
    $folders += Get-VeeamBackupTransportFolderCandidates
    Write-Host "`n=== Folder Exclusions ===" -ForegroundColor White
    foreach ($f in $folders) {
        if ($f -like "*Backup Transport*") { Add-DefenderFolderExclusionOptional $f ([ref]$status) } else { Add-DefenderFolderExclusion $f ([ref]$status) }
    }

    Write-Host "`n=== Process Exclusions ===" -ForegroundColor White
    $procFolders = @(
        "C:\Windows\Veeam\Backup\",
        "C:\Program Files (x86)\Veeam\Backup Tape\",
        "C:\Program Files\Veeam\Backup Tape\"
    )
    $procFolders += Get-VeeamBackupTransportFolderCandidates
    $procList = @()
    foreach ($pf in $procFolders) {
        if (Test-Path $pf) {
            Get-ChildItem -Path $pf -Filter *.exe -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $procList += $_.Name }
        }
    }
    $procList | Select-Object -Unique | ForEach-Object { Add-DefenderProcessExclusion $_ ([ref]$status) }

    Write-Host "`n=== Firewall Rules ===" -ForegroundColor White
    Add-FirewallRule "Veeam Exclusion - Tape Server - RPC and SMB" TCP 135,445 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Tape Server - NetBIOS TCP" TCP 137 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Tape Server - NetBIOS UDP" UDP 138-139 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Tape Server - Installer Service" TCP 6160,6162,6166 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Tape Server - Transmission Ports" TCP 2500-3300 ([ref]$status)

    Write-Host "`n=== Summary for Tape Server ===" -ForegroundColor Magenta
    $status | ForEach-Object { Write-Host $_ }
}

function Configure-EnterpriseManager {
    $status = @()
    $folders = @(
        "C:\Program Files\Veeam\",
        "C:\Program Files (x86)\Veeam\",
        "C:\Program Files\Common Files\Veeam\",
        "C:\Program Files (x86)\Common Files\Veeam\",
        "C:\Windows\Veeam\",
        "C:\ProgramData\Veeam\",
        "C:\Program Files\PostgreSQL\"
    )
    if (Test-Path 'HKLM:\SOFTWARE\Veeam\Veeam Backup Catalog') {
        $cat = (Get-ItemProperty 'HKLM:\SOFTWARE\Veeam\Veeam Backup Catalog').CatalogPath
        if ($cat) { $folders += $cat }
    }
    Write-Host "`n=== Folder Exclusions ===" -ForegroundColor White
    foreach ($f in $folders) { Add-DefenderFolderExclusion $f ([ref]$status) }

    Write-Host "`n=== Process Exclusions ===" -ForegroundColor White
    $procFolders = @(
        "C:\Program Files\Veeam\",
        "C:\Program Files (x86)\Veeam\",
        "C:\Program Files\Common Files\Veeam\",
        "C:\Program Files (x86)\Common Files\Veeam\",
        "C:\Program Files\PostgreSQL\17\bin"
    )
    $procList = @()
    foreach ($pf in $procFolders) {
        if (Test-Path $pf) {
            Get-ChildItem -Path $pf -Filter *.exe -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $procList += $_.Name }
        }
    }
    $procList | Select-Object -Unique | ForEach-Object { Add-DefenderProcessExclusion $_ ([ref]$status) }

    Write-Host "`n=== Extension Exclusions ===" -ForegroundColor White
            $extensions = @("erm","flat","vab","vacm","vacm_tmp","vasm","vasm_tmp","vbk","vbk.tmp","vblob","vbm","vbm.temp","vbm_tmp","vcache","vib","vindex","vlb","vmdk","vom","vom_tmp","vrb","vsb","vslice","vsm","vsm_*tmp","vsource","vsourcecopy","vsourcetemp","vstore","vstorecopy","vstoretemp","key","crt","conf","pid")
            foreach ($e in $extensions) { Add-DefenderExtensionExclusion $e ([ref]$status) }

    Write-Host "`n=== Firewall Rules ===" -ForegroundColor White
    Add-FirewallRule "Veeam Exclusion - Enterprise Manager - Web UI" TCP 9443 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Enterprise Manager - Veeam ONE" TCP 135,443,445,50001,49152-65535 ([ref]$status)

    Write-Host "`n=== Summary for Enterprise Manager ===" -ForegroundColor Magenta
    $status | ForEach-Object { Write-Host $_ }
}

function Configure-Console {
    $status = @()
    $folders = @(
        "C:\Program Files\Veeam\",
        "C:\Program Files (x86)\Veeam\",
        "C:\Program Files\Common Files\Veeam\",
        "C:\Program Files (x86)\Common Files\Veeam\",
        "C:\VeeamFLR\",
        "C:\Windows\Veeam\",
        "C:\ProgramData\Veeam\",
        "C:\Windows\Temp\*\veeamflr-*.flat",
        "C:\Windows\Temp\VeeamBackup\",
        "C:\Windows\Temp\VeeamBackupTemp\",
        "C:\Windows\Temp\veeamdumprecorder\",
        "%localappdata%\Veeam\Backup\"
    )
    Write-Host "`n=== Folder Exclusions ===" -ForegroundColor White
    foreach ($f in $folders) { Add-DefenderFolderExclusion $f ([ref]$status) }

    Write-Host "`n=== Process Exclusions ===" -ForegroundColor White
    $processes = @("Veeam.Backup.Shell.exe","Veeam.Backup.Shell.PowerShell.exe","Veeam.Backup.UILauncher.exe")
    foreach ($p in $processes) { Add-DefenderProcessExclusion $p ([ref]$status) }

    Write-Host "`n=== Summary for Console ===" -ForegroundColor Magenta
    $status | ForEach-Object { Write-Host $_ }
}

function Configure-CloudGateway {
    $status = @()
    $folders = @(
        "C:\ProgramData\Veeam\",
        "C:\Windows\Temp\Veeam\",
        "C:\Windows\Temp\VeeamBackupTemp\",
        "C:\Windows\Veeam\Backup\",
        "C:\Program Files (x86)\Veeam\Backup Gate\"
    )
    $folders += Get-VeeamBackupTransportFolderCandidates
    Write-Host "`n=== Folder Exclusions ===" -ForegroundColor White
    foreach ($f in $folders) {
        if ($f -like "*Backup Transport*") { Add-DefenderFolderExclusionOptional $f ([ref]$status) } else { Add-DefenderFolderExclusion $f ([ref]$status) }
    }

    Write-Host "`n=== Process Exclusions ===" -ForegroundColor White
    $procFolders = @(
        "C:\Windows\Veeam\Backup\",
        "C:\Program Files (x86)\Veeam\Backup Gate\"
    )
    $procFolders += Get-VeeamBackupTransportFolderCandidates
    $procList = @()
    foreach ($pf in $procFolders) {
        if (Test-Path $pf) {
            Get-ChildItem -Path $pf -Filter *.exe -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $procList += $_.Name }
        }
    }
    $procList | Select-Object -Unique | ForEach-Object { Add-DefenderProcessExclusion $_ ([ref]$status) }

    Write-Host "`n=== Firewall Rules ===" -ForegroundColor White
    Add-FirewallRule "Veeam Exclusion - Cloud Gateway - RPC and SMB" TCP 135,445 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Cloud Gateway - Installer Service" TCP 6160, 6168 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Cloud Gateway - Transmission Ports" TCP 2500-3300 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Cloud Gateway - Tenant Connections TCP" TCP 6180 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Cloud Gateway - Tenant Connections UDP" UDP 6180 ([ref]$status)

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
        "%LOCALAPPDATA%\Veeam\",
        "C:\PerfCache\",
        "C:\Program Files\PostgreSQL\"
    )
    Write-Host "`n=== Folder Exclusions ===" -ForegroundColor White
    foreach ($f in $folders) { Add-DefenderFolderExclusion $f ([ref]$status) }

    # Additional paths (KB2046) - may depend on installed components / service accounts
    Add-DefenderFolderExclusionOptional "C:\PerfCache\" ([ref]$status)
    Add-DefenderFolderExclusionOptional "C:\Windows\VeeamOneAgent\" ([ref]$status)
    Add-DefenderFolderExclusionOptional "C:\Windows\VeeamOneDeploymentService\" ([ref]$status)
    Add-DefenderFolderExclusionOptional "C:\Program Files\Veeam\Veeam ONE\Veeam Analytics Service\" ([ref]$status)
    Add-DefenderFolderExclusionOptional "%PROGRAMDATA%\Veeam\Veeam ONE\AnalyticsService\" ([ref]$status)

    Write-Host "`n=== Process Exclusions ===" -ForegroundColor White
    $processes = @("VeeamOneMonitorSvc.exe","VeeamOneReporterSvc.exe","VeeamDCS.exe","VeeamOneSettings.exe","postgres.exe")
    foreach ($p in $processes) { Add-DefenderProcessExclusion $p ([ref]$status) }

    Write-Host "`n=== Extension Exclusions ===" -ForegroundColor White
        $extensions = @("key","crt","conf","pid")
        foreach ($e in $extensions) { Add-DefenderExtensionExclusion $e ([ref]$status) }

    Write-Host "`n=== Firewall Rules ===" -ForegroundColor White
    Add-FirewallRule "Veeam Exclusion - Veeam ONE Server - Analytics" TCP 1239,2741 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Veeam ONE Server - WebUI" TCP 2714,2742,139,445 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Veeam ONE Server - WebUI" UCP 137 ([ref]$status)

    Write-Host "`n=== Summary for Veeam ONE v===" -ForegroundColor Magenta
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
        "%PROGRAMDATA%\Veeam\",
        "C:\Program Files\PostgreSQL\"
    )
    Write-Host "`n=== Folder Exclusions ===" -ForegroundColor White
    foreach ($f in $folders) { Add-DefenderFolderExclusion $f ([ref]$status) }

    Write-Host "`n=== Process Exclusions ===" -ForegroundColor White
    $processes = @("Veeam.Archiver.Service.exe","Veeam.Archiver.Proxy.exe","Veeam.Archiver.RestSvc.exe","postgres.exe")
    foreach ($p in $processes) { Add-DefenderProcessExclusion $p ([ref]$status) }

    Write-Host "`n=== Extension Exclusions ===" -ForegroundColor White
    $extensions = @("adb","jrs","key","crt","conf","pid")
    foreach ($e in $extensions) { Add-DefenderExtensionExclusion $e ([ref]$status) }

    Write-Host "`n=== Firewall Rules ===" -ForegroundColor White
    Add-FirewallRule "Veeam Exclusion - Backup for M365 - Components" TCP 9191,9194 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Backup for M365 - Proxy" TCP 9193 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Backup for M365 - Rest API" TCP 4443 ([ref]$status)

    Write-Host "`n=== Summary for Backup for Microsoft 365 ===" -ForegroundColor Magenta
    $status | ForEach-Object { Write-Host $_ }
}

function Configure-Orchestrator {
    $status = @()
    $folders = @(
        "C:\Program Files\Veeam\",
        "C:\Program Files (x86)\Veeam\",
        "C:\Program Files\Common Files\Veeam\",
        "C:\Program Files (x86)\Common Files\Veeam\",
        "%WINDIR%\Veeam\",
        "%PROGRAMDATA%\Veeam\"
    )
    if (Test-Path 'HKLM:\SOFTWARE\Veeam\Veeam Backup Catalog') {
        $cat = (Get-ItemProperty 'HKLM:\SOFTWARE\Veeam\Veeam Backup Catalog').CatalogPath
        if ($cat) { $folders += $cat }
    }
    Write-Host "`n=== Folder Exclusions ===" -ForegroundColor White
    foreach ($f in $folders) { Add-DefenderFolderExclusion $f ([ref]$status) }

    Write-Host "`n=== Process Exclusions ===" -ForegroundColor White
    $procFolders = @(
        "C:\Program Files\Veeam\",
        "C:\Program Files (x86)\Veeam\",
        "C:\Program Files\Common Files\Veeam\",
        "C:\Program Files (x86)\Common Files\Veeam\",
        "%WINDIR%\Veeam\",
        "%PROGRAMDATA%\Veeam\"
    )
    $procList = @()
    foreach ($pf in $procFolders) {
        if (Test-Path $pf) {
            Get-ChildItem -Path $pf -Filter *.exe -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $procList += $_.Name }
        }
    }
    $procList | Select-Object -Unique | ForEach-Object { Add-DefenderProcessExclusion $_ ([ref]$status) }

    Write-Host "`n=== Firewall Rules ===" -ForegroundColor White
	Add-FirewallRule "Veeam Exclusion - Orchestrator - Veeam Orchestrator Agents" TCP 8888,443 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Orchestrator - Orchestrator UI" TCP 12348,9898 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Orchestrator - Veeam ONE Client" TCP 139,445 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - Orchestrator - License Update" TCP 443 ([ref]$status)

    Write-Host "`n=== Summary for Veeam Backup Orchestrator ===" -ForegroundColor Magenta
    $status | ForEach-Object { Write-Host $_ }
}

function Configure-VeeamAgentWindows {
    $status = @()

    Write-Host "`n=== Veeam Agent for Microsoft Windows ===" -ForegroundColor Cyan

    $folders = @(
        "C:\Program Files\Veeam\",
        "C:\Program Files (x86)\Veeam\",
        "C:\Program Files\Common Files\Veeam\",
        "C:\Program Files (x86)\Common Files\Veeam\",
        "%PROGRAMDATA%\Veeam\",
        "%WINDIR%\Veeam\Backup\"
    )

    Write-Host "`n=== Folder Exclusions ===" -ForegroundColor White
    foreach ($f in $folders) { Add-DefenderFolderExclusion $f ([ref]$status) }

    # Optional / version-dependent folders
    Add-DefenderFolderExclusionOptional "%PROGRAMDATA%\Veeam\EndpointData\" ([ref]$status)
    Add-DefenderFolderExclusionOptional "%WINDIR%\VeeamLogShipper\" ([ref]$status)
    
    Write-Host "`n=== Process Exclusions ===" -ForegroundColor White
    # Collect all executables below typical Agent folders (keeps the list resilient across versions)
    $procFolders = @(
        "C:\Program Files\Veeam\",
        "C:\Program Files (x86)\Veeam\",
        "C:\Program Files\Common Files\Veeam\",
        "C:\Program Files (x86)\Common Files\Veeam\",
        "%WINDIR%\Veeam\Backup\",
        "%PROGRAMDATA%\Veeam\EndpointData\"
    )
    $procList = @()
    foreach ($pf in $procFolders) {
        $expanded = [Environment]::ExpandEnvironmentVariables($pf)
        if (Test-Path $expanded) {
            Get-ChildItem -Path $expanded -Filter *.exe -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $procList += $_.Name }
        }
    }
    $procList | Select-Object -Unique | ForEach-Object { Add-DefenderProcessExclusion $_ ([ref]$status) }

    Write-Host "`n=== Firewall Rules ===" -ForegroundColor White
	Add-FirewallRule "Veeam Exclusion - Agent Windows - General" TCP 135,445,6160,6162,6183,3260,2500-3300,49152-65535 ([ref]$status)

    Write-Host "`n=== Summary for Veeam Agent for Microsoft Windows ===" -ForegroundColor Magenta
    $status | ForEach-Object { Write-Host $_ }
}

function Configure-VSPCServerComponent {
    param([ref]$status)

    $folders = @(
        "C:\Program Files\Veeam\",
        "C:\Program Files\Common Files\Veeam\",
        "C:\Program Files (x86)\Common Files\Veeam\",
        "%PROGRAMDATA%\Veeam\",
        "%WINDIR%\Veeam\"
    )
    Write-Host "`n=== Folder Exclusions (VSPC Server Component) ===" -ForegroundColor White
    foreach ($f in $folders) { Add-DefenderFolderExclusion $f $status }

    Write-Host "`n=== Process Exclusions (VSPC Server Component) ===" -ForegroundColor White
    $procFolders = @(
        "C:\Program Files\Veeam\",
        "C:\Program Files\Common Files\Veeam\",
        "C:\Program Files (x86)\Common Files\Veeam\",
        "%WINDIR%\Veeam\"
    )
    $procList = @()
    foreach ($pf in $procFolders) {
        $expanded = [Environment]::ExpandEnvironmentVariables($pf)
        if (Test-Path $expanded) {
            Get-ChildItem -Path $expanded -Filter *.exe -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $procList += $_.Name }
        }
    }
    $procList | Select-Object -Unique | ForEach-Object { Add-DefenderProcessExclusion $_ $status }
}

function Configure-VSPCManagementAgent {
    param([ref]$status)

    $folders = @(
        "C:\Program Files\Veeam\",
        "C:\Program Files\Common Files\Veeam\",
        "C:\Program Files (x86)\Common Files\Veeam\",
        "%PROGRAMDATA%\Veeam\",
        "%WINDIR%\Veeam\",
        "\\localhost\admin$\Veeam\"
    )
    Write-Host "`n=== Folder Exclusions (VSPC Management Agent) ===" -ForegroundColor White
    foreach ($f in $folders) { Add-DefenderFolderExclusion $f $status }

    # Optional: Admin share path (used by the agent for deployment operations)
    Add-DefenderFolderExclusionOptional "\\localhost\admin$\Veeam\" $status

    Write-Host "`n=== Process Exclusions (VSPC Management Agent) ===" -ForegroundColor White
    $processes = @(
        "VeeamAgentWindows.exe",
        "ManagementAgent.exe",
        "VAC.CommunicationAgent.x64.msi",
        "VAC.CommunicationAgent.x86.msi",
        "Veeam.MBP.DeploymentService.exe"
    )
    foreach ($p in $processes) { Add-DefenderProcessExclusion $p $status }
}

function Configure-VSPC {
    $status = @()

    Write-Host "`n=== Veeam Service Provider Console (VSPC) ===" -ForegroundColor Cyan
    Write-Host "1 - VSPC Server Component"
    Write-Host "2 - VSPC Management Agent (Windows)"
    Write-Host "3 - Both (Server + Agent)"
    $sub = Read-Host "Please select what to configure (1-3)"

    switch ($sub) {
        "1" { Configure-VSPCServerComponent ([ref]$status) }
        "2" { Configure-VSPCManagementAgent ([ref]$status) }
        "3" {
            Configure-VSPCServerComponent ([ref]$status)
            Configure-VSPCManagementAgent ([ref]$status)
        }
        default {
            Write-Host "Invalid selection. Returning to main menu." -ForegroundColor Red
            return
        }
    }

    Write-Host "`n=== Firewall Rules ===" -ForegroundColor White
    Add-FirewallRule "Veeam Exclusion - VSPC - WebUI" TCP 1989,1280 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - VSPC - Management Agent" TCP 9999 ([ref]$status)

    Write-Host "`n=== Summary for Veeam Service Provider Console ===" -ForegroundColor Magenta
    $status | ForEach-Object { Write-Host $_ }
}

function Configure-VCC {
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
        "C:\Windows\SystemTemp\veeam-*.json",
        "%localappdata%\Veeam\Backup\",
        "C:\Program Files\PostgreSQL\",
        "C:\Windows\VeeamOneAgent\",
        "C:\Windows\VeeamOneDeploymentService\",
        "C:\Program Files\Veeam\Veeam ONE\Veeam Analytics Service\",
        "C:\ProgramData\Veeam\Veeam ONE\AnalyticsService\"
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
        "C:\Windows\Veeam\",
        "C:\Program Files\PostgreSQL\17\bin"
    )
    $procList = @()
    foreach ($pf in $procFolders) {
        if (Test-Path $pf) {
            Get-ChildItem -Path $pf -Filter *.exe -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $procList += $_.Name }
        }
    }
    $procList | Select-Object -Unique | ForEach-Object { Add-DefenderProcessExclusion $_ ([ref]$status) }

    Write-Host "`n=== Firewall Rules ===" -ForegroundColor White
    Add-FirewallRule "Veeam Exclusion - VCC Server - Backup Service" TCP 9392 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - VCC Server - Catalog Service" TCP 9393 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - VCC Server - Mount Server" TCP 9401 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - VCC Server - Rest API" TCP 9419 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - VCC Server - RPC and SMB" TCP 135,445 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - VCC Server - NetBIOS TCP" TCP 137 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - VCC Server - NetBIOS UDP" UDP 138-139 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - VCC Server - WebUI" TCP 443 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - VCC Server - CDP" TCP 33032-33035 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - VCC Server - Enterprise Manager" TCP 9405,9392,49152-65535 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - VCC Server - Agent Connections" TCP 10003,10005 ([ref]$status)
    Add-FirewallRule "Veeam Exclusion - VCC Server - Tenant Connections" TCP 6169,8190,8191,6185,2500-5000 ([ref]$status)

    Write-Host "`n=== Summary for Cloud Connect Server ===" -ForegroundColor Magenta
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
	Write-Host "11 - Veeam Recovery Orchestrator"
    Write-Host "12 - Veeam Service Provider Console (VSPC)"
    Write-Host "13 - Veeam Cloud Connect Server (VCC)"
    Write-Host "14 - Veeam Agent for Microsoft Windows"
    Write-Host "0  - Exit"
    Write-Host "--------------------------------------------------------" -ForegroundColor White
    $choice = Read-Host "Please select the component to configure (0-14)"
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
		"11" { Configure-Orchestrator    }
        "12" { Configure-VSPC            }
        "13" { Configure-VCC             }
        "14" { Configure-VeeamAgentWindows }
        "0"  { Write-Host "Exiting..." -ForegroundColor Cyan; Write-Log "Script terminated by user."; break }
        default { Write-Host "Invalid selection. Please enter 0-14." -ForegroundColor Red }
    }
    if ($choice -ne "0") { Read-Host -Prompt "Press [Enter] to return to the menu..." }
} while ($choice -ne "0")

#endregion Main Menu Loop

Write-Host "The output file is located at C:\Install."