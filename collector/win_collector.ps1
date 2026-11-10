<#
.SYNOPSIS
    WinDFIR-AI Endpoint Forensic Collector (PowerShell Edition - Pure ASCII)
.DESCRIPTION
    Zero-dependency Windows emergency response collector compatible with PowerShell 5.1+
    on any locale (Chinese/English Windows Server & Workstation).
    Collects:
    1. Host basic info (Hostname, internal IPv4, OS version) -> system_snapshot.json
    2. Active processes (PID, PPID, CommandLine, Executable SHA256)
    3. Active TCP/UDP network connections
    4. Scheduled tasks and Registry Run/RunOnce persistence items
    5. Core event logs: Security.evtx, System.evtx, Microsoft-Windows-PowerShell%4Operational.evtx
    Modes:
    - Offline mode (default): creates Forensic_<Hostname>_<Timestamp>.zip in current directory
    - Online upload mode: -Server http://127.0.0.1:8000 -CaseId IR-20261021-XXXXXX
      (also supports POSIX flags: --server http://127.0.0.1:8000 --case-id 20261021-XXXXXX)
#>

param(
    [string]$Server = "",
    [string]$CaseId = "",
    [string]$OutputDir = "."
)

# Support POSIX-style CLI arguments: --server http://127.0.0.1:8000 --case-id IR-20261021-21CEDA
for ($i = 0; $i -lt $args.Count; $i++) {
    $argName = [string]$args[$i]
    if (($argName -eq "--server" -or $argName -eq "-s") -and ($i + 1) -lt $args.Count) {
        $Server = [string]$args[$i + 1]
    }
    elseif (($argName -eq "--case-id" -or $argName -eq "--case" -or $argName -eq "-c") -and ($i + 1) -lt $args.Count) {
        $CaseId = [string]$args[$i + 1]
    }
    elseif (($argName -eq "--out" -or $argName -eq "-o") -and ($i + 1) -lt $args.Count) {
        $OutputDir = [string]$args[$i + 1]
    }
}

$ErrorActionPreference = "SilentlyContinue"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "   WinDFIR-AI Endpoint Forensic Collector v1.1 (PowerShell)     " -ForegroundColor Cyan
Write-Host "   Windows DFIR Artifact & EVTX Triage Tool (Offline / Online)  " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# 1. Collect basic host profile
$Hostname = $env:COMPUTERNAME
if (-not $Hostname) { $Hostname = [System.Net.Dns]::GetHostName() }

$IPAddress = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
    $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*"
} | Select-Object -First 1).IPAddress
if (-not $IPAddress) { $IPAddress = "127.0.0.1" }

$OSInfo = Get-CimInstance Win32_OperatingSystem
$OSVersion = if ($OSInfo) { ([string]$OSInfo.Caption + " (" + [string]$OSInfo.Version + ")") } else { [System.Environment]::OSVersion.VersionString }

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$WorkDir = Join-Path $env:TEMP ("windfir_collect_" + $Timestamp)
New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null

Write-Host ("[1/6] Host Profile: " + $Hostname + " (" + $IPAddress + ") - " + $OSVersion) -ForegroundColor Green

# 2. Enumerate active processes (PID, PPID, CommandLine, SHA256)
Write-Host "[2/6] Enumerating active processes, command lines, and image SHA256..." -ForegroundColor Green
$Processes = @()
$HashCache = @{}
$WmiProcs = Get-CimInstance Win32_Process
foreach ($p in $WmiProcs) {
    $sha256 = ""
    $exePath = [string]$p.ExecutablePath
    if ($exePath -and (Test-Path $exePath)) {
        if ($HashCache.ContainsKey($exePath)) {
            $sha256 = $HashCache[$exePath]
        }
        else {
            $hashObj = Get-FileHash -Path $exePath -Algorithm SHA256
            if ($hashObj -and $hashObj.Hash) {
                $sha256 = $hashObj.Hash.ToLower()
            }
            $HashCache[$exePath] = $sha256
        }
    }
    $Processes += [PSCustomObject]@{
        pid             = $p.ProcessId
        ppid            = $p.ParentProcessId
        name            = [string]$p.Name
        executable_path = $exePath
        command_line    = [string]$p.CommandLine
        username        = ""
        sha256          = $sha256
    }
}
Write-Host ("      -> Collected active processes: " + $Processes.Count) -ForegroundColor Gray

# 3. Enumerate active TCP/UDP network connections
Write-Host "[3/6] Enumerating active TCP/UDP network connections..." -ForegroundColor Green
$NetConns = @()
$TcpConns = Get-NetTCPConnection
foreach ($c in $TcpConns) {
    $NetConns += [PSCustomObject]@{
        proto        = "TCP"
        local_addr   = ([string]$c.LocalAddress + ":" + [string]$c.LocalPort)
        foreign_addr = ([string]$c.RemoteAddress + ":" + [string]$c.RemotePort)
        state        = [string]$c.State
        pid          = [string]$c.OwningProcess
    }
}
$UdpEnds = Get-NetUDPEndpoint
foreach ($u in $UdpEnds) {
    $NetConns += [PSCustomObject]@{
        proto        = "UDP"
        local_addr   = ([string]$u.LocalAddress + ":" + [string]$u.LocalPort)
        foreign_addr = "*:*"
        state        = "LISTEN"
        pid          = [string]$u.OwningProcess
    }
}
Write-Host ("      -> Collected network connections: " + $NetConns.Count) -ForegroundColor Gray

# 4. Collect scheduled tasks and registry Run persistence items
Write-Host "[4/6] Collecting scheduled tasks and registry Run persistence items..." -ForegroundColor Green
$Tasks = @()
$RawTasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft\*" }
foreach ($t in $RawTasks) {
    $actionExec = ($t.Actions | ForEach-Object { ([string]$_.Execute + " " + [string]$_.Arguments) }) -join "; "
    $Tasks += [PSCustomObject]@{
        task_name   = ([string]$t.TaskPath + [string]$t.TaskName)
        status      = [string]$t.State
        task_to_run = $actionExec
        run_as_user = [string]$t.Principal.UserId
    }
}

$Autoruns = @()
$RegPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
)
foreach ($rp in $RegPaths) {
    if (Test-Path $rp) {
        $props = Get-ItemProperty -Path $rp
        foreach ($prop in $props.PSObject.Properties) {
            if ($prop.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")) {
                $Autoruns += [PSCustomObject]@{
                    registry_path = $rp
                    name          = [string]$prop.Name
                    command       = [string]$prop.Value
                }
            }
        }
    }
}

# Write system_snapshot.json
$Snapshot = [PSCustomObject]@{
    collected_at        = (Get-Date).ToString("o")
    hostname            = $Hostname
    ip_address          = $IPAddress
    os_version          = $OSVersion
    collector_version   = "WinDFIR-AI-Collector-PS-1.1"
    processes           = $Processes
    network_connections = $NetConns
    scheduled_tasks     = $Tasks
    registry_autoruns   = $Autoruns
}
$SnapshotPath = Join-Path $WorkDir "system_snapshot.json"
$SnapshotJson = $Snapshot | ConvertTo-Json -Depth 6
[System.IO.File]::WriteAllText($SnapshotPath, $SnapshotJson, [System.Text.Encoding]::UTF8)
Write-Host "      -> Generated host snapshot: system_snapshot.json" -ForegroundColor Gray

# 5. Export core Windows Event Logs (.evtx)
Write-Host "[5/6] Exporting core event logs (Security / System / PowerShell Operational)..." -ForegroundColor Green
$Channels = @(
    @{ Channel = "Security"; File = "Security.evtx" },
    @{ Channel = "System"; File = "System.evtx" },
    @{ Channel = "Microsoft-Windows-PowerShell/Operational"; File = "PowerShell_Operational.evtx" }
)
$WinevtDir = Join-Path $env:SystemRoot "System32\winevt\Logs"

foreach ($ch in $Channels) {
    $destFile = Join-Path $WorkDir $ch.File
    & wevtutil.exe epl $ch.Channel $destFile /ow:true 2>$null
    if (Test-Path $destFile) {
        Write-Host ("      -> [OK] Exported via wevtutil: " + $ch.File) -ForegroundColor Gray
    }
    else {
        $rawName = $ch.Channel.Replace("/", "%4") + ".evtx"
        $rawSource = Join-Path $WinevtDir $rawName
        if (Test-Path $rawSource) {
            Copy-Item -Path $rawSource -Destination $destFile -Force
        }
        if (Test-Path $destFile) {
            Write-Host ("      -> [OK] Exported via file copy: " + $ch.File) -ForegroundColor Gray
        }
        else {
            Write-Host ("      -> [WARN] Failed to export " + $ch.Channel + " (Run as Administrator recommended)") -ForegroundColor Yellow
        }
    }
}

# 6. Compress artifacts into Forensic_<Hostname>_<Timestamp>.zip
Write-Host "[6/6] Compressing forensic triage package..." -ForegroundColor Green
$SafeHost = $Hostname -replace '[\\/:*?"<>|\s]', '_'
$ZipFileName = ("Forensic_" + $SafeHost + "_" + $Timestamp + ".zip")
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}
$ResolvedOut = (Resolve-Path $OutputDir).Path
$ZipFullPath = Join-Path $ResolvedOut $ZipFileName

if (Test-Path $ZipFullPath) { Remove-Item $ZipFullPath -Force }
Compress-Archive -Path (Join-Path $WorkDir "*") -DestinationPath $ZipFullPath -Force
Remove-Item -Path $WorkDir -Recurse -Force

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ("[+] Local forensic archive created: " + $ZipFullPath) -ForegroundColor Green

# 7. Online upload mode if Server and CaseId are provided
$CleanServer = $Server.Trim()
$CleanCaseId = $CaseId.Trim()

if ($CleanServer -ne "" -and $CleanCaseId -ne "") {
    $BaseUrl = $CleanServer.TrimEnd('/')
    $UploadUrl = ($BaseUrl + "/api/cases/" + [uri]::EscapeDataString($CleanCaseId) + "/hosts")
    Write-Host ("[*] Uploading forensic package to server: " + $UploadUrl + " ...") -ForegroundColor Cyan
    try {
        $curlBin = Get-Command "curl.exe" -ErrorAction SilentlyContinue
        if ($curlBin) {
            $resp = & curl.exe -s -S -X POST $UploadUrl `
                -F ("hostname=" + $Hostname) `
                -F ("ip_address=" + $IPAddress) `
                -F ("os_version=" + $OSVersion) `
                -F "sync_parse=true" `
                -F ("file=@" + $ZipFullPath)
            if ($LASTEXITCODE -eq 0 -and $resp -notmatch '"detail":') {
                Write-Host "[+] Online upload and EVTX parsing completed! Server response:" -ForegroundColor Green
                Write-Host ("    " + $resp) -ForegroundColor Gray
            }
            else {
                Write-Host ("[!] Server returned an error response: " + $resp) -ForegroundColor Yellow
                Write-Host ("    You can manually upload " + $ZipFileName + " via the web console.") -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "[!] curl.exe not found on this system. Please upload the ZIP file manually." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host ("[!] Online upload failed: " + $_.Exception.Message) -ForegroundColor Red
        Write-Host ("    Please manually drag and drop " + $ZipFileName + " into the WinDFIR-AI web console.") -ForegroundColor Yellow
    }
}
else {
    Write-Host "[*] Running in OFFLINE mode. Next steps:" -ForegroundColor Gray
    Write-Host ("    1. Drag and drop " + $ZipFileName + " into the WinDFIR-AI web console; OR") -ForegroundColor Gray
    Write-Host "    2. Run in ONLINE mode: powershell -ExecutionPolicy Bypass -File .\win_collector.ps1 --server http://127.0.0.1:8000 --case-id IR-YYYYMMDD-XXXXXX" -ForegroundColor Gray
}
Write-Host "================================================================" -ForegroundColor Cyan
