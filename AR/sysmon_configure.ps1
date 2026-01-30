#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

###########################################################
# --- WAZUH ACTIVE RESPONSE HANDSHAKE (REQUIRED) ---
###########################################################

function Read-ARStdin {
    try {
        if ([Console]::IsInputRedirected) {
            
$stdin = [Console]::OpenStandardInput()
            $buffer = New-Object byte[] 4096
            $bytes = $stdin.Read($buffer, 0, $buffer.Length)
            if ($bytes -gt 0) {
                return [System.Text.Encoding]::UTF8.GetString($buffer, 0, $bytes)
            }

        }
        return ""
    } catch { return "" }
}

# 1) Read AR JSON from stdin (ignore if script run manually)
$raw = Read-ARStdin
$arInput = $null
if ($raw -and $raw.Trim().Length -gt 0) {
    try { $arInput = $raw | ConvertFrom-Json } catch { }
}

# 2) Immediately send ACK back so Wazuh is unblocked
$ack = @{ version = 1; command = "ack" } | ConvertTo-Json -Compress
[Console]::Out.WriteLine($ack)
[Console]::Out.Flush()

# 3) Detach long-running logic from AR pipes
#    After ACK, Wazuh no longer waits for output.
#    We now continue normally with Sysmon logic below.

###########################################################
# --- YOUR EXISTING SYSMON WORKER LOGIC BELOW ---
###########################################################

# -------------------- Settings --------------------
$ConfigDir  = "C:\Program Files (x86)\ossec-agent\shared"
$ConfigPath = Join-Path $ConfigDir 'sysmonconfig.xml'

$LogFile    = "C:\Program Files (x86)\ossec-agent\active-response\sysmonconfig-ar.log"
$LockFile   = "$LogFile.lock"

$StdOutFile = "$LogFile.stdout"
$StdErrFile = "$LogFile.stderr"

$TimeoutSec = 60

$candidates = @(
    'sysmon64', 'sysmon',
    'C:\Windows\sysmon64.exe',
    'C:\Windows\sysmon.exe'
)

# -------------------- Utilities --------------------
function Ensure-PathExists {
    param([string]$Path)
    $parent = Split-Path -Parent $Path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
}

function Log-Message {
    param([string]$Message)

    Ensure-PathExists -Path $LogFile
    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    $line = "$timestamp - $Message"

    $maxRetries = 5
    $retryDelay = 2
    $attempt = 0
    $lockHandle = $null

    while ($attempt -lt $maxRetries) {
        try {
            $lockHandle = New-Object System.IO.FileStream(
                $LockFile,
                [System.IO.FileMode]::CreateNew,
                [System.IO.FileAccess]::ReadWrite,
                [System.IO.FileShare]::None
            )

            Add-Content -LiteralPath $LogFile -Value $line -Encoding UTF8
            break
        }
        catch {
            Start-Sleep -Seconds $retryDelay
            $attempt++
        }
        finally {
            if ($lockHandle) {
                $lockHandle.Close()
                $lockHandle.Dispose()
                $lockHandle = $null
            }
            if (Test-Path -LiteralPath $LockFile) {
                try { Remove-Item -LiteralPath $LockFile -Force -ErrorAction SilentlyContinue } catch {}
            }
        }
    }
}

function Get-WorkingDirectory {
    param([string]$ExePath)
    try {
        if (-not $ExePath) { return $null }
        if ($ExePath -match '^[A-Za-z]:\\') {
            return (Split-Path -Parent $ExePath)
        }
        $cmd = Get-Command -Name $ExePath -ErrorAction Stop
        return (Split-Path -Parent $cmd.Path)
    } catch { return $null }
}

function Start-External {
    param(
        [string]$FilePath,
        [string]$Arguments,
        [int]$TimeoutSec,
        [string]$StdOutFile,
        [string]$StdErrFile
    )

    $wd = Get-WorkingDirectory $FilePath
    if ($StdOutFile) { Ensure-PathExists -Path $StdOutFile }
    if ($StdErrFile) { Ensure-PathExists -Path $StdErrFile }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.Arguments = $Arguments
    $psi.WorkingDirectory = if ($wd) { $wd } else { 'C:\Windows\System32' }
    $psi.CreateNoWindow = $true
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi

    if (-not $proc.Start()) {
        throw "Failed to start: $FilePath"
    }

    $outSB = New-Object System.Text.StringBuilder
    $errSB = New-Object System.Text.StringBuilder

    $proc.BeginOutputReadLine()
    $proc.BeginErrorReadLine()

    if (-not $proc.WaitForExit($TimeoutSec * 1000)) {
        try { $proc.Kill() } catch {}
        throw "Timeout after $TimeoutSec seconds invoking $FilePath"
    }

    $exit = $proc.ExitCode

    [PSCustomObject]@{
        ExitCode=$exit
        StdOut=""
        StdErr=""
    }
}

function Test-ExeAvailable {
    param([string]$exe)
    try {
        if ([System.IO.Path]::IsPathRooted($exe)) {
            return (Test-Path $exe)
        } else {
            $cmd = Get-Command $exe -ErrorAction Stop
            return $true
        }
    } catch { return $false }
}

function Get-SysmonServiceState {
    try {
        $svc = Get-Service 'sysmon' -ErrorAction Stop
        return $svc.Status
    } catch { return $null }
}

function Try-ConfigureSysmon {
    param([string]$exe, [string]$ConfigPath)

    if (-not (Test-ExeAvailable $exe)) {
        Log-Message "Candidate not found: $exe"
        return [PSCustomObject]@{ Success=$false; ExitCode=$null; Used=$exe }
    }

    $args = "-c `"$ConfigPath`""
    Log-Message "Attempting: $exe $args"

    $result = Start-External -FilePath $exe -Arguments $args -TimeoutSec $TimeoutSec `
        -StdOutFile $StdOutFile -StdErrFile $StdErrFile

    $ok = ($result.ExitCode -eq 0)

    Log-Message "Result: Exit=$($result.ExitCode); Success=$ok"

    return [PSCustomObject]@{
        Success=$ok; ExitCode=$result.ExitCode; Used=$exe
    }
}

###########################################################
# -------------------- Main Logic -------------------------
###########################################################

$overallSuccess = $false
$usedBinary = $null

$svcState = Get-SysmonServiceState
$svcStateText = if ($svcState) { $svcState } else { 'NotFound' }

try {
    Log-Message "=== Starting Sysmon config apply ==="
    Log-Message "Config path: $ConfigPath"
    Log-Message "Sysmon service state: $svcStateText"

    foreach ($cand in $candidates) {
        $r = Try-ConfigureSysmon -exe $cand -ConfigPath $ConfigPath
        if ($r.Success) {
            $overallSuccess = $true
            $usedBinary = $r.Used
            break
        }
    }

    if (-not $overallSuccess) {
        throw "Failed to apply Sysmon configuration with all candidates."
    }

    Log-Message "Sysmon configuration applied using: $usedBinary"
}
catch {
    Log-Message "ERROR: $($_.Exception.Message)"
    $overallSuccess = $false
}
finally {
    Log-Message "=== Finished Sysmon config apply (Success=$overallSuccess) ==="
}

if ($overallSuccess) {
    exit 0
} else {
    exit 1
}
