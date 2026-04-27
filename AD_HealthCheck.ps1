<#
.SYNOPSIS
    Active Directory Domain Health Check Script
.DESCRIPTION
    Runs comprehensive AD health checks and generates a single HTML report.
    Must be run as Administrator on a domain controller or management workstation
    with RSAT (Remote Server Administration Tools) installed.
.NOTES
    Commands covered:
      - dcdiag /v, /test:services, /test:advertising
      - repadmin /replsummary, /showrepl, /queue
      - dfsrmig /getglobalstate, dfsrdiag backlog
      - nslookup SRV, ipconfig /all, dnscmd /zoneinfo
      - netdom query fsmo, w32tm /query /status, /configuration
      - gpotool /health (Resource Kit — skipped if not installed), gpresult /r, gpresult /h
      - net group Domain Admins / Enterprise Admins
      - dsquery server, Get-ADDomain, Get-ADForest
#>

[CmdletBinding()]
param(
    [string]$ReportDir = "$env:USERPROFILE\Desktop"
)

# ─── Self-elevation ────────────────────────────────────────────────────────────
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Not running as Administrator. Relaunching elevated..." -ForegroundColor Yellow
    $escapedScript = $PSCommandPath -replace '"', '\"'
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$escapedScript`"" -Verb RunAs
    exit
}

# ─── Banner ───────────────────────────────────────────────────────────────────
Clear-Host
Write-Host ""
Write-Host "  +---------------------------------------------------------+" -ForegroundColor Cyan
Write-Host "  |       Active Directory Domain Health Check Tool        |" -ForegroundColor Cyan
Write-Host "  |                                                         |" -ForegroundColor Cyan
Write-Host "  |  Runs all standard AD health commands as Administrator  |" -ForegroundColor Cyan
Write-Host "  |  and compiles results into a single HTML report.        |" -ForegroundColor Cyan
Write-Host "  +---------------------------------------------------------+" -ForegroundColor Cyan
Write-Host ""

# ─── Prompt: Domain name ──────────────────────────────────────────────────────
$Domain = Read-Host "  Enter the domain DNS name (e.g., contoso.local)"
$Domain = $Domain.Trim()

if ([string]::IsNullOrWhiteSpace($Domain)) {
    Write-Host "  Attempting to auto-detect domain..." -ForegroundColor Yellow
    try {
        $Domain = (Get-ADDomain -ErrorAction Stop).DNSRoot
        Write-Host "  Auto-detected domain: $Domain" -ForegroundColor Green
    } catch {
        Write-Host "  ERROR: No domain entered and auto-detection failed. Exiting." -ForegroundColor Red
        Read-Host "  Press Enter to close"
        exit 1
    }
}

Write-Host ""
Write-Host "  Domain : $Domain" -ForegroundColor Cyan

# ─── Discover domain controllers for dfsrdiag ─────────────────────────────────
$DiscoveredDCs = @()
try {
    $DiscoveredDCs = @(Get-ADDomainController -Filter * -Server $Domain -ErrorAction Stop |
                       Select-Object -ExpandProperty Name | Sort-Object)
    Write-Host "  DCs found: $($DiscoveredDCs -join ', ')" -ForegroundColor Cyan
} catch {
    Write-Host "  Could not auto-discover DCs (RSAT may not be installed or domain unreachable)." -ForegroundColor Yellow
}

$SourceDC = if ($DiscoveredDCs.Count -ge 1) { $DiscoveredDCs[0] } else { "DC1" }
$DestDC   = if ($DiscoveredDCs.Count -ge 2) { $DiscoveredDCs[1] } else { $SourceDC }

Write-Host ""
Write-Host "  For DFSR Backlog check:" -ForegroundColor Yellow
Write-Host "    Source (smem) : $SourceDC"
Write-Host "    Dest   (rmem) : $DestDC"
$override = (Read-Host "  Press Enter to accept, or type 'SOURCE,DEST' to override").Trim()
if ($override -match ',') {
    $parts   = $override -split ',', 2
    $SourceDC = $parts[0].Trim()
    $DestDC   = $parts[1].Trim()
    Write-Host "  Using: $SourceDC -> $DestDC" -ForegroundColor Green
}

# ─── Timestamp / Report path ──────────────────────────────────────────────────
$RunTime   = Get-Date
$Stamp     = $RunTime.ToString("yyyyMMdd_HHmmss")
$ReportPath = Join-Path $ReportDir "AD_HealthCheck_${Stamp}.html"
$GpoHtmlTmp = Join-Path $env:TEMP   "AD_HC_gpo_${Stamp}.html"

Write-Host ""
Write-Host "  Report will be saved to: $ReportPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Starting checks..." -ForegroundColor Green
Write-Host "  (Some checks — especially dcdiag /v and repadmin — may take 1-5 minutes)" -ForegroundColor DarkGray
Write-Host ""

# ─── Result store ─────────────────────────────────────────────────────────────
$Sections = [System.Collections.Specialized.OrderedDictionary]::new()

function Add-CheckResult {
    param(
        [string]$Section,
        [string]$Command,
        [string]$Output,
        [string]$Status   # Success | Warning | Error
    )
    if (-not $Sections.Contains($Section)) {
        $Sections[$Section] = [System.Collections.Generic.List[hashtable]]::new()
    }
    $Sections[$Section].Add(@{ Command = $Command; Output = $Output; Status = $Status })
}

# ─── Runner ───────────────────────────────────────────────────────────────────
function Invoke-Check {
    param(
        [string]$Section,
        [string]$Label,
        [scriptblock]$ScriptBlock
    )
    Write-Host "  [RUN] $Label" -NoNewline

    $output = ""
    $status = "Success"

    try {
        # Capture both stdout and stderr; external exe exit codes are checked via $LASTEXITCODE
        $rawOutput = & $ScriptBlock 2>&1
        $output    = ($rawOutput | Out-String).TrimEnd()
        # Check external-command exit code
        if ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0) {
            $status = "Warning"
        }
    } catch {
        $output = "EXCEPTION: $($_.Exception.Message)"
        $status = "Error"
    }

    # Keyword scan for additional warning/failure signals
    $lc = $output.ToLower()
    if ($status -eq "Success") {
        if ($lc -match '\b(failed|critical error|unable to connect|access denied|not recognized|is not available)\b') {
            # Ignore benign patterns like "0 failures" or "no errors found"
            if ($lc -notmatch '0 failures|no errors|passed test|0 errors') {
                $status = "Warning"
            }
        }
    }

    $dot = switch ($status) {
        "Success" { Write-Host " ... OK"      -ForegroundColor Green }
        "Warning" { Write-Host " ... WARNING" -ForegroundColor Yellow }
        "Error"   { Write-Host " ... ERROR"   -ForegroundColor Red }
    }

    Add-CheckResult -Section $Section -Command $Label -Output $output -Status $status
}

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 1 — DC Diagnostics
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "  [1/8] DC Diagnostics" -ForegroundColor Yellow

Invoke-Check "DC Diagnostics" "dcdiag /v" {
    dcdiag /v 2>&1
}

Invoke-Check "DC Diagnostics" "dcdiag /test:services" {
    dcdiag /test:services 2>&1
}

Invoke-Check "DC Diagnostics" "dcdiag /test:advertising" {
    dcdiag /test:advertising 2>&1
}

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 2 — AD Replication
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "  [2/8] AD Replication" -ForegroundColor Yellow

Invoke-Check "AD Replication" "repadmin /replsummary" {
    repadmin /replsummary 2>&1
}

Invoke-Check "AD Replication" "repadmin /showrepl" {
    repadmin /showrepl 2>&1
}

Invoke-Check "AD Replication" "repadmin /queue" {
    repadmin /queue 2>&1
}

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 3 — DFSR / Sysvol
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "  [3/8] DFSR / Sysvol" -ForegroundColor Yellow

Invoke-Check "DFSR / Sysvol" "dfsrmig /getglobalstate" {
    dfsrmig /getglobalstate 2>&1
}

Invoke-Check "DFSR / Sysvol" "dfsrdiag backlog /rgname:`"Domain System Volume`" /smem:$SourceDC /rmem:$DestDC" {
    dfsrdiag backlog /rgname:"Domain System Volume" /smem:$SourceDC /rmem:$DestDC 2>&1
}

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 4 — DNS & Network
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "  [4/8] DNS & Network" -ForegroundColor Yellow

Invoke-Check "DNS & Network" "nslookup -type=SRV _ldap._tcp.dc._msdcs.$Domain" {
    # Call via cmd to prevent PowerShell from mis-parsing the -type= flag
    cmd /c "nslookup -type=SRV _ldap._tcp.dc._msdcs.$Domain" 2>&1
}

Invoke-Check "DNS & Network" "ipconfig /all" {
    ipconfig /all 2>&1
}

Invoke-Check "DNS & Network" "dnscmd /zoneinfo $Domain" {
    # dnscmd must run on a DNS server or target one — runs against local DNS service
    dnscmd /zoneinfo $Domain 2>&1
}

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 5 — FSMO Roles & Time Service
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "  [5/8] FSMO Roles & Time Service" -ForegroundColor Yellow

Invoke-Check "FSMO Roles & Time Service" "netdom query fsmo" {
    netdom query fsmo 2>&1
}

Invoke-Check "FSMO Roles & Time Service" "w32tm /query /status" {
    w32tm /query /status 2>&1
}

Invoke-Check "FSMO Roles & Time Service" "w32tm /query /configuration" {
    w32tm /query /configuration 2>&1
}

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 6 — Group Policy
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "  [6/8] Group Policy" -ForegroundColor Yellow

Invoke-Check "Group Policy" "gpotool /health" {
    $gpotoolCmd = Get-Command gpotool.exe -ErrorAction SilentlyContinue
    if ($gpotoolCmd) {
        gpotool /health 2>&1
    } else {
        Write-Output "SKIPPED: gpotool.exe not found on this system."
        Write-Output "gpotool ships with the Windows Server Resource Kit Tools (not installed by default)."
        Write-Output "Alternative: Use 'Get-GPO -All | Where-Object { `$_.GpoStatus -ne `"AllSettingsEnabled`" }' in PowerShell."
        Write-Output ""
        Write-Output "--- Fallback: GPO list via Get-GPO (GPMC) ---"
        try {
            Import-Module GroupPolicy -ErrorAction Stop
            Get-GPO -All -Domain $Domain | Format-Table DisplayName, GpoStatus, CreationTime, ModificationTime -AutoSize | Out-String
        } catch {
            Write-Output "GroupPolicy module not available: $($_.Exception.Message)"
        }
    }
}

Invoke-Check "Group Policy" "gpresult /r" {
    gpresult /r 2>&1
}

Invoke-Check "Group Policy" "gpresult /h (saved to Desktop)" {
    gpresult /h $GpoHtmlTmp /f 2>&1
}

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 7 — Security Groups
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "  [7/8] Privileged Security Groups" -ForegroundColor Yellow

Invoke-Check "Privileged Security Groups" "net group `"Domain Admins`" /domain" {
    net group "Domain Admins" /domain 2>&1
}

Invoke-Check "Privileged Security Groups" "net group `"Enterprise Admins`" /domain" {
    net group "Enterprise Admins" /domain 2>&1
}

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 8 — Directory & Forest Info
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "  [8/8] Directory & Forest Info" -ForegroundColor Yellow

Invoke-Check "Directory & Forest Info" "dsquery server -o rdn" {
    dsquery server -o rdn 2>&1
}

Invoke-Check "Directory & Forest Info" "Get-ADDomain | Format-List DomainMode" {
    try {
        Get-ADDomain -Server $Domain -ErrorAction Stop | Format-List DomainMode | Out-String
    } catch {
        "ERROR: $($_.Exception.Message)"
    }
}

Invoke-Check "Directory & Forest Info" "Get-ADForest | Format-List ForestMode" {
    try {
        Get-ADForest -Identity $Domain -ErrorAction Stop | Format-List ForestMode | Out-String
    } catch {
        "ERROR: $($_.Exception.Message)"
    }
}

# ─── Tally results ────────────────────────────────────────────────────────────
$TotalChecks = 0
$PassCount   = 0
$WarnCount   = 0
$ErrCount    = 0

foreach ($key in $Sections.Keys) {
    foreach ($item in $Sections[$key]) {
        $TotalChecks++
        switch ($item.Status) {
            "Success" { $PassCount++ }
            "Warning" { $WarnCount++ }
            "Error"   { $ErrCount++ }
        }
    }
}

# ─── HTML helpers ─────────────────────────────────────────────────────────────
function HtmlEncode([string]$s) {
    $s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;'
}

function StatusBadge([string]$status) {
    $map = @{ Success = '#238636'; Warning = '#9e6a03'; Error = '#da3633' }
    $bg  = $map[$status]
    "<span class='badge' style='background:$bg;'>$status</span>"
}

# ─── Build HTML body sections ─────────────────────────────────────────────────
$htmlBody = ""
$sectionIdx = 0
foreach ($sectionName in $Sections.Keys) {
    $sectionIdx++
    $checks    = $Sections[$sectionName]
    $sWarn     = ($checks | Where-Object { $_.Status -eq 'Warning' }).Count
    $sErr      = ($checks | Where-Object { $_.Status -eq 'Error'   }).Count
    $sIcon     = if ($sErr   -gt 0) { "#da3633" }
                 elseif ($sWarn -gt 0) { "#e3b341" }
                 else                  { "#3fb950" }

    $htmlBody += @"
<section class="card" id="sec$sectionIdx">
  <div class="card-header" onclick="toggleCard('sec$sectionIdx')">
    <span class="dot" style="background:$sIcon;"></span>
    <span class="card-title">$sectionName</span>
    <span class="card-meta">$($checks.Count) check(s)</span>
    <span class="caret" id="caret_sec$sectionIdx">&#9660;</span>
  </div>
  <div class="card-body" id="body_sec$sectionIdx">
"@

    $checkIdx = 0
    foreach ($check in $checks) {
        $checkIdx++
        $uid    = "c${sectionIdx}_${checkIdx}"
        $badge  = StatusBadge $check.Status
        $enc    = HtmlEncode $check.Output
        $htmlBody += @"
    <div class="check">
      <div class="check-header" onclick="toggleCheck('$uid')">
        <span class="caret" id="caret_$uid">&#9654;</span>
        <code class="cmd-label">$(HtmlEncode $check.Command)</code>
        $badge
      </div>
      <pre class="check-output" id="out_$uid">$enc</pre>
    </div>
"@
    }
    $htmlBody += "  </div>`n</section>`n"
}

# ─── Overall status color ─────────────────────────────────────────────────────
$overallColor = if ($ErrCount  -gt 0) { "#da3633" }
                elseif ($WarnCount -gt 0) { "#e3b341" }
                else                      { "#3fb950" }

$RunDateStr = $RunTime.ToString("dddd, MMMM d yyyy  HH:mm:ss")

# ─── Full HTML document ───────────────────────────────────────────────────────
$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AD Health Check &mdash; $Domain &mdash; $Stamp</title>
<style>
  :root{
    --bg:#0d1117;--surface:#161b22;--surface2:#1c2128;
    --border:#30363d;--text:#e6edf3;--sub:#8b949e;
    --green:#3fb950;--yellow:#e3b341;--red:#f85149;
    --accent:#58a6ff;
  }
  *{box-sizing:border-box;margin:0;padding:0;}
  body{background:var(--bg);color:var(--text);font-family:'Segoe UI',Arial,sans-serif;
       padding:24px 32px;line-height:1.5;}
  a{color:var(--accent);}
  /* ── Header ── */
  .page-header{margin-bottom:28px;}
  .page-header h1{font-size:1.55em;font-weight:700;margin-bottom:6px;}
  .page-header .meta{color:var(--sub);font-size:0.9em;}
  .page-header .meta span{margin-right:20px;}
  /* ── Summary bar ── */
  .summary{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:28px;}
  .sum-card{background:var(--surface);border:1px solid var(--border);border-radius:8px;
            padding:14px 22px;text-align:center;min-width:110px;}
  .sum-card .num{font-size:2em;font-weight:700;line-height:1.1;}
  .sum-card .lbl{font-size:0.75em;color:var(--sub);text-transform:uppercase;letter-spacing:.08em;margin-top:3px;}
  /* ── Section cards ── */
  .card{background:var(--surface);border:1px solid var(--border);border-radius:8px;
        margin-bottom:14px;overflow:hidden;}
  .card-header{display:flex;align-items:center;gap:10px;padding:13px 18px;
               cursor:pointer;user-select:none;border-bottom:1px solid transparent;}
  .card-header:hover{background:var(--surface2);}
  .dot{width:10px;height:10px;border-radius:50%;flex-shrink:0;}
  .card-title{font-weight:600;flex:1;font-size:1em;}
  .card-meta{font-size:0.78em;color:var(--sub);}
  .caret{font-size:.7em;color:var(--sub);margin-left:6px;}
  .card-body{border-top:1px solid var(--border);}
  /* ── Individual checks ── */
  .check{border-bottom:1px solid var(--border);}
  .check:last-child{border-bottom:none;}
  .check-header{display:flex;align-items:center;gap:8px;padding:9px 18px;
                cursor:pointer;user-select:none;}
  .check-header:hover{background:var(--surface2);}
  .cmd-label{font-family:'Cascadia Code','Consolas',monospace;font-size:0.85em;
             flex:1;color:var(--accent);}
  .badge{display:inline-block;padding:1px 9px;border-radius:20px;font-size:0.75em;
         font-weight:600;color:#fff;margin-left:6px;}
  .check-output{display:none;padding:14px 22px;background:#010409;
                font-family:'Cascadia Code','Consolas',monospace;font-size:0.8em;
                white-space:pre-wrap;word-break:break-all;color:#a5d6ff;
                border-top:1px solid var(--border);max-height:600px;overflow-y:auto;}
  /* ── Footer ── */
  .footer{margin-top:32px;text-align:center;color:var(--sub);font-size:0.8em;}
</style>
</head>
<body>

<div class="page-header">
  <h1>&#x1F4CB; Active Directory Health Check</h1>
  <div class="meta">
    <span>&#x1F310; Domain: <strong>$Domain</strong></span>
    <span>&#x1F5A5; Host: <strong>$env:COMPUTERNAME</strong></span>
    <span>&#x1F4C5; Run: <strong>$RunDateStr</strong></span>
    <span>&#x1F464; User: <strong>$env:USERDOMAIN\$env:USERNAME</strong></span>
  </div>
</div>

<div class="summary">
  <div class="sum-card">
    <div class="num" style="color:var(--accent);">$TotalChecks</div>
    <div class="lbl">Total Checks</div>
  </div>
  <div class="sum-card">
    <div class="num" style="color:var(--green);">$PassCount</div>
    <div class="lbl">Passed</div>
  </div>
  <div class="sum-card">
    <div class="num" style="color:var(--yellow);">$WarnCount</div>
    <div class="lbl">Warnings</div>
  </div>
  <div class="sum-card">
    <div class="num" style="color:var(--red);">$ErrCount</div>
    <div class="lbl">Errors</div>
  </div>
  <div class="sum-card" style="border-color:$overallColor;">
    <div class="num" style="color:$overallColor;">
      $(if ($ErrCount -gt 0) { "ISSUES" } elseif ($WarnCount -gt 0) { "REVIEW" } else { "HEALTHY" })
    </div>
    <div class="lbl">Overall</div>
  </div>
</div>

$htmlBody

<div class="footer">
  Generated by AD_HealthCheck.ps1 &mdash; $RunDateStr &mdash; $env:COMPUTERNAME
</div>

<script>
function toggleCard(id) {
  var body  = document.getElementById('body_'  + id);
  var caret = document.getElementById('caret_' + id);
  var hidden = body.style.display === 'none';
  body.style.display  = hidden ? '' : 'none';
  caret.innerHTML     = hidden ? '&#9660;' : '&#9654;';
  // add bottom border to header when open
  body.previousElementSibling.style.borderBottomColor = hidden ? '' : 'transparent';
}

function toggleCheck(uid) {
  var out   = document.getElementById('out_'   + uid);
  var caret = document.getElementById('caret_' + uid);
  var hidden = out.style.display === 'none';
  out.style.display = hidden ? 'block' : 'none';
  caret.innerHTML   = hidden ? '&#9660;' : '&#9654;';
}

// All section bodies start expanded
document.querySelectorAll('.card-body').forEach(function(b) {
  b.style.display = '';
});
document.querySelectorAll('[id^="caret_sec"]').forEach(function(c) {
  c.innerHTML = '&#9660;';
});
</script>
</body>
</html>
"@

# ─── Write files ──────────────────────────────────────────────────────────────
try {
    $html | Out-File -FilePath $ReportPath -Encoding UTF8 -Force
} catch {
    # Fallback to temp if Desktop write fails
    $ReportPath = Join-Path $env:TEMP "AD_HealthCheck_${Stamp}.html"
    $html | Out-File -FilePath $ReportPath -Encoding UTF8 -Force
    Write-Host "  NOTE: Could not write to Desktop, report saved to: $ReportPath" -ForegroundColor Yellow
}

# Copy the GPO HTML report alongside main report if it was generated
$GpoCopied = $false
if (Test-Path $GpoHtmlTmp) {
    $GpoDestPath = [System.IO.Path]::ChangeExtension($ReportPath, $null).TrimEnd('.') + "_GPO_Detail.html"
    try {
        Copy-Item $GpoHtmlTmp $GpoDestPath -Force
        $GpoCopied = $true
    } catch { }
}

# ─── Final summary ────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  +---------------------------------------------+" -ForegroundColor Cyan
Write-Host "  |              Health Check Complete          |" -ForegroundColor Cyan
Write-Host "  +---------------------------------------------+" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Total  : $TotalChecks checks"
Write-Host "  Passed : $PassCount" -ForegroundColor Green
Write-Host "  Warned : $WarnCount" -ForegroundColor $(if ($WarnCount -gt 0) { 'Yellow' } else { 'Gray' })
Write-Host "  Errors : $ErrCount"  -ForegroundColor $(if ($ErrCount  -gt 0) { 'Red'    } else { 'Gray' })
Write-Host ""
Write-Host "  Main report  : $ReportPath" -ForegroundColor Cyan
if ($GpoCopied) {
    Write-Host "  GPO detail   : $GpoDestPath" -ForegroundColor Cyan
}
Write-Host ""

$open = (Read-Host "  Open the HTML report in your browser now? (Y/N)").Trim()
if ($open -match '^[Yy]') {
    Start-Process $ReportPath
}

Write-Host ""
Write-Host "  Done. Press Enter to exit." -ForegroundColor Green
Read-Host
