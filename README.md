# AD Health Checker

A PowerShell tool that runs a full suite of Active Directory domain health checks and compiles the results into a single, easy-to-read HTML report.

Created by **Dallas Milem**

---

## What it checks

| Category | Commands |
|---|---|
| **DC Diagnostics** | `dcdiag /v`, `dcdiag /test:services`, `dcdiag /test:advertising` |
| **AD Replication** | `repadmin /replsummary`, `repadmin /showrepl`, `repadmin /queue` |
| **DFSR / Sysvol** | `dfsrmig /getglobalstate`, `dfsrdiag backlog` |
| **DNS & Network** | `nslookup -type=SRV`, `ipconfig /all`, `dnscmd /zoneinfo` |
| **FSMO Roles & Time** | `netdom query fsmo`, FSMO role holder lookup, `w32tm /query /status`, `w32tm /query /configuration` |
| **Group Policy** | `gpotool /health`, `gpresult /r`, `gpresult /h` |
| **Privileged Security Groups** | `net group "Domain Admins"`, `net group "Enterprise Admins"` |
| **Directory & Forest Info** | `dsquery server -o rdn`, `Get-ADDomain`, `Get-ADForest` |

The script also includes an interactive **FSMO role migration** option at the end of the run.

---

## Requirements

Before running, make sure the machine has:

1. **Windows Server (Domain Controller) or a management workstation** with **RSAT: Active Directory Domain Services and LDS Tools** installed (provides `dcdiag`, `repadmin`, `dsquery`, `netdom`, and the `ActiveDirectory` PowerShell module).
2. **RSAT: Group Policy Management Tools** installed (provides `gpresult`; `gpotool` is optional — see note below).
3. **Administrator rights** on the local machine — the script needs to run elevated.
4. **PowerShell 5.1** (built into Windows) or later. No additional modules need to be installed manually as long as RSAT is present.

> **Note on `gpotool`:** This tool ships with the older Windows Server Resource Kit and is not installed by default on modern systems. If it isn't found, the script automatically skips it and substitutes a `Get-GPO`-based summary instead — no action needed on your part.

---

## Download

### Option 1 — Direct download (recommended)

Run this in PowerShell to pull the files directly from GitHub:

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\Downloads\AD-Health-Checker" | Out-Null

Invoke-WebRequest -Uri "https://raw.githubusercontent.com/homestead367/AD-Health-Checker/master/AD_HealthCheck.ps1" `
    -OutFile "$env:USERPROFILE\Downloads\AD-Health-Checker\AD_HealthCheck.ps1"

Invoke-WebRequest -Uri "https://raw.githubusercontent.com/homestead367/AD-Health-Checker/master/Run-ADHealthCheck.cmd" `
    -OutFile "$env:USERPROFILE\Downloads\AD-Health-Checker\Run-ADHealthCheck.cmd"
```

> The `[Net.ServicePointManager]::SecurityProtocol` line forces TLS 1.2, which is required on older systems where Windows PowerShell 5.1 defaults to an outdated TLS version that GitHub rejects.

### Option 2 — Clone with git

```powershell
git clone https://github.com/homestead367/AD-Health-Checker.git
cd AD-Health-Checker
```

> **Important:** Don't copy/paste the script's text out of GitHub's web page into Notepad or another editor. Browsers and "smart" editors can silently convert straight quotes and dashes into typographic equivalents, which breaks the script's syntax. Always use a direct download or `git clone` so the file arrives byte-for-byte intact.

---

## Running the script

### Easiest way — double-click the launcher

1. Make sure `AD_HealthCheck.ps1` and `Run-ADHealthCheck.cmd` are in the **same folder**.
2. Double-click **`Run-ADHealthCheck.cmd`**.
3. Approve the **User Account Control (UAC)** prompt — this elevates PowerShell to Administrator automatically.

### Manual way — run from an elevated PowerShell prompt

```powershell
powershell -ExecutionPolicy Bypass -File "C:\path\to\AD_HealthCheck.ps1"
```

(The script will also try to self-elevate via UAC if it detects it isn't running as Administrator.)

---

## What to expect during the run

1. **The script auto-detects the domain** the machine is joined to and displays it with a **30-second countdown**. If no key is pressed it auto-accepts and moves on:
   - Press `Y`, Enter, or any key (except `N`) to accept immediately.
   - Press `N` to dismiss it and manually enter a different domain name instead.
   - If the machine is not domain-joined or detection fails, you will be prompted to enter the domain name manually.
2. **The script auto-discovers your domain controllers** and proposes a source/destination pair for the DFSR backlog check. Press Enter to accept, or type `SOURCE,DEST` to specify your own DC names.
3. **Checks run sequentially** — most complete in seconds, but `dcdiag /v` and the `repadmin` checks can take **1–5 minutes** on larger environments. Progress is displayed in the console as each check runs (`OK`, `WARNING`, or `ERROR`).
4. **At the end**, you'll be asked whether to review/migrate FSMO roles to a different DC (optional — type `N` to skip).
5. **The HTML report is saved to your Desktop** as `AD_HealthCheck_<timestamp>.html`, along with a companion `_GPO_Detail.html` file from `gpresult /h`.
6. **The report opens automatically** in your default browser as soon as it is generated.

---

## Reading the report

The report is a self-contained, dark-themed HTML file:

- A **summary bar** at the top shows total checks, pass/warning/error counts, and an overall health verdict.
- An **FSMO Role Holders table** lists the current Schema Master, Domain Naming Master, PDC Emulator, RID Master, and Infrastructure Master.
- Each **category** (DC Diagnostics, Replication, DNS, etc.) is a collapsible card — click the header to expand/collapse.
- Each **individual check** within a category can be expanded to view its full raw output, with a colored badge (green = success, yellow = warning, red = error).

You can open the report in any browser and share it as a single file — no external dependencies or internet connection required to view it.

---

## Troubleshooting

**"Could not create SSL/TLS secure channel" when downloading**
Run `[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12` before `Invoke-WebRequest`, then retry.

**Parse errors mentioning "ampersand" or unexpected tokens**
This means the `.ps1` file's content was altered in transit (usually from copying text out of a browser instead of downloading the raw file). Delete your local copy and re-download using the commands in the [Download](#download) section above — don't copy/paste from the GitHub web viewer.

**`dnscmd /zoneinfo` returns an error**
`dnscmd` must be run on a machine with the DNS Server role installed. If you're running this from a workstation without the DNS role, this check will report an error — that's expected and not indicative of a domain problem.

**`gpotool /health` is skipped**
This is expected on modern systems — `gpotool` is a legacy Resource Kit tool. The script automatically substitutes a `Get-GPO`-based summary.

**`dfsrdiag backlog` shows zero backlog with source = destination**
This happens when only one domain controller was discovered. The check is most useful in multi-DC environments; with a single DC it will simply confirm there's nothing to replicate against.

---

## Files in this repo

| File | Purpose |
|---|---|
| `AD_HealthCheck.ps1` | The main health-check script |
| `Run-ADHealthCheck.cmd` | One-click launcher that elevates and runs the script as Administrator |
| `README.md` | This file |
