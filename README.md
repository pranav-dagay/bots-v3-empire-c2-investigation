# SOC Investigation: PowerShell Empire C2 Detection via Windows Event Log Analysis
### Splunk BOTS v3 Dataset | Pranav Dagay

---

## Overview

| Field | Details |
|---|---|
| **Dataset** | Splunk Boss of the SOC (BOTS) v3 |
| **Analyst** | Pranav Dagay |
| **Investigation Type** | Threat Detection & Incident Analysis |
| **Tools Used** | Splunk Enterprise, SPL |
| **Sourcetypes** | `WinEventLog:Security` |
| **Event IDs** | 4624, 4625, 4688 |
| **Affected Host** | `BSTOLL-L.froth.ly` |
| **Affected Account** | `BudStoll` |
| **Incident Date** | 2018-08-20 |
| **Severity** | Critical |
| **Disposition** | Confirmed Compromise — Escalate Immediately |

---

During routine monitoring of Windows Security Event logs in the BOTS v3 environment, only 3 failed logon events (4625) were identified against 427 successful logons (4624) and 7,427 process creation events (4688) — an unusually low failure ratio warranting investigation. Analysis of the failed logons revealed a single disabled Guest account access attempt on `MKRAEUS-L`, which pivoted the investigation toward successful logon and process creation activity. Focus on `BSTOLL-L.froth.ly` revealed that user `BudStoll` executed encoded PowerShell commands consistent with PowerShell Empire C2 malware on two occasions, alongside automated host reconnaissance commands — confirming a compromised endpoint.

---

## Investigation Steps

**Step 1 — Establish baseline Event ID distribution**
```spl
index=botsv3 earliest=0 sourcetype=WinEventLog:Security (EventCode=4624 OR EventCode=4625 OR EventCode=4688)
| stats count by EventCode
| sort -count
```
Found 7,427 process creation events (4688), 427 successful logons (4624), and only 3 failed logons (4625). The extremely low failure count relative to successful logons was the initial anomaly — in a normal environment, some level of failed authentication is expected. Only 3 failures across the entire environment warranted immediate review.

---

**Step 2 — Investigate the 3 failed logon events**
```spl
index=botsv3 earliest=0 sourcetype=WinEventLog:Security EventCode=4625
| table _time, _raw
```
Three events identified:
- `MKRAEUS-L` — User `MalloryKraeusen` attempted to access the disabled `Guest` account via `explorer.exe` (Logon Type 3, network). Failure reason: account currently disabled.
- `SEPM` (x2) — Service account `SEPM$` failed Logon Type 5 (service logon) via `svchost.exe`. Failure reason: error during logon — consistent with a misconfigured Symantec Endpoint Protection Manager service account.

**Assessment:** SEPM failures are benign service misconfigurations. The Guest account attempt by MalloryKraeusen is worth noting but showed no Source Network Address, indicating a local attempt with no follow-on successful access.

---

**Step 3 — Identify all accounts with successful logons**
```spl
index=botsv3 earliest=0 sourcetype=WinEventLog:Security EventCode=4624
| stats count by Account_Name
| sort -count
```
17 unique accounts identified. `MalloryKraeusen` had zero successful logons — confirming the Guest attempt was isolated. `bstoll@froth.ly` appeared with 4 successful logons using an unusual email-format username — atypical compared to all other accounts using short names.

---

**Step 4 — Profile bstoll successful logon events**
```spl
index=botsv3 earliest=0 sourcetype=WinEventLog:Security EventCode=4624 Account_Name="bstoll@froth.ly"
| table _time, Account_Name, ComputerName, Logon_Type, Source_Network_Address
| sort _time
```
All 4 logons occurred on `BSTOLL-L.froth.ly` at `19:05` — Logon Types 11 (CachedInteractive from `127.0.0.1`) and 7 (Unlock). This represents a user unlocking their workstation using cached credentials — not immediately suspicious but flagged for correlation with process activity.

---

**Step 5 — Identify high-volume process creation hosts**
```spl
index=botsv3 earliest=0 sourcetype=WinEventLog:Security EventCode=4688
(New_Process_Name="*powershell*" OR New_Process_Name="*cmd.exe*")
| stats count by ComputerName, New_Process_Name
| sort -count
```
`BSTOLL-L.froth.ly` had the highest cmd.exe count of any machine (376) and was also running PowerShell. This machine appeared in both the unusual logon investigation and the process creation analysis — making it the clear investigation priority.

---

**Step 6 — Review process command lines on BSTOLL-L**
```spl
index=botsv3 earliest=0 sourcetype=WinEventLog:Security EventCode=4688 ComputerName="BSTOLL-L.froth.ly"
(New_Process_Name="*powershell*" OR New_Process_Name="*cmd.exe*")
| table _time, Account_Name, New_Process_Name, Process_Command_Line
| sort _time
```
**Critical Finding — PowerShell Empire C2:**

At `15:29:48` and `16:58:40`, user `BudStoll` executed the following command:
```
powershell -noP -sta -w 1 -enc [LARGE BASE64 ENCODED PAYLOAD]
```

Flag analysis:
- `-noP` — bypasses PowerShell profile (defence evasion)
- `-sta` — single threaded apartment (required for certain exploits)
- `-w 1` — hidden window (concealment)
- `-enc` — Base64 encoded payload (obfuscation)

This is a **PowerShell Empire C2 stager** — one of the most widely recognised attacker frameworks for maintaining persistent control over compromised systems.

**Supporting reconnaissance commands also identified:**
- `reg query HKLM\SOFTWARE\...\Uninstall\*` — automated software enumeration (Empire host recon module)
- `netstat -nao | findstr LISTENING` — open port enumeration (repeated at 15:15, 16:15, 17:13, 18:55, 19:06, 20:40)
- `wmic os get LocalDateTime` — timestamp collection for C2 beacon synchronisation

All of the above are consistent with automated Empire post-exploitation modules running under BudStoll's compromised account.

---

## Pivot Points

The investigation pivoted twice. First, from failed logon analysis (which yielded mostly benign findings) to successful logon and process creation correlation — triggered by the unusual email-format account `bstoll@froth.ly`. Second, from generic cmd.exe volume analysis to specific command line inspection — triggered by `BSTOLL-L.froth.ly` appearing as the top process creation host. The second pivot revealed the Empire C2 stager, transforming what began as a routine logon review into a confirmed compromise investigation.

---

## IOC Summary

| Indicator | Type | Context |
|---|---|---|
| `BSTOLL-L.froth.ly` | Hostname | Compromised endpoint |
| `BudStoll` | Account | Compromised user account used to execute Empire |
| `powershell -noP -sta -w 1 -enc` | Command Pattern | PowerShell Empire C2 stager |
| `netstat -nao \| findstr LISTENING` | Command | Empire port enumeration module |
| `reg query HKLM\SOFTWARE\...\Uninstall` | Command | Empire software enumeration module |
| `wmic os get LocalDateTime` | Command | Empire beacon timestamp synchronisation |
| `2018-08-20 15:29:48` | Timestamp | First Empire execution |
| `2018-08-20 16:58:40` | Timestamp | Second Empire execution |

---

## Conclusion & Disposition

**Verdict: CONFIRMED COMPROMISE — Escalate Immediately, Isolate Endpoint**

User `BudStoll`'s account on `BSTOLL-L.froth.ly` was used to execute PowerShell Empire C2 malware on two occasions. The surrounding command activity — automated software enumeration, port scanning, and timestamp collection — is consistent with Empire's automated post-exploitation reconnaissance modules running under a compromised user context.

**Recommended Actions:**
1. **Isolate `BSTOLL-L.froth.ly` from the network immediately** — an active C2 connection may still be present
2. Revoke and reset `BudStoll` credentials across all systems
3. Identify the Empire C2 server by decoding the Base64 payload
4. Review `BudStoll`'s email and browser activity for initial compromise vector (phishing likely)
5. Scan other endpoints for the same PowerShell Empire command pattern
6. Preserve all logs and memory for forensic review

---

## Analyst Notes

The low 4625 count (3 events) was the initial anomaly that triggered this investigation — but the real finding came from process creation analysis, not authentication logs. This demonstrates that Windows Event Log investigations require correlating multiple event types rather than focusing on a single indicator. The `-enc` flag in PowerShell is one of the highest-value detection indicators in Windows environments — any encoded PowerShell execution should be treated as suspicious until proven otherwise. In future investigations, PowerShell command line inspection (4688) should be a standard step whenever a host shows elevated process creation activity.

---

## Key SPL Techniques Demonstrated

| Technique | Purpose |
|---|---|
| `EventCode=4624 OR EventCode=4625 OR EventCode=4688` | Multi-event filtering |
| `stats count by EventCode` | Event distribution analysis |
| `stats count by Account_Name \| sort -count` | Account activity profiling |
| `table _time, _raw` | Raw event inspection |
| `New_Process_Name="*powershell*"` | Wildcard process filtering |
| `table _time, Account_Name, New_Process_Name, Process_Command_Line` | Command line forensics |

---

## Tools & Environment

- **Splunk Enterprise 10.2.1** (local install)
- **Dataset:** Splunk BOTS v3 (~2.08M events, 107 sourcetypes)
- **Primary Sourcetype:** `WinEventLog:Security`
- **Key Event IDs:** 4624 (Successful Logon), 4625 (Failed Logon), 4688 (Process Creation)
- **Investigation Duration:** ~90 minutes

---

*Part of my SOC portfolio — [github.com/pranav-dagay](https://github.com/pranav-dagay)*
