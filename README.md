# SOC Labs

## About This Portfolio

Every lab in this repo follows the same core workflow a SOC analyst uses day to day: get logs into a SIEM, hunt through them, build a detection, investigate a triggered incident, and confirm a fix actually worked. Where possible, I use real-world data (exposed, internet-facing resources that attract genuine attack traffic) instead of simulated data, so the analysis reflects the kind of noisy, real signal analysts actually deal with.

## Labs

| # | Lab / Focus | Scope & Tools | Status |
|---|---|---|---|
| 01 | Brute-Force RDP Detection | Microsoft Sentinel, KQL threat hunting, analytics rules, incident investigation | ✅ Complete |
| 02 | SOAR Automated Incident Response | Logic Apps, Automation Rules, Managed Identity, NSG remediation, Discord notifications | ✅ Complete |
| 03 | Threat Intelligence Enrichment & Correlation | KQL `externaldata`, CINS Army feed, TI match analytics rule, GeoIP correlation | ✅ Complete |
| 04 | Threat Hunting & MITRE ATT&CK Coverage | KQL hunting, hypothesis-driven analysis, ATT&CK coverage mapping | 🔜 Planned |
| 05 | Detection-as-Code | Bicep/ARM templates, Git, CI/CD for analytics rules | 🔜 Planned |

## Lab Summaries

### 01 – Brute-Force RDP Detection

Deployed a Windows VM with RDP intentionally exposed to the internet to attract genuine brute-force login attempts. Streamed security logs into a Log Analytics Workspace, connected everything to Microsoft Sentinel, hunted through failed logons with KQL, and built an analytics rule to auto-generate incidents. Investigated a triggered incident end-to-end, mapping the activity to MITRE ATT&CK T1110 (Brute Force). Enriched attacker IPs with a GeoIP watchlist and built a Sentinel workbook that visualizes attack origins on a live map.

### 02 – SOAR Automated Incident Response

Built a Logic App playbook that fires automatically when the RDP brute-force analytics rule creates an incident. The playbook extracts the attacker's IP from the incident, blocks it at the NSG, sends a real-time Discord notification, and writes an audit comment back onto the incident. Uses a scoped Managed Identity with Network Contributor permissions rather than stored credentials, and includes an explicit safeguard against blocking my own IP. Wired to the analytics rule via a Sentinel Automation Rule.

### 03 – Threat Intelligence Enrichment & Correlation

Integrated CINS Army's known-malicious IP blocklist into the detection pipeline using KQL's `externaldata` operator, correlating the honeypot's live attacker IPs against it. Built a high-severity analytics rule that fires on any match, independent of attempt volume — a different signal than the volume-based brute-force rule from Lab 01. Combined the threat intel output with the existing GeoIP watchlist to produce a single view showing where each attacker is from and whether they are independently known to be malicious.
