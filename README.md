# SOC Labs

## About This Portfolio

Every lab in this repo follows the same core workflow a SOC analyst uses day to day: get logs into a SIEM, hunt through them, build a detection, investigate a triggered incident, and confirm a fix actually worked. Where possible, I use real-world data (exposed, internet-facing resources that attract genuine attack traffic) instead of simulated data, so the analysis reflects the kind of noisy, real signal analysts actually deal with.

## Labs
###	Lab	Focus	Status
| # | Lab / Focus | Scope & Tools | Status |
| :--- | :--- | :--- | :---: |
| 01 | Brute-Force RDP Detection | Microsoft Sentinel, KQL threat hunting, analytics rules, incident investigation, NSG remediation | ✅ Complete |
| 02 | TBD | | 🔜 Planned |
| 03 | TBD | | 🔜 Planned |
| 04 | TBD | | 🔜 Planned |

### Lab Summaries

#### 01 – Brute-Force RDP Detection

Deployed a Windows VM with RDP intentionally exposed to the internet to attract genuine brute-force login attempts. Streamed security logs into a Log Analytics Workspace, connected everything to Microsoft Sentinel, hunted through failed logons with KQL, built an analytics rule to auto-generate incidents, investigated a triggered incident end-to-end (mapped to MITRE ATT&CK T1110), and locked the VM down with an NSG rule — then verified attack volume dropped as a result.
