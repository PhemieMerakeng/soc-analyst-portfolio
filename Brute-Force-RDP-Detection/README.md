# Azure SOC Lab — RDP Honeypot & Attack Map

## Overview

For this project, I built a Security Operations Center (SOC) environment in Microsoft Azure to practice the real workflow of a SOC analyst, exposing a real system to genuine internet attack traffic, ingesting the resulting logs into a SIEM, hunting through them with KQL, building an automated detection, and visualizing the attack activity geographically. I used a Free Services VM, connected its security logs to Microsoft Sentinel via the Azure Monitor Agent, hunted through failed RDP logons, built a scheduled analytics rule to auto-generate incidents, enriched the data with a GeoIP watchlist, and built a live workbook mapping attacker origins.

## Objectives

- Deploy a Windows VM as an intentional RDP honeypot using Azure's Free Services tier
- Onboard the VM as a log source into a Log Analytics Workspace via Azure Monitor Agent
- Enable Microsoft Sentinel as a cloud-native SIEM
- Hunt through real failed-logon telemetry using KQL
- Build a Scheduled Analytics Rule to automatically detect brute-force activity
- Enrich attacker IPs with GeoIP data and visualize them on a live map workbook

## Resources / Technologies Used

- **Microsoft Azure Free Account** 
- **Azure Virtual Machines** 
- **Azure Network Security Groups (NSG)**
- **Log Analytics Workspace**
- **Microsoft Sentinel** (cloud-native SIEM/SOAR)
- **Kusto Query Language (KQL)**
- **Azure Monitor Agent (AMA) / Data Collection Rules (DCR)**
- **Sentinel Watchlists** (GeoIP enrichment)
- **Sentinel Workbooks** (attack map visualization)


## Deployment

## Step 1 – Create a Resource Group

In the Azure Portal, I created a Resource Group to contain all lab resources.

#### Create Resource Group
Azure Portal → Resource groups → Create
Subscription: Free subscription
Resource group name: rg-honeypot-lab
Region: West US 2

<img width="1366" height="594" alt="Screenshot (564)" src="https://github.com/user-attachments/assets/fac434bf-fb95-4a05-8d5c-dda15b1e7036" />

## Step 2 – Deploy the Honeypot VM via Free Services

#### Create   Virtual Machine in Free Services
Azure Portal → Free services → Virtual Machine → Create
Resource group: rg-honeypot-lab
VM name: NAS-net-vm
Region: West US 2
Image: Windows Server 2025 Datacenter: Azure Edition
Size: Standard_B2ats_v2 (2 vCPU, 1 GiB RAM)
Inbound port: RDP (3389) → Allow

<img width="1366" height="590" alt="Screenshot (565)" src="https://github.com/user-attachments/assets/e41b9c79-0887-4a27-a25e-44483463ea9a" />


The VM deployed with no public IP address assigned. This is a default behavior of the Free Services — a public IP isn't part of the free allocation and carries its own charge. Since a honeypot has to be internet-reachable to attract real attack traffic, I associated one manually after deployment:

Azure Portal → VM → Networking → Network Interface → IP configurations → ipconfig1
Public IP address → Associate → Create new
Name: honeypot-vm-ip
SKU: Standard
Assignment: Static

## Step 3 – Scope the NSG to RDP Only

I confirmed the inbound rule after deployment and deliberately kept exposure limited to port 3389, rather than opening the VM to all ports and protocols — full exposure isn't necessary to attract RDP brute-force traffic and unnecessarily increases the risk of the VM being compromised and repurposed.

| Rule | Port | Protocol | Source | Action |
| :--- | :--- | :--- | :--- | :--- |
| RDP | 3389 | TCP | Any | Allow |

<img width="1038" height="240" alt="Screenshot (566)" src="https://github.com/user-attachments/assets/cafc2ac8-5e04-4131-a28d-e8cc5719f1a1" />



## Step 4 – Connect to the VM

I connected via RDP to confirm the deployment 

## Step 5 – Create a Log Analytics Workspace and Enable Sentinel

#### Create Log Analytics Workspace
Azure Portal → Log Analytics workspaces → Create
Resource group: rg-honeypot-lab
Name: honeypot-workspace
Region: West US 2
Pricing tier: Pay-as-you-go (includes free tier)

<img width="1366" height="579" alt="Screenshot (567)" src="https://github.com/user-attachments/assets/b3f8a707-c1ad-4775-acad-1092529ab1b1" />


#### Enable Microsoft Sentinel
Azure Portal → Microsoft Sentinel → Create
Select workspace: honeypot-workspace

<img width="1366" height="522" alt="Screenshot (568)" src="https://github.com/user-attachments/assets/2e246c98-6c60-489e-9e50-74e2538facbb" />


## Step 6 – Install Windows Security Events and Connect VM Logs via Azure Monitor Agent 

### Install Windows Security Events (WSE)
Microsoft Sentinel → Content Hub → Search "Windows Security Events" → Install
Microsoft Sentinel → Data connectors → Windows Security Events via AMA → Open connector page

#### Create Data Collection Rule
Microsoft Sentinel → Data connectors → Windows Security Events via AMA → Open connector page
Click + Create data collection rule
Rule name: DCR-Windows-Events
Resource group: rg-honeypot-lab
Resources → + Add resource(s) → Check NAS-net-vm → Apply
Review + create → Create

<img width="1366" height="596" alt="Screenshot (569)" src="https://github.com/user-attachments/assets/bf1e1b8a-91c2-4baa-9de8-0e70f51c6bd7" />


#### Verify Agent Installation
VM (NAS-net-vm) → Settings → Extensions + applications → Confirm AzureMonitorWindowsAgent shows "Provisioning succeeded"

Step 7 – Hunt Through the Logs with KQL

Microsoft Defender portal → Advanced Hunting

1. Identify the attackers:

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| summarize FailedAttempts = count() by IpAddress, TargetUserName
| sort by FailedAttempts desc
...
```
<img width="757" height="494" alt="Screenshot (584)" src="https://github.com/user-attachments/assets/be382a1f-36d7-41a4-9a39-45e895726fc5" />


Groups failed logons by source IP and targeted account, ranked by attempt count — the starting point for identifying who's attacking and what they're after.

2. Detect the spike:

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| summarize FailedAttempts = count() by bin(TimeGenerated, 1h)
| render timechart

...
```

<img width="1366" height="564" alt="Screenshot (574)" src="https://github.com/user-attachments/assets/e33de107-943e-4938-a8fe-bc76959f51ae" />

Plots failed logons in a time series graph to reveal whether activity is a genuine spike or just background noise.

3. Identify the pattern:

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| summarize Attempts = count() by TargetUserName
| sort by Attempts desc
| take 10
...
```
<img width="998" height="435" alt="Screenshot (575)" src="https://github.com/user-attachments/assets/87f33187-d1d8-4f35-b677-1a3284c7e7ad" />


Ranks the most-attempted usernames — generic guesses (admin, test, guest) point to an automated tool, while one specific username targeted repeatedly suggests something more deliberate.

4. Confirm the attack vector:

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| summarize count() by LogonType
...
```

<img width="998" height="421" alt="Screenshot (576)" src="https://github.com/user-attachments/assets/bc874866-e493-4613-ac6e-fb42ed5a2aea" />


Breaks down failures by Logon Type to confirm these attempts are actually coming through RDP, not some other login method producing the same event ID.


Step 8 – Build the Analytics Rule

Microsoft Defender portal → Microsoft Sentinel → Configuration → Analytics → Create → Scheduled query rule

Rule name:    RDP Brute Force - Failed Logons
Severity:     Medium
Tactic:       Credential Access

Rule query:

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by IpAddress, TargetUserName
| where FailedAttempts >= 5
...
```

<img width="933" height="542" alt="Screenshot (579)" src="https://github.com/user-attachments/assets/6a3f4231-732a-4cea-a799-d60a66cad295" />

Entity mapping:   Account = TargetUserName, IP = IpAddress
Scheduling:       Run every 5 min, lookback 5 min
Alert threshold:  Greater than 0 results
Action:           Auto-create incident

<img width="978" height="533" alt="Screenshot (580)" src="https://github.com/user-attachments/assets/410bcb4a-69f0-4345-933d-b2fefddcbb3b" />


Step 9 – Enrich with GeoIP Data

I imported a pre-trimmed GeoIP dataset 

Microsoft Defender portal → Microsoft Sentinel → Configuration → Watchlists → Add new

Watchlist:   geoip
SearchKey:   network


<img width="1181" height="564" alt="Screenshot (581)" src="https://github.com/user-attachments/assets/2d7b36c4-ad76-47d6-9cd1-2ec557031178" />


Step 10 – Build the Attack Map Workbook

Microsoft Defender portal → Microsoft Sentinel → Threat management → Workbooks → Add workbook

I built a Sentinel Workbook that summarizes failed-logon events per unique attacking IP, looks up each one against the GeoIP watchlist, and plots the results on a live map — sized and colored by attempt volume.

kql
let GeoIP = _GetWatchlist('Geoip');
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| where isnotempty(IpAddress) and IpAddress != "-" and not(ipv4_is_private(IpAddress))
| summarize FailedAttempts = count() by IpAddress
| evaluate ipv4_lookup(GeoIP, IpAddress, network)
| where isnotempty(latitude) and isnotempty(longitude)
| project AttackerIP = IpAddress, FailedAttempts, Country = countryname,
          City = cityname, Latitude = latitude, Longitude = longitude
| sort by FailedAttempts desc

Summarizes by IP first, then looks up each unique attacker once against the GeoIP watchlist, dropping any IP that didn't match a range so no blank markers try to render.

Name:         Honeypot Attack Map
Description:  Maps failed RDP logon attempts by attacker location.
Size by:      FailedAttempts
Color by:     FailedAttempts

<img width="1366" height="631" alt="Screenshot (583)" src="https://github.com/user-attachments/assets/59bb5405-63bf-4729-9f1f-619a58057105" />

Conclusion

This lab replicates the core workflow of a real SOC analyst — expose a system to genuine attack traffic, ingest and hunt through the resulting logs, build an automated detection, enrich the findings, and investigate the resulting incident — while working within real infrastructure constraints. Rather than treat the VM compute quota restriction as a blocker, I found and documented a legitimate alternative provisioning path, which is itself a practical skill: production environments have constraints too, and working around them without cutting corners on the security posture (scoping exposure to just RDP, keeping the OS firewall on, using a properly licensed GeoIP source) reflects real operational judgment.

Key takeaways from this project:

Hands-on experience deploying and securing cloud infrastructure under real subscription constraints
Practical use of Microsoft Sentinel as a SIEM, including data connectors, KQL, analytics rules, watchlists, and workbooks
Incident investigation and response mapped to the MITRE ATT&CK framework
Geographic enrichment and visualization of live attack telemetry
Judgment in scoping a lab's exposure and controls appropriately, rather than maximizing exposure for its own sake

This project is part of my ongoing cybersecurity portfolio, demonstrating applied skills in cloud security monitoring and SOC operations.
