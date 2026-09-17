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

### Step 1 – Create a Resource Group

In the Azure Portal, I created a Resource Group to contain all lab resources.

#### Create Resource Group
Azure Portal → Resource groups → Create
Subscription: Free subscription
Resource group name: rg-honeypot-lab
Region: West US 2

<img width="1366" height="594" alt="Screenshot (564)" src="https://github.com/user-attachments/assets/fac434bf-fb95-4a05-8d5c-dda15b1e7036" />

### Step 2 – Deploy the Honeypot VM via Free Services

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

### Step 3 – Scope the NSG to RDP Only

I confirmed the inbound rule after deployment and deliberately kept exposure limited to port 3389, rather than opening the VM to all ports and protocols — full exposure isn't necessary to attract RDP brute-force traffic and unnecessarily increases the risk of the VM being compromised and repurposed.

| Rule | Port | Protocol | Source | Action |
| :--- | :--- | :--- | :--- | :--- |
| RDP | 3389 | TCP | Any | Allow |

<img width="1038" height="240" alt="Screenshot (566)" src="https://github.com/user-attachments/assets/cafc2ac8-5e04-4131-a28d-e8cc5719f1a1" />



### Step 4 – Connect to the VM

I connected via RDP to confirm the deployment 

### Step 5 – Create a Log Analytics Workspace and Enable Sentinel

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


### Step 6 – Install Windows Security Events and Connect VM Logs via Azure Monitor Agent 

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
