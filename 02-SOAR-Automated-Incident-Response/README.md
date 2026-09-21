# Azure SOC Lab — SOAR: Automated Incident Response

## Project Overview

This project builds an automated response system that protects a cloud server from RDP brute-force attacks. Building on the detection rule from the earlier honeypot lab, it eliminates manual analyst intervention by automatically containing threats as soon as an alert fires. When the alert fires, a Logic App playbook runs automatically. It identifies the attacker's IP address from the alert, blocks that address at the server's firewall, sends a notification to Discord, and writes a record of what it did back onto the alert. 

## Objectives

- Design an automated end-to-end incident response workflow triggered by security alerts.
- Trigger a Logic App playbook automatically from a Sentinel incident, via an Automation Rule
- Use a Managed Identity with limited, scoped permissions instead of stored credentials
- Automatically extract the attacker's IP from a triggered incident
- Automatically contain the threat by blocking the IP at the NSG
- Send a real-time notification and write an audit trail back onto the incident
- Ensure the automation can never block my own IP, since I generate test traffic against the honeypot myself

## Resources / Technologies Used

- **Microsoft Sentinel** (Automation Rules, incidents — using incidents created by the "RDP Brute Force - Failed Logons" analytics rule from the **Azure SOC Lab — RDP Honeypot & Attack Map** lab)
- **Azure Logic Apps** 
- **Azure Managed Identity + RBAC** 
- **Azure Resource Manager REST API** 
- **Discord webhook** 
- **Azure Network Security Groups (NSG)**

## What I Did

### Step 1 – Created the Logic App

1. Azure Portal → searched **Logic Apps** → clicked **+ Add**
2. Selected the **Consumption** hosting plan
3. Filled in:
   - **Name:** playbook-block-bruteforce-ip
   - **Resource group:** rg-honeypot-lab
   - **Region:** same as Lab 1
   - **Zone redundancy:** Disabled
   - **Enable log analytics:** No
4. Clicked **Review + create** → **Create** → **Go to resource**

<img width="1366" height="584" alt="Screenshot (587)" src="https://github.com/user-attachments/assets/f9c799b1-8510-41c5-bfc9-71adf6cf7a61" />


### Step 2 – Enabled a Managed Identity and Granted It NSG Permissions

1. Opened the Logic App → **Settings → Identity**
2. Under **System assigned**, set **Status** to **On**
3. Clicked **Save**, confirmed
4. After saving, clicked **Azure role assignments** → **+ Add role assignment**
5. Configured:
   - **Scope:** Resource group
   - **Subscription:** my subscription
   - **Resource group:** rg-honeypot-lab
   - **Role:** Network Contributor
6. Clicked **Save**

<img width="1366" height="368" alt="Screenshot (588)" src="https://github.com/user-attachments/assets/a345e736-0b46-488a-aaae-195447a62402" />


### Step 3 – Granted Microsoft Sentinel Permission to Run the Playbook

**Logic App Contributor**

1. Logic App → **Access control (IAM)** → **+ Add → Add role assignment**
2. Searched **Logic App Contributor** → selected it → **Next**
3. Set **Assign access to** to **User, group, or service principal**
4. Clicked **+ Select members** → searched **Azure Security Insights** → selected it
5. Clicked **Review + assign**

<img width="1366" height="584" alt="Screenshot (590)" src="https://github.com/user-attachments/assets/0da8e843-fe2b-4264-a4d8-28379f7cb540" />

**Microsoft Sentinel Automation Contributor**

1. Azure Portal → **Resource groups** → opened **rg-honeypot-lab**
2. **Access control (IAM)** → **+ Add → Add role assignment**
3. Searched **Microsoft Sentinel Automation Contributor** → selected it → **Next**
4. Set **Assign access to** to **User, group, or service principal**
5. Clicked **+ Select members** → searched **Azure Security Insights** → selected it
6. Clicked **Review + assign**

<img width="1366" height="581" alt="Screenshot (602)" src="https://github.com/user-attachments/assets/beb43d86-4032-4c18-930f-99fe93844523" />


### Step 4 – Added the Sentinel Incident Trigger

1. Logic App → **Development Tools → Logic app designer**
2. In the connector search box, typed **Microsoft Sentinel**
3. Selected the trigger **Microsoft Sentinel incident** and signed in
4. Left subscription/workspace unconfigured — this trigger version is workspace-agnostic; incident data flows in at runtime from the Automation Rule
5. Clicked **Save**

📸 *Screenshot: Trigger in place.*

### Step 5 – Extracted the Attacker IP and Excluded My Own

**Added "Entities - Get IPs"**

1. Below the trigger, clicked **+ New step** → searched **Microsoft Sentinel**
2. Selected **Entities - Get IPs**
3. On the **Parameters** tab, clicked inside the **Entities List** box
4. Clicked the blue **"Enter data from previous..."** icon
5. Under **Microsoft Sentinel incident** (trigger), selected **Entities**

**Added the For each loop**

1. Clicked **+ New step** → searched **For each** → under **Built-in**, selected **For each**
2. Clicked inside the **Select an output from previous steps** box
3. Clicked the blue **"Enter data from previous..."** icon
4. Under **Entities - Get IPs**, selected **IPs**

**Added the Condition for IP exclusion**

1. Inside the For each card, clicked **Add an action** → searched **Condition** → selected **Condition**
2. **Left box:** clicked inside, clicked the blue **"Enter data from previous..."** icon, under **Entities - Get IPs** selected **IP address**
3. **Middle dropdown:** selected **is not equal to**
4. **Right box:** typed my own public IP as plain text
5. Left the **If false** branch empty
6. Clicked **Save**

Everything from Step 7 onward goes inside the **If true** branch.

<img width="1366" height="592" alt="Screenshot (592)" src="https://github.com/user-attachments/assets/64fbdbfa-bb3b-4d85-9f3f-128003c09349" />


### Step 6 – Pre-created the NSG Rule

1. Azure Portal → **Network security groups → NAS-net-vm-nsg**
2. Left menu → **Inbound security rules** → clicked **+ Add**
3. Filled in:
   - **Source:** IP Addresses
   - **Source IP addresses/CIDR ranges:** 192.0.2.1/32 (used a placeholder)
   - **Source port ranges:** *
   - **Destination:** Any
   - **Destination port ranges:** *
   - **Protocol:** Any
   - **Action:** Deny
   - **Priority:** 100
   - **Name:** Auto-Block-Attackers
4. Clicked **Add**

<img width="1366" height="563" alt="Screenshot (593)" src="https://github.com/user-attachments/assets/b4f958f5-543e-4b0c-8d1c-942ffcfe33da" />


The playbook updates this rule, so it must exist first.

### Step 7 – Blocked the IP at the NSG

1. Inside the **If true** branch, clicked **Add an action** → searched **HTTP**
2. Selected **HTTP** (built-in, globe icon — not HTTP Webhook)
3. Configured:
   - **Method:** PUT
   - **URI:** https://management.azure.com/subscriptions/<sub-id>/resourcegroups/rg-honeypot-lab/providers/Microsoft.Network/networkSecurityGroups/NAS-net-vm-nsg/securityRules/Auto-Block-Attackers?api-version=2023-09-01
   - **Headers:** Content-Type → application/json
4. Under **Advanced parameters**, enabled **Authentication** and set:
   - **Authentication type:** Managed identity
   - **Managed identity:** System-assigned managed identity
   - **Audience:** https://management.azure.com/
5. Pasted the JSON body:

```json
{
  "properties": {
    "protocol": "*",
    "access": "Deny",
    "priority": 100,
    "direction": "Inbound",
    "sourcePortRange": "*",
    "destinationPortRange": "*",
    "sourceAddressPrefixes": ["/32"],
    "destinationAddressPrefix": "*"
  }
}
```

6. Clicked between the opening quote and the `/32`
7. Clicked the blue **"Enter data from previous..."** icon → under **Entities - Get IPs**, selected **IP address**

*The original design used the built-in "Create or update a resource" action. It failed repeatedly and was replaced with the HTTP call above — see Problems Encountered.*



### Step 8 – Sent Notification via HTTP to Discord

**Created the Discord webhook**

1. Discord → **Server Settings → Integrations → Webhooks → New Webhook**
2. Named it and picked a channel
3. Clicked **Copy Webhook URL**

**Added the HTTP action**

1. Below the PUT action, clicked **Add an action** → searched **HTTP** → selected **HTTP**
2. Configured:
   - **Method:** POST
   - **URI:** my Discord webhook URL
   - **Headers:** Content-Type → application/json
3. In the **Body**, built the JSON and inserted three tokens via the blue **"Enter data from previous..."** icon:
   - **IP address** from **Entities - Get IPs**
   - **Title** from **Microsoft Sentinel incident** (trigger)
   - **Incident Created Time UTC** from **Microsoft Sentinel incident** (trigger)

```json
{ "content": "Blocked IP: <IP> | Incident: <title> | Time: <created time>" }
```

### Step 9 – Wrote an Audit Comment Back to the Incident

**Retrieved the incident**

1. Below the HTTP POST, clicked **Add an action** → searched **Microsoft Sentinel**
2. Selected **Get incident**
3. Clicked inside **Incident ARM ID**, clicked the blue **"Enter data from previous..."** icon
4. Under **Microsoft Sentinel incident** (trigger), selected **Incident ARM ID**

**Added the comment**

1. Below Get incident, clicked **Add an action** → searched **Microsoft Sentinel**
2. Selected **Add comment to incident (V3)**
3. Clicked inside **Incident ARM ID**, clicked the blue **"Enter data from previous..."** icon
4. Under **Get incident** (not the trigger), selected **Incident ARM ID**
5. In the **Message**, built the text and inserted the attacker IP as a dynamic token:

```
Automated response: blocked IP <IP> at NSG NAS-net-vm-nsg via playbook-block-bruteforce-ip. Notification sent.
```

Final **If true** branch order: HTTP PUT → HTTP POST → Get incident → Add comment to incident (V3).

### Step 10 – Wired the Playbook via an Automation Rule

1. Defender portal → **Microsoft Sentinel → Configuration → Automation**
2. Clicked **+ Create → Automation rule**
3. Set **Rule type** to **Standard** (Enhanced cannot trigger Logic App playbooks)
4. Configured:
   - **Name:** Auto-respond-to-bruteforce
   - **Trigger:** When incident is created
   - **Condition:** Analytics rule name → **Contains** → RDP Brute Force - Failed Logons
   - **Action:** Run Logic App playbook → playbook-block-bruteforce-ip
5. Clicked **Apply → Create**

<img width="1366" height="582" alt="Screenshot (603)" src="https://github.com/user-attachments/assets/382e886d-5e8d-4d42-8896-f6844b03213d" />

### Step 11 – Tested End-to-End

Ran the playbook against a real incident already in Sentinel — generated by live attack traffic from the earlier lab. All four confirmations came back positive.

<img width="1366" height="579" alt="Screenshot (604)" src="https://github.com/user-attachments/assets/6e86ad45-6fde-4f76-9499-432db1baebbc" />


1. **NSG updated** — `Auto-Block-Attackers` source now shows the attacker IP with `/32` (138.226.239.7/32)

<img width="1094" height="166" alt="Screenshot (606)" src="https://github.com/user-attachments/assets/78e7b063-49d0-4bcf-a53b-c7c2ade99331" />

2. **Discord notification received** — with blocked IP, incident title, and created time

<img width="994" height="169" alt="Screenshot (608)" src="https://github.com/user-attachments/assets/f331ad15-c6c9-49a1-9039-af49f12ce3a8" />

3. **Audit comment written** — visible on the incident's Activities tab

<img width="1366" height="437" alt="Screenshot (607)" src="https://github.com/user-attachments/assets/e16d4596-ba76-43f2-90b6-fc1991bbc8a5" />

4. **Logic App run history** — successful run


## Problems Encountered

### 1. The NSG update action failed repeatedly

Step 7 was originally built using the built-in **"Create or update a resource"** action from the Azure Resource Manager connector. It was intended to build the request path and payload automatically, but failed three times for three separate reasons:

- **Malformed request path.** The connector URL-encoded the entire path including the forward slashes, so Azure could not parse the resource address and could not locate the rule.
- **Incorrectly nested request body.** The connector added its own `properties` wrapper on top of the one I had written, producing `properties.properties`, which Azure's API rejects.
- **Pre-execution lookup failure.** The connector tried to read the rule before writing to it, which failed because the rule update hadn't run yet.

Each attempt to fix one problem surfaced a new one, indicating the tool itself was the issue rather than my configuration of it.

**Resolution:** Replaced the connector with a direct HTTP PUT to Azure's REST API, authenticated via the playbook's Managed Identity. Succeeded on the first attempt.

<img width="1366" height="582" alt="Screenshot (605)" src="https://github.com/user-attachments/assets/1871780b-7788-4578-9b5b-9ef591547047" />


### 2. The Gmail connector could not be used in the same workflow

Attempted to send notification emails via the Gmail connector. The Logic App returned a `GmailConnectorPolicyViolation` error — Gmail is a Power Platform connector and cannot coexist with the Sentinel and ARM connectors in the same workflow.

**Resolution:** Replaced the email notification with a Discord webhook via the built-in HTTP action.

<img width="1366" height="587" alt="Screenshot (596)" src="https://github.com/user-attachments/assets/f26ed346-1cfe-4ca0-a0db-46e55b3a40bd" />

## Conclusion

This project took the RDP honeypot from the earlier lab and gave it a way to fight back on its own. Before, the honeypot could spot an attack and raise an alert, but someone still had to see that alert and decide what to do about it. Now the playbook handles that step: it pulls the attacker's IP off the incident, blocks it at the firewall, sends a notification, and leaves a note on the incident explaining what it did. I tested it against a real incident from real attack traffic, and all four pieces worked — the NSG updated, the Discord message arrived, the comment showed up on the incident, and the Logic App run finished clean.

### **Key takeaways from this project:**

- Built an end-to-end Sentinel-to-Logic-App automation chain: incident trigger, entity extraction, conditional exclusion logic, network remediation, external notification, and incident audit logging
- Diagnosed three distinct failure modes in the same tool — a malformed request path, an incorrectly nested request body, and a pre-execution lookup failure — rather than treating them as unrelated bugs
- Replaced the failing built-in connector with a direct HTTP call to Azure's REST API, which succeeded on the first attempt
- Applied least-privilege permissions throughout — the playbook's identity can only modify network resources within a single resource group
- Built an explicit safeguard against the automation blocking my own IP, since I generate test traffic against the honeypot myself
- Tested the pipeline against a real incident from live attack traffic
