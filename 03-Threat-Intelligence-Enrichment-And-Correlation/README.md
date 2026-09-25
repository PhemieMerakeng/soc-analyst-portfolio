# Threat Intelligence Enrichment & Correlation

## Overview
This project adds threat-intelligence detection to the honeypot. It checks the attacker IPs hitting the VM against CINS Army's blocklist of known-malicious IPs, using KQL's externaldata operator to pull the feed at query time. It correlates the results, builds an analytics rule that fires automatically on any match, and combines the output with the existing GeoIP watchlist to show where each attacker is from and whether they are independently known to be malicious.

## Objectives
- **Integrate a free threat intelligence feed into Microsoft Sentinel**
- **Correlate real honeypot attacker IPs against known-malicious infrastructure**
- **Build a detection that fires automatically on a match, independent of attempt volume**
- **Combine threat intel with existing GeoIP enrichment for a richer view of each attacker**

## Resources / Technologies Used
- **Microsoft Sentinel (Analytics rules, correlation queries)**
- **CINS Army IP blocklist (Threat intelligence feed, updated every 3 hours)**
- **Kusto Query Language (KQL) — externaldata, joins, watchlist lookups**
- **Sentinel Watchlists (existing GeoIP dataset from 01-Brute-Force-RDP-Detection)**


## Deployment 

### Step 1 – Selected the Threat Intel Feed
I used CINS Army's bad-guy IP list, a free feed of roughly 15,000 IPs observed carrying out malicious activity in the last 24 hours. It refreshes every 3 hours, which gives it a good chance of matching against live attacker traffic.

I confirmed the feed was reachable by pulling it directly with KQL's externaldata operator:

```kql
externaldata(ip:string)
[@"http://cinsscore.com/list/ci-badguys.txt"]
with(format="csv")
| where ip matches regex @"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
| distinct ip
| take 10
```

<img width="1004" height="557" alt="Screenshot (621)" src="https://github.com/user-attachments/assets/2c565a5a-bb11-48d6-a4d6-993b08a186e6" />

### Step 2 – Correlated Against My Attacker IPs
Rather than importing the feed into a Watchlist (which would require re-uploading on every refresh), I used KQL's externaldata operator to pull the feed at query time. This keeps the detection current without manual re-import.

```kql
let BadIPs = (
    externaldata(ip:string)
    [@"http://cinsscore.com/list/ci-badguys.txt"]
    with(format="csv")
    | where ip matches regex @"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    | distinct ip
);
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count(), LastSeen = max(TimeGenerated) by IpAddress
| join kind=inner (BadIPs) on $left.IpAddress == $right.ip
| project IpAddress, FailedAttempts, LastSeen
| sort by FailedAttempts desc
```

<img width="1001" height="526" alt="Screenshot (622)" src="https://github.com/user-attachments/assets/17f5ce36-7194-49c4-9aae-06a17fb0a936" />


This is intelligence-driven detection rather than volume-based — a single connection from a known-bad IP is worth flagging regardless of attempt count.

### Step 3 – Built an Analytics Rule for Future Matches
The rule fires automatically whenever a honeypot attacker IP appears on the CINS Army feed, so the correlation runs on its own without needing to be re-run manually.

**Created the rule:**

Defender portal → Microsoft Sentinel → Configuration → Analytics

Clicked + Create → Scheduled query rule

**General tab:**

Name:         Known-Malicious IP Contact - Threat Intel Match
Description:  Fires when a honeypot attacker IP appears on the CINS Army known-malicious IP blocklist.
Severity:     High
MITRE ATT&CK: Command and Control

**Set rule logic tab — Rule query:**

```kql
let BadIPs = (
    externaldata(ip:string)
    [@"http://cinsscore.com/list/ci-badguys.txt"]
    with(format="csv")
    | where ip matches regex @"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    | distinct ip
);
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by IpAddress, TargetUserName
| join kind=inner (BadIPs) on $left.IpAddress == $right.ip
| project IpAddress, TargetUserName, FailedAttempts
```

<img width="905" height="543" alt="Screenshot (623)" src="https://github.com/user-attachments/assets/ab80514d-9b36-43f1-ab5e-563aaa058c3c" />


This is the same join logic as Step 2, but grouped by IP and username so each result carries both entity types for mapping.

**Entity mapping:**

IP → Address → IpAddress

Account → Name → TargetUserName

**Query scheduling:**

Run every:                  1 hour
Lookup data from the last:  1 hour
Alert threshold:

Generate alert when number of query results is:  Greater than 0
Incident settings:

Create incidents from alerts triggered by this analytics rule:  Enabled
Alert grouping:                                                 Disabled
Automated response tab: left blank — no playbook action attached to this rule.

Click Review + create → Save.

<img width="1340" height="562" alt="Screenshot (624)" src="https://github.com/user-attachments/assets/aa1f08e1-5494-4a4c-9be6-e26cf53f7cb4" />


I set this to High severity, higher than the brute-force rule's Medium — a volume-based alert could still be background noise, but a match against a known-malicious list is a higher-confidence signal since it's confirmed against external intelligence rather than inferred from behavior alone.

### Step 4 – Combined with GeoIP for a Fuller Picture
This produces a single view showing every attacker, their attempt count, their geographic origin, and whether they're on the known-malicious list — answering a richer question than either enrichment source alone.

**Ran the combined query:**

Defender portal → Microsoft Sentinel → Logs (or Advanced Hunting)

```kql
let BadIPs = (
    externaldata(ip:string)
    [@"http://cinsscore.com/list/ci-badguys.txt"]
    with(format="csv")
    | where ip matches regex @"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    | distinct ip
);
let GeoIP = _GetWatchlist("Geoip");
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by IpAddress
| evaluate ipv4_lookup(GeoIP, IpAddress, network)
| extend IsKnownBad = iff(IpAddress in ((BadIPs | project ip)), "Yes", "No")
| project IpAddress, FailedAttempts, Country = countryname, City = cityname, IsKnownBad
| sort by FailedAttempts desc
```

<img width="1366" height="768" alt="Screenshot (625)" src="https://github.com/user-attachments/assets/ca58f54a-c8de-4546-8f45-85974b4496d2" />

<img width="1332" height="574" alt="Screenshot (626)" src="https://github.com/user-attachments/assets/cdf0cc55-ee03-4c4c-9c4f-1b54ffa61c5a" />



## Conclusion
This project added a second kind of detection alongside Lab 1's volume-based brute-force rule: intelligence-driven correlation against a known-malicious IP feed. The two approaches catch different things — one flags unusual behavior, the other flags known-bad identity regardless of behavior — and running both together is closer to how a real SOC layers its detections rather than relying on any single method.

Only 3 of 167 attackers appeared on the CINS Army feed, and the two highest-volume attackers were not on it. That gap is exactly what threat intelligence is for: it distinguishes confirmed malicious infrastructure from generic scanning noise, even when the noise is louder. A high attempt count alone doesn't make an attacker notable, and a single attempt from a known-bad IP does.

### Key takeaways from this project:

- Integrated a free threat intelligence feed into Microsoft Sentinel using KQL's externaldata operator
- Built a KQL correlation query joining real attacker data against external threat intelligence, rather than only my own logs
- Built an analytics rule with a different severity rationale than the earlier volume-based rule — reflecting that a confirmed threat-intel match is a higher-confidence signal than a raw attempt count
- Combined two independent enrichment sources (GeoIP and threat intelligence) into a single view of each attacker
