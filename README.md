# Threat Hunting: Investigating Sudden Network Slowdown

## Introduction/Objectives
In this project, I conduct a threat-hunting exercise within a Microsoft Azure-hosted virtual machine using Microsoft Defender for Endpoint (MDE). The primary goal is to detect, investigate, and mitigate suspicious network activities related to devices exposed to the internet. This scenario involves analyzing potential adversarial behaviors, identifying indicators of compromise (IoCs), and leveraging Kusto Query Language (KQL) to perform in-depth analysis.

## Components, Tools, and Technologies Employed
- **Cloud Environment:** Microsoft Azure (VM-hosted threat-hunting lab)
- **Threat Detection Platform:** Microsoft Defender for Endpoint (MDE)
- **Query Language:** Kusto Query Language (KQL) for log analysis

## Disclaimer
I am operating in a shared learning environment hosted within the same Microsoft Azure subscription. As a result, certain private IP addresses associated with failed logon attempts may appear due to testing purposes. The threat actors examined in this project are external remote IP addresses originating from unauthorized and untrusted sources beyond the Azure environment.

## Scenario
A sudden network slowdown has been reported, raising concerns about possible malicious activity within the network. Upon investigating, a virtual machine labeled **windows-target-1** exhibits unusual connection failures and increased network requests, suggesting potential reconnaissance or unauthorized access attempts. Threat-hunting activities are conducted to analyze network events, detect anomalies, and determine the root cause of this network disruption.

## High-Level IoC Discovery Plan
1. **Network Behavior Analysis** – Monitor device network activities to detect abnormal connection patterns.
2. **Process Analysis** – Identify suspicious processes, scripts, or execution commands associated with detected anomalies.
3. **File System Inspection** – Investigate files created or modified during the suspicious activity period.
4. **Correlation with MITRE ATT&CK TTPs** – Map findings to known adversary tactics, techniques, and procedures.
5. **Incident Response Actions** – Isolate compromised systems, perform malware scans, and implement remediation steps.

## Steps Taken

### Step 1: Identifying Unusual Connection Failures
It was observed that **windows-target-1** was failing multiple connection requests against itself and another host on the same network:
#### **KQL Query Used:**
```kql
DeviceNetworkEvents
| where DeviceName == "windows-target-1"
| where ActionType == "ConnectionFailed"
| summarize FailedConnectionsAttempts = count() by DeviceName, ActionType, LocalIP, RemoteIP
| order by FailedConnectionsAttempts desc
```
![image](https://github.com/user-attachments/assets/88368802-f8d8-42ee-a8a9-430fd11c46b6)


### Step 2: Identifying Possible Port Scanning Activity
By including the **RemotePort** value and specifying the **LocalIP** of the suspect host (10.0.0.5), it was evident that multiple failed connection attempts were targeting different ports sequentially, indicating potential port scanning activity.
#### **KQL Query Used:**
```kql
let IPInQuestion = "10.0.0.5";
DeviceNetworkEvents
| where DeviceName == "windows-target-1"
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/3fb570dd-18cd-4fb6-a928-e8ea3517e22e)


### Step 3: Investigating the Use of PowerShell for Scanning
A deeper inspection into the **DeviceProcessEvents** table revealed that a PowerShell script named **portscan.ps1** was executed around the timeframe when the port scan occurred.
#### **KQL Query Used:**
```kql
let VMName = "windows-target-1";
let specificTime = datetime(2025-01-26T13:40:15.4179705Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| where InitiatingProcessCommandLine contains "scan"
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/24661795-2cd6-49f5-a49b-09ffa6e44e3e)


### Step 4: Inspecting the Suspect PowerShell Script
After logging into the suspect system, the **portscan.ps1** script was identified as the tool responsible for conducting the port scan.
![image](https://github.com/user-attachments/assets/574d76ec-1e70-492f-92c8-647d00af6102)


### Step 5: Determining Privilege Level of Execution
Observations revealed that the **portscan.ps1** script was executed by the **SYSTEM** account, an unexpected behavior since it was not configured by administrators. Consequently, the device was immediately isolated and subjected to a malware scan.
#### **KQL Query Used:**
```kql
let VMName = "windows-target-1";
let specificTime = datetime(2025-01-26T13:40:15.4179705Z)
DeviceProcessEvents
| where Timestamp between  ((specificTime - 10min) .. (specificTime + 10min))
| where DeviceName == VMName
| where InitiatingProcessCommandLine contains "scans"
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine, AccountName
```
![image](https://github.com/user-attachments/assets/a90f8cd3-1fac-4bef-9948-b4ea25adba0f)


### Step 6: Post-Scan Remediation Actions
The malware scan yielded no results. However, as a precautionary measure, the compromised device was isolated, and a support ticket was raised to reimage/rebuild the system.
![image](https://github.com/user-attachments/assets/df500129-72cb-4751-b51b-af84c2b25900)


### Step 7: Additional File System Investigation
A final query was executed to gather details related to the **portscan.ps1** script, including file location, initiating process, execution command line, and other attributes.
#### **KQL Query Used:**
```kql
DeviceFileEvents
| where DeviceName == "windows-target-1"
| where Timestamp >= ago(7d)
| where ActionType == "FileCreated"
| where FileName contains "portscan.ps1"
| summarize ScanCount = count() by FileName, InitiatingProcessFolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, RequestAccountDomain, RequestAccountName, Timestamp
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/11f38a28-4f1d-4447-b8ea-23db4c24c63f)


## TTPs from MITRE ATT&CK Framework
### **1. Initial Access**
- **T1190 - Exploit Public-Facing Application**

### **2. Discovery**
- **T1046 - Network Service Scanning**
- **T1016 - System Network Configuration Discovery**

### **3. Execution**
- **T1059.001 - Command and Scripting Interpreter: PowerShell**

### **4. Defense Evasion**
- **T1070.004 - Indicator Removal on Host: File Deletion**

### **5. Lateral Movement**
- **T1021.001 - Remote Services: SMB/Windows Admin Shares**

### **6. Impact**
- **T1499 - Endpoint Denial of Service**

### **7. Command and Control**
- **T1071.001 - Application Layer Protocol: Web Protocols**

## Conclusion
This project demonstrates a structured approach to threat hunting in a Microsoft Azure-hosted virtual machine using Microsoft Defender for Endpoint. By leveraging KQL queries and correlating findings with MITRE ATT&CK TTPs, the investigation successfully identified and mitigated suspicious activities indicative of adversarial reconnaissance and potential system compromise. Future enhancements include automating threat-hunting queries and improving response workflows to streamline incident handling processes.

