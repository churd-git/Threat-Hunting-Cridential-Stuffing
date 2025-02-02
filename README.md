# Threat Hunt Report (Credential Stuffing)
**Detection of Credential Stuffing & Data Exfiltration**

## Example Scenario:
---
Recent reports reveal a newly discovered Advanced Persistent Threat (APT) group known as "Jackal Spear," originating from South Africa and occasionally operating in Egypt. This group has been targeting large corporations using spear-phishing campaigns and credential stuffing attacks. By exploiting stolen credentials, they can gain access to systems with minimal login attempts. Their primary targets are executives. Once they successfully compromise an account, they establish persistence by creating a secondary account on the same system with a similar username. This new account is then used to exfiltrate sensitive data while avoiding detection. Management has tasked you with identifying Indicators of Compromise (IoCs) related to this South African/Egyptian APT within our systems. If you find any IoCs, conduct a thorough investigation to track the attacker’s movements and piece together their tactics, techniques, and procedures (TTPs).

---
## High-Level Cridential Stuffing related IoC Discovery Plan:
1. Check DeviceLogonEvents for any brute force IOC on machines from the region of South Africa or Egypt. 
2. Check DeviceEvents for any signs of a new user account being created.
3. Check DeviceProccessEvents for any signs suspcious actions or behaviour executed by the threat actor.
4. Check DeviceFileEvents for to confirm the succesful creation of the files. 

---

## Steps Taken

1. Searched the DeviceLogonEvents for any brute force IOCs. The search was narrowed to IP addresses only in the regions of South Africa and Egypt. The results showed 22 options. After deeper investigation "102.37.140.95" was found to be the IP of the malicious attacker because the patterns of the logs indicated that this IP was successful in a credential stuffing attempt. The attakc began at "2025-01-29T05:47:47.9786193Z", they succesffuly accessed the account at "2025-01-29T05:48:49.4362038Z".

Querys used to locate these events:
```kql
DeviceLogonEvents 
| where ActionType == "LogonFailed"
| summarize FailedLogonAttempts = count() by RemoteIP
| where FailedLogonAttempts < 30
| where RemoteIP startswith "41" or RemoteIP startswith "102" or RemoteIP startswith "105" or RemoteIP startswith "196" or RemoteIP startswith "197" or RemoteIP startswith "156"
```
<img width="1440" alt="Screenshot 2025-02-01 at 7 18 00 PM" src="https://github.com/user-attachments/assets/8b2f3904-d6a8-4779-b3d4-c47ab923c126" />

```kql
DeviceLogonEvents
| where RemoteIP == "102.37.140.95"
| where Timestamp >= datetime(2025-01-29T05:47:47.9786193Z)
```
<img width="1431" alt="Screenshot 2025-02-01 at 7 18 26 PM" src="https://github.com/user-attachments/assets/fbcac013-1157-4ea0-9b8e-c732017ec7d2" />
  
2. Searched the DeviceEvents logs for idication that a new user was created in order to find out if the APT had tried to establish persistence. At "2025-01-29T05:51:25.6071097Z", less than 5 minutes after the account was compromsied a new user named "chadwick.s" was created. This is consistent with the report that the APT group uses a similar account name when establishing persistence in a newly compromised environment by using a similar user name.

Querys used to locate these events:
```kql
DeviceEvents
| where DeviceName contains "corpnet-1-ny"
| where ActionType contains "UserAccountCreated"
```
<img width="1414" alt="Screenshot 2025-02-01 at 7 25 34 PM" src="https://github.com/user-attachments/assets/8477caec-f6f0-40c8-afd6-880560af0549" />

3. Check DeviceProccessEvents for any signs suspcious actions or behaviour executed by the threat actor. There were a few that showed the newly created account had downloaded, installed and executed 7z which is suspcious because file compression is often used to data exfiltration. The APT exectued the following command: "7z.exe"  a gene_editing_papers.zip "CRISPR-X__Next-Generation_Gene_Editing_for_Artificial_Evolution.pdf" "Genetic_Drift_in_Hyper-Evolving_Species__A_Case_Study.pdf" "Mutagenic_Pathways_and_Cellular_Adaptation.pdf" "Mutational_Therapy__Theoretical_Applications_in_Human_Enhancement.pdf" "Spontaneous_Mutations_in_Simul" at "2025-01-29T06:02:44.2185194Z". These are the files that were targeted by the malicous actors.

Querys used to locate these events:
```kql
DeviceProcessEvents
| where DeviceName == "corpnet-1-ny" 
| where AccountName == "chadwick.s"
| where ProcessVersionInfoProductName contains "7-Zip"
```
<img width="1425" alt="Screenshot 2025-02-01 at 7 32 04 PM" src="https://github.com/user-attachments/assets/744b401b-160c-4498-9bf2-c569ab066982" />

4. Searched DeviceFileEvents for to confirm the succesful creation of the compressed files called "gene_editing_papers.zip". The file was created at "2025-01-29T06:02:44.3408164Z", however it does not appear that the data was successfully exfiltrated.  

Querys used to locate these events:
```kql
DeviceFileEvents 
| where DeviceName == "corpnet-1-ny"
| where RequestAccountName == "chadwick.s"
| where InitiatingProcessAccountDomain == "corpnet-1-ny"
| where InitiatingProcessCommandLine contains "7z"
```
<img width="1420" alt="Screenshot 2025-02-01 at 7 36 00 PM" src="https://github.com/user-attachments/assets/fbd8805f-1e8a-462f-90db-ae4b8aeaf157" />

---

## Chronological Events

1. ...
2. ...
3. ...

---

## Summary

...

---

## Response Taken
TOR usage was confirmed on endpoint ______________. The device was isolated and the user's direct manager was notified.

---

## MDE Tables Referenced:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used for detecting TOR download and installation, as well as the shopping list creation and deletion. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect the silent installation of TOR as well as the TOR browser and service launching.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect TOR network activity, specifically tor.exe and firefox.exe making connections over ports to be used by TOR (9001, 9030, 9040, 9050, 9051, 9150).|

---

## Detection Queries:
```kql
// Installer name == tor-browser-windows-x86_64-portable-(version).exe
// Detect the installer being downloaded
DeviceFileEvents
| where FileName startswith "tor"

// TOR Browser being silently installed
// Take note of two spaces before the /S (I don't know why)
DeviceProcessEvents
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.1.exe  /S"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine

// TOR Browser or service was successfully installed and is present on the disk
DeviceFileEvents
| where FileName has_any ("tor.exe", "firefox.exe")
| project  Timestamp, DeviceName, RequestAccountName, ActionType, InitiatingProcessCommandLine

// TOR Browser or service was launched
DeviceProcessEvents
| where ProcessCommandLine has_any("tor.exe","firefox.exe")
| project  Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine

// TOR Browser or service is being used and is actively creating network connections
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc

// User shopping list was created and, changed, or deleted
DeviceFileEvents
| where FileName contains "shopping-list.txt"
```

---

## Created By:
- **Author Name**: Josh Madakor
- **Author Contact**: https://www.linkedin.com/in/joshmadakor/
- **Date**: August 31, 2024

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `September  6, 2024`  | `Josh Madakor`   
