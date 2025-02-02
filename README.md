![image](https://github.com/user-attachments/assets/961992c9-0651-4573-be17-5133c312f44f)

# Threat Hunt Report (Credential Stuffing)
**Detection of Credential Stuffing & Data Exfiltration**

## Example Scenario:
---
Recent reports reveal a newly discovered Advanced Persistent Threat (APT) group known as "Jackal Spear," originating from South Africa and occasionally operating in Egypt. This group has been targeting large corporations using spear-phishing campaigns and credential stuffing attacks. By exploiting stolen credentials, they can gain access to systems with minimal login attempts. Their primary targets are executives. Once they successfully compromise an account, they establish persistence by creating a secondary account on the same system with a similar username. This new account is then used to exfiltrate sensitive data while avoiding detection. Management has tasked you with identifying Indicators of Compromise (IoCs) related to this South African/Egyptian APT within our systems. If you find any IoCs, conduct a thorough investigation to track the attacker’s movements and piece together their tactics, techniques, and procedures (TTPs).

---
## High-Level Cridential Stuffing related IoC Discovery Plan:
1. Check DeviceLogonEvents for any brute force IOC on machines from the region of South Africa or Egypt. 
2. Check DeviceEvents for any signs of a new user account being created.
3. Check DeviceProccessEvents for any signs suspicious actions or behaviour executed by the threat actor.
4. Check DeviceFileEvents for to confirm the succesful creation of the files. 

---

## Steps Taken

1. Searched the DeviceLogonEvents for any brute force IOCs. The search was narrowed to IP addresses only in the regions of South Africa and Egypt. The results showed 22 options. After deeper investigation "102.37.140.95" was found to be the IP of the malicious attacker because the patterns of the logs indicated that this IP was successful in a credential stuffing attempt. The attack began at "2025-01-29T05:47:47.9786193Z", they successfully accessed the account at "2025-01-29T05:48:49.4362038Z".

Queries used to locate these events:
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
  
2. Searched the DeviceEvents logs for indication that a new user was created in order to find out if the APT had tried to establish persistence. At "2025-01-29T05:51:25.6071097Z", less than 5 minutes after the account was compromised a new user named "chadwick.s" was created. This is consistent with the report that the APT group uses a similar account name when establishing persistence in a newly compromised environment by using a similar user name.

Query used to locate these events:
```kql
DeviceEvents
| where DeviceName contains "corpnet-1-ny"
| where ActionType contains "UserAccountCreated"
```
<img width="1414" alt="Screenshot 2025-02-01 at 7 25 34 PM" src="https://github.com/user-attachments/assets/8477caec-f6f0-40c8-afd6-880560af0549" />

3. Check DeviceProccessEvents for any signs suspicious actions or behaviour executed by the threat actor. There were a few that showed the newly created account had downloaded, installed and executed 7z which is suspicious because file compression is often used to data exfiltration. The APT executed the following command: "7z.exe"  a gene_editing_papers.zip "CRISPR-X__Next-Generation_Gene_Editing_for_Artificial_Evolution.pdf" "Genetic_Drift_in_Hyper-Evolving_Species__A_Case_Study.pdf" "Mutagenic_Pathways_and_Cellular_Adaptation.pdf" "Mutational_Therapy__Theoretical_Applications_in_Human_Enhancement.pdf" "Spontaneous_Mutations_in_Simul" at "2025-01-29T06:02:44.2185194Z". These are the files that were targeted by the malicous actors.

Query used to locate these events:
```kql
DeviceProcessEvents
| where DeviceName == "corpnet-1-ny" 
| where AccountName == "chadwick.s"
| where ProcessVersionInfoProductName contains "7-Zip"
```
<img width="1425" alt="Screenshot 2025-02-01 at 7 32 04 PM" src="https://github.com/user-attachments/assets/744b401b-160c-4498-9bf2-c569ab066982" />

4. Searched DeviceFileEvents for to confirm the successful creation of the compressed files called "gene_editing_papers.zip". The file was created at "2025-01-29T06:02:44.3408164Z", however it does not appear that the data was successfully exfiltrated.  

Query used to locate these events:
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

Here is the revised **timeline report** formatted according to your preference:

---

# **Credential Stuffing Attack - Timeline Report**  
**APT Group:** Jackal Spear  
**Incident Date:** January 29, 2025  
**Affected System:** `corpnet-1-ny`  

---

1. ### **Initial Credential Stuffing Attempts**  
   **Timestamp:** 2025-01-29 05:47:47Z  
   **Event:** Multiple failed login attempts were detected from IP `102.37.140.95`, originating from South Africa.  
   **Source:** `DeviceLogonEvents` logs.  
   **Query:**  
   ```kql
   DeviceLogonEvents 
   | where ActionType == "LogonFailed"
   | summarize FailedLogonAttempts = count() by RemoteIP
   | where FailedLogonAttempts < 30
   | where RemoteIP startswith "41" or RemoteIP startswith "102" or RemoteIP startswith "105" or RemoteIP startswith "196" or RemoteIP startswith "197" or RemoteIP startswith "156"
   ```

2. ### **Successful Credential Compromise**  
   **Timestamp:** 2025-01-29 05:48:49Z  
   **Event:** A successful login attempt was recorded from the attacker’s IP `102.37.140.95`.  
   **Source:** `DeviceLogonEvents` logs.  
   **Query:**  
   ```kql
   DeviceLogonEvents
   | where RemoteIP == "102.37.140.95"
   | where Timestamp >= datetime(2025-01-29T05:47:47.9786193Z)
   ```

3. ### **Persistence Established via New User Account**  
   **Timestamp:** 2025-01-29 05:51:25Z  
   **Event:** A new user account **"chadwick.s"** was created, consistent with the APT’s persistence tactics.  
   **Source:** `DeviceEvents` logs.  
   **Query:**  
   ```kql
   DeviceEvents
   | where DeviceName contains "corpnet-1-ny"
   | where ActionType contains "UserAccountCreated"
   ```

4. ### **Execution of File Compression Utility**  
   **Timestamp:** 2025-01-29 06:02:44Z  
   **Event:** The attacker downloaded, installed, and executed **7-Zip**, a known tool for data compression.  
   **Source:** `DeviceProcessEvents` logs.  
   **Query:**  
   ```kql
   DeviceProcessEvents
   | where DeviceName == "corpnet-1-ny" 
   | where AccountName == "chadwick.s"
   | where ProcessVersionInfoProductName contains "7-Zip"
   ```

5. ### **Data Targeted for Exfiltration**  
   **Timestamp:** 2025-01-29 06:02:44Z  
   **Event:** The attacker compressed multiple research files into `gene_editing_papers.zip`.  
   **Command Executed:**  
   ```plaintext
   "7z.exe" a gene_editing_papers.zip "CRISPR-X__Next-Generation_Gene_Editing_for_Artificial_Evolution.pdf" 
   "Genetic_Drift_in_Hyper-Evolving_Species__A_Case_Study.pdf" 
   "Mutagenic_Pathways_and_Cellular_Adaptation.pdf" 
   "Mutational_Therapy__Theoretical_Applications_in_Human_Enhancement.pdf" 
   "Spontaneous_Mutations_in_Simul"
   ```
   **Source:** `DeviceProcessEvents` logs.  

6. **File Creation & Exfiltration Attempt**  
   **Timestamp:** 2025-01-29 06:02:44Z  
   **Event:** The zip file `gene_editing_papers.zip` was successfully created in the system.  
   **File Path:** `C:\Users\chadwicks\Documents\CRISPR Research\gene_editing_papers.zip`  
   **Source:** `DeviceFileEvents` logs.  
   **Query:**  
   ```kql
   DeviceFileEvents 
   | where DeviceName == "corpnet-1-ny"
   | where RequestAccountName == "chadwick.s"
   | where InitiatingProcessAccountDomain == "corpnet-1-ny"
   | where InitiatingProcessCommandLine contains "7z"
   ```
   **Exfiltration Status:** No evidence found indicating the file was successfully exfiltrated.  

---

## Summary 

On **January 29, 2025**, an Advanced Persistent Threat (APT) group known as **Jackal Spear** executed a **credential stuffing attack** against the corporate system **corpnet-1-ny**. The attack originated from **IP address 102.37.140.95**, located in **South Africa**, and involved multiple failed login attempts before successfully compromising an account at **05:48:49 UTC**. Within three minutes of gaining access, the attacker created a new user account, **"chadwick.s"**, as a persistence mechanism, mirroring a known tactic of this APT group. Shortly after, the threat actor downloaded and executed **7-Zip**, a tool commonly used for **data compression and exfiltration**. At **06:02:44 UTC**, the attacker used 7-Zip to compress multiple sensitive **gene-editing research files** into a zip archive named **"gene_editing_papers.zip"**, located in the **CRISPR Research directory** on the compromised system. While the files were successfully compressed, there is no clear evidence from the logs that the data was fully exfiltrated. The attack followed a structured sequence—initial access via credential stuffing, persistence via a secondary account, and attempted data exfiltration via file compression—indicating a well-planned intrusion. This incident underscores the importance of **multi-factor authentication (MFA), proactive monitoring for unauthorized account creation, and strict access controls on sensitive research files** to mitigate similar threats in the future.

---

## Response Taken
Credential stuffing attack was confirmed on endpoint corpnet-1-ny. The device was isolated, the machine was reset to a state before it was compromised, and the user's cridentials were reset. 

---

## MDE Tables Referenced:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceLogonEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table|
| **Purpose**| Used for detecting credential stuffing IOCs and identifying malicious IPs.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table|
| **Purpose**| Used to detect if a new account was created to establish persistence.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProccessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to identify any signs suspcious actions or behaviours executed by the threat actor.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**|  DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to confirm the succesful creation of the files compressed files.|

---

## Detection Queries:
```kql
DeviceLogonEvents 
| where ActionType == "LogonFailed"
| summarize FailedLogonAttempts = count() by RemoteIP
| where FailedLogonAttempts < 30
| where RemoteIP startswith "41" or RemoteIP startswith "102" or RemoteIP startswith "105" or RemoteIP startswith "196" or RemoteIP startswith "197" or RemoteIP startswith "156"

DeviceLogonEvents
| where RemoteIP == "102.37.140.95"
| where Timestamp >= datetime(2025-01-29T05:47:47.9786193Z)

DeviceEvents
| where DeviceName contains "corpnet-1-ny"
| where ActionType contains "UserAccountCreated"

DeviceProcessEvents
| where DeviceName == "corpnet-1-ny" 
| where AccountName == "chadwick.s"
| where ProcessVersionInfoProductName contains "7-Zip"

DeviceFileEvents 
| where DeviceName == "corpnet-1-ny"
| where RequestAccountName == "chadwick.s"
| where InitiatingProcessAccountDomain == "corpnet-1-ny"
| where InitiatingProcessCommandLine contains "7z"
```

---

## Created By:
- **Author Name**: Carlton Hurd
- **Author Contact**: https://www.linkedin.com/in/carlton-hurd-6069a5120/
- **Date**: Feb 1st, 2025

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
| 1.0         | Initial draft                  | `February 1st, 2025`  | `Carlton Hurd`   
