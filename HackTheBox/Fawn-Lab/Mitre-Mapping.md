# Lab: Fawn Machine
**Platform:** **HackTheBox**
> This file maps the commands used and actions performed during the Fawn machine exploitation to techniques in the MITRE ATT&CK framework.

This lab focuses on exploiting ftp service by leveraging anonymous login which enables an attacker to retrieve files in a server.

# MITRE ATT&CK Mapping

| Tactic         | Technique                      | Technique ID | Lab Activity                                |
| -------------- | ------------------------------ | ------------ | ------------------------------------------- |
| Reconnaissance | Active Scanning                | T1595        | Used Nmap to identify open ports            |
| Discovery      | Network Service Discovery      | T1046        | Identified FTP service running on port 21   |
| Initial Access | Valid Accounts                 | T1078        | Logged into FTP using the anonymous account |
| Collection     | Data from Network Shared Drive | T1039        | Retrieved the flag file from the FTP server |


---
# Mitre Att&ck Command Mapping

| MITRE Technique                        | Command Used          | Explanation                                                                                                                  |
| -------------------------------------- | --------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| Active Scanning (T1595)                | `nmap -v -sV -sC $IP` | Performed an active scan to identify open ports and running services on the target machine.                                  |
| Network Service Discovery (T1046)      | `nmap -v -sV -sC $IP` | Service enumeration revealed that port **21** was running an FTP service (`vsftpd`).                                         |
| Valid Accounts (T1078)                 | `ftp anonymous@$IP`   | The attacker logged into the FTP service using the **anonymous account**.           |
| Data from Network Shared Drive (T1039) | `get flag.txt`        | Downloaded a file from the FTP server, showing how attackers can retrieve sensitive data from shared network services. |

---

## Key Takeaways
* **FTP transmits credentials and files in plain text, making it vulnerable to interception.**
* **Allowing anonymous FTP access can expose sensitive files to attackers.**
* **Learn to directly interact with detected services.**

