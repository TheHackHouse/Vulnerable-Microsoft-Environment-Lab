# Vulnerable Microsoft Environment Lab

**Powershell scripts to enable and disable known vulnerabilities in a Windows Environment**

**WARNING - This script may cause dangerous changes to the system**

## Vulnerable-AD-plus-plus

The Vulnearble-AD-plus-plus script is a PowerShell script to deploy a variety of Active Directory misconfigurations and Windows service settings for lab testing of common privilege-escalation and relay attacks.

This is a fork of [Vulnerable-AD-plus](https://github.com/WaterExecution/vulnerable-AD-plus/tree/master)

It also includes `ADCSTemplate` from [GOAD](https://github.com/Orange-Cyberdefense/GOAD/tree/main)

And Includes `PSPKI` from [PKI Solutions (PSPKI)](https://github.com/PKISolutions/PSPKI/)

Note that the script requires the files in the 'deps' folder.

---
## Vulnerability Options
The following vulnerbilities can be configured: 
  1. [ACL Misconfigurations](#1-acl-misconfigurations)  
  2. [Kerberoasting Setup](#2-kerberoasting-setup)  
  3. [AS-REPRoasting Setup](#3-as-reproasting-setup)  
  4. [DNSAdmins Privilege Grant](#4-dnsadmins-privilege-grant)  
  5. [Default Password Accounts](#5-default-password-accounts)  
  6. [Password Spraying](#6-password-spraying)  
  7. [Bad ACLs (Advanced ACL Abuse)](#7-bad-acls-advanced-acl-abuse)  
  8. [SMB Signing Disabled](#8-smb-signing-disabled)  
  9. [Insecure WinRM Configuration](#9-insecure-winrm-configuration)  
  10. [Anonymous LDAP Reads](#10-anonymous-ldap-reads)  
  11. [Public SMB Share](#11-public-smb-share)  
  12. [Firewall Disabled](#12-firewall-disabled)  
  13. [NTLM Coercion Vulnerabilities](#13-ntlm-coercion-vulnerabilities)  
  14. [AD CS (ESC) Vulnerabilities](#14-ad-cs-esc-vulnerabilities)  
  15. [Add Users Only](#15-add-users-only)  

Note that option 13 will call the NTLM Coercersion Lab Setup script detailed below. 
It allows configuring the following NTLM Coercion Vulnearbilities:

* printerbug: RPC vulnerability using the Print Spooler service (MS-RPRN)
* petitpotam: RPC vulnerability using the SMB service (MS-EFSRPC)
* shadowcoerce: RPC vulnerability using the Microsoft File Server Remote VSS Protocol (MS-FSRVP)
* dfscoerce: RPC vulnerability using the Distributed File System service (MS-DFSNM)

---

## Prerequisites

- A Windows Server (2016+) joined as an Active Directory Domain Controller  
- **RSAT-AD-PowerShell** feature installed (script will install if missing)  
- **AD Certificate Services** role installed (for ESC tests; script installs if missing)  
- PowerShell execution policy unrestricted or RemoteSigned  

---

## Installation

1. Clone or copy the repository to your DC.  
2. Ensure the `.deps\` folder contains:  
   - `HumanNames.txt` (list of first names)  
   - `BadPasswords.txt` (list of known weak passwords)  
   - `ADCSTemplate` and `VulnerableTemplates\*.json` for AD CS tests  

## NTLM-Coercion-Lab-Setup

```
=== NTLM Coercion Lab Setup ===
Enables and Disables NTLM coercion related vulnerabilities
* Run without vulnerabilities to open the interactive shell

Usage: NTLM-Coercion-Lab-Setup.ps1 <FLAGS> <enable/disable> [<vulnerabilities>] (or "all")

Flags:
  -y  Confirm all prompts

Vulnerabilities:
  [0] printerbug: RPC vulnerability using the Print Spooler service (MS-RPRN)
  [1] petitpotam: RPC vulnerability using the SMB service (MS-EFSRPC)
  [2] shadowcoerce: RPC vulnerability using the Microsoft File Server Remote VSS Protocol (MS-FSRVP)
  [3] dfscoerce: RPC vulnerability using the Distributed File System service (MS-DFSNM)
```

* Use `-h` for the help menu (lists vulnerabilities)
* use `-y` to automatically confirm all prompts
* Use `all` to enable/disable all vulnerabilities
* Run without vulnerabilities to open the interactive shell

