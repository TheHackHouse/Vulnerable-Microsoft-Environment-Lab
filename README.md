# Vulnerable Microsoft Environment Lab
**Powershell scripts to enable and disable known vulnerabilities in a Windows Environment**

## NTLM-Coercion-Lab-Setup
**WARNING - This script may cause unintended changes to the system**
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