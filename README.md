# instance-vuln-scripts
**Powershell scripts to enable and disable known vulnerabilities in a Windows Domain Controller**

## vuln-script.ps1 usage
**WARNING - This script may cause unintended changes to the system**
```
vuln-script.ps1 <enable/disable> [<vulnerabilities>] (or "all")
```

* Use `-h` for the help menu (lists vulnerabilities)
* Use `all` to enable/disable all vulnerabilities
* Run without vulnerabilities to open the interactive shell