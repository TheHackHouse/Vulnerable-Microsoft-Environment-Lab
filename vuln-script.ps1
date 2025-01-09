function Read-Boolean {
    param(
        [string]$Prompt
    )

    while ($true) {
        $answer = Read-Host -Prompt "$prompt (y/N)"
        if ($answer -ieq 'y' -or $answer -ieq 'yes') {
            return $true
        }
        elseif ($answer -ieq 'n' -or $answer -ieq 'no') {
            return $false
        }
        elseif ($answer -eq '') {
            return $false
        }
        else {
            Write-Host 'Input must either be empty or (y/yes) or (n/no)' -ForegroundColor Red
        }
    }
}

function Get-ServiceStatus {
    param (
        [string]$Name,
        [string]$ExpectedState,
        [string]$ReadableName = $null
    )

    if (-not $ReadableName) {
        $ReadableName = $Name
    }
    
    $isExpectedState = (Get-Service -Name $name).Status -eq $expectedState
    if ($isExpectedState) {
        Write-Host "  $ReadableName Service is $($ExpectedState.ToLower()), skipping..." -ForegroundColor Red
    }

    return $isExpectedState
}

function Set-ServiceStatus {
    param (
        [string]$Name,
        [switch]$On,
        [switch]$Off,
        [bool]$DefaultYes,
        [string]$ReadableName = $null
    )

    if (-not $ReadableName) {
        $ReadableName = $Name
    }

    if (-not $on -and -not $off) {
        throw 'Must provide On/Off option'
    }

    if ($on) {
        if (Get-ServiceStatus -Name $name -ExpectedState 'Running' -ReadableName $ReadableName) { return }
        if ($defaultYes -or (Read-Boolean -Prompt "  Enable $readableName service?")) {
            Write-Host "  Enabling $readableName service..."
            Start-Service -Name $name
            Write-Host "  Enabling $readableName on startup..."
            Set-Service -Name $name -StartupType Automatic
            return $true
        }
        else {
            Write-Host "  Skipping enabling of $readableName Service (You may not be vulnerable)" -ForegroundColor Red
        }
    }
    else {
        if (Get-ServiceStatus -Name $name -ExpectedState 'Stopped' -ReadableName $ReadableName) { return }
        if ($defaultYes -or (Read-Boolean -Prompt "  Disable $readableName service?")) {
            Write-Host "  Disabling $readableName service..."
            Stop-Service -Name $name
            Write-Host "  Disabling $readableName on startup..."
            Set-Service -Name $name -StartupType Disabled
            return $true
        }
        else {
            Write-Host "  Skipping disabling of $readableName Service (You may still be vulnerable)" -ForegroundColor Red
        }
    }

    return $false
}

$vulnerabilities = @{
    'printerbug'   = @{
        'description' = 'RPC vulnerability using the Print Spooler service (MS-RPRN)'
        'code'        = 0
        'enable'      = {
            param ([bool]$DefaultYes)
            Set-ServiceStatus -On -Name 'Spooler' -ReadableName 'Print Spooler' -DefaultYes $DefaultYes | Out-Null
        }
        'disable'     = {
            param ([bool]$DefaultYes)
            Set-ServiceStatus -Off -Name 'Spooler' -ReadableName 'Print Spooler' -DefaultYes $DefaultYes | Out-Null
        }
    }
    'petitpotam'   = @{
        'description' = 'RPC vulnerability using the SMB service (MS-EFSRPC)'
        'code'        = 1
        'enable'      = {
            param ([bool]$DefaultYes)
            Set-ServiceStatus -On -Name 'LanmanServer' -ReadableName 'SMB' -DefaultYes $DefaultYes | Out-Null
        }
        'disable'     = {
            param ([bool]$DefaultYes)
            if (-not (Set-ServiceStatus -Off -Name 'LanmanServer' -ReadableName 'SMB' -DefaultYes $DefaultYes)) {
                Write-Host '  See external resources: ' -ForegroundColor Red -NoNewline
                Write-Host 'https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429'
            }
        }
    }
    'shadowcoerce' = @{
        'description' = 'RPC vulnerability using the Microsoft File Server Remote VSS Protocol (MS-FSRVP)'
        'code'        = 2
        'enable'      = {
            param ([bool]$DefaultYes)
            Set-ServiceStatus -On -Name 'VSS' -ReadableName 'Volume Shadow Copy' -DefaultYes $DefaultYes | Out-Null
        }
        'disable'     = {
            param ([bool]$DefaultYes)
            if (-not (Set-ServiceStatus -On -Name 'VSS' -ReadableName 'Volume Shadow Copy' -DefaultYes $DefaultYes)) {
                Write-Host '  See external resources: ' -ForegroundColor Red -NoNewline
                Write-Host 'https://support.microsoft.com/en-us/topic/kb5015527-shadow-copy-operations-using-vss-on-remote-smb-shares-denied-access-after-installing-windows-update-dated-june-14-2022-6d460245-08b6-40f4-9ded-dd030b27850b'
            }
        }
    }
    'dfscoerce'    = @{
        'description' = 'RPC vulnerability using the Distributed File System service (MS-DFSNM)'
        'code'        = 3
        'enable'      = {
            param ([bool]$DefaultYes)
            Set-ServiceStatus -On -Name 'DFS' -ReadableName 'Distributed File System' -DefaultYes $DefaultYes | Out-Null
        }
        'disable'     = {
            param ([bool]$DefaultYes)
            Set-ServiceStatus -Off -Name 'DFS' -ReadableName 'Distributed File System' -DefaultYes $DefaultYes | Out-Null
        }
    }
    # 'cheeseounce'  = @{
    #     'description' = ''
    #     'code'        = 4
    #     'enable'      = {
    #         param ([bool]$DefaultYes)
    #     }
    #     'disable'     = {
    #         param ([bool]$DefaultYes)
    #     }
    # }
}

$seenVulnerabilities = New-Object 'System.Collections.Generic.HashSet[string]'

function Show-HelpMenu {
    Write-Host '=== Vulnerability Enabler Script ==='
    Write-Host 'Enables and Disables vulnerabilities in a Windows Domain Controller'
    Write-Host '* Run without vulnerabilities to open the interactive shell'
    Write-Host ''
    Write-Host 'Usage: vuln-script.ps1 <FLAGS> <enable/disable> [<vulnerabilities>] (or "all")'
    Write-Host ''
    Write-Host 'Flags:'
    Write-Host '  -y  Confirm all prompts'
}

function Show-VulnerabilityList {
    Write-Host ''
    Write-Host 'Vulnerabilities:'
    $sortedVulnerabilities = $vulnerabilities.GetEnumerator() | Sort-Object { $_.Value.code }
    foreach ($vulnerability in $sortedVulnerabilities) {
        $key = $vulnerability.Key
        $value = $vulnerability.Value
        $description = $value['description']
        $code = $value['code']

        Write-Host '  [' -NoNewline
        Write-Host "$code" -ForegroundColor DarkGray -NoNewline
        Write-Host '] ' -NoNewline
        Write-Host "$key" -ForegroundColor Green -NoNewline
        Write-Host ": $description"
    }
    Write-Host ''
}

function Start-InteractiveShell {
    param (
        [string]$Action
    )

    $titleColor = $null

    if ($action -eq 'enable') {
        $titleColor = 'Blue'
    }
    elseif ($action -eq 'disable') {
        $titleColor = 'Yellow'
    }

    Write-Host "Running in $Action mode" -ForegroundColor $titleColor

    Show-VulnerabilityList

    while ($true) {
        $userInput = Read-Host 'Enter the name/index of the vulnerability or "all"/"list"/"exit"'
        if ($userInput -ieq 'exit') {
            Write-Host 'Exiting...'
            exit 0
        }
    
        if ($userInput -ieq 'list') {
            Show-VulnerabilityList
            continue
        }
    
        if ($userInput -ieq 'all') {
            Switch-All
            continue
        }
    
        $vulnerabilityNames = $userInput -split ','
        foreach ($vulnerabilityName in $vulnerabilityNames) {
            Switch-Vulnerability -VulnerabilityName $vulnerabilityName -Action $action
        }
    }
}

function Switch-Vulnerability {
    param (
        [Object]$VulnerabilityName,
        [string]$Action,
        [bool]$DefaultYes
    )

    $vulnerabilityCode = $null
    if ($vulnerabilityName -is [int] -or [int]::TryParse($vulnerabilityName, [ref]$vulnerabilityCode)) {
        $vulnerabilityCode = $vulnerabilityName
        $vulnerabilityName = $vulnerabilities.GetEnumerator() | Where-Object { $_.Value.code -eq $vulnerabilityCode } | Select-Object -First 1 | ForEach-Object { $_.Key }
    }
    elseif (-not ($vulnerabilityName -is [string])) {
        throw 'Vulnerability provided must be either an integer code or a string name'
    }

    if ($null -ne $vulnerabilityName -and $vulnerabilities.ContainsKey($VulnerabilityName)) {
        if ($seenVulnerabilities.Contains($VulnerabilityName)) {
            Write-Host 'Skipping (duplicate): ' -ForegroundColor Red -NoNewline
            Write-Host "$VulnerabilityName"
            return
        }

        $seenVulnerabilities.Add($VulnerabilityName) | Out-Null

        if ($action -eq 'enable') {
            Write-Host 'Enabling: ' -ForegroundColor Blue -NoNewline
        }
        elseif ($action -eq 'disable') {
            Write-Host 'Disabling: ' -ForegroundColor Yellow -NoNewline
        }
    
        Write-Host "$vulnerabilityName"

        try {
            & $vulnerabilities[$vulnerabilityName][$action] -DefaultYes $DefaultYes
            Write-Host 'Done!' -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to $action $vulnerabilityName" -ForegroundColor Red
        }
    }
    else {
        Write-Host 'Skipping (not found): ' -ForegroundColor Red -NoNewline
        if ($null -ne $VulnerabilityName) {
            Write-Host "$vulnerabilityName"
        }
        else {
            Write-Host "$vulnerabilityCode"
        }
    }
}

function Switch-All {
    param (
        [bool]$DefaultYes
    )

    foreach ($vulnerabilityName in $vulnerabilities.Keys) {
        Switch-Vulnerability -VulnerabilityName $vulnerabilityName -Action $actionState -DefaultYes $defaultYes
    }
}

if ($args.Count -eq 0 -or $args.Contains('-h') -or $args.Contains('--help')) {
    Show-HelpMenu
    Show-VulnerabilityList
    exit 0
}

$defaultYes = $args.Contains('-y')
$actionState = $null

if ($args[0]) {
    if ($args[0] -ieq 'enable') {
        $actionState = 'enable'
    }
    elseif ($args[0] -ieq 'disable') {
        $actionState = 'disable'
    }
}

if ($null -eq $actionState) {
    throw 'Must provide valid action (enable/disable)'
}

if ($args.Count -eq 1) {
    Start-InteractiveShell -Action $actionState
}

if (($args | ForEach-Object { if ($_ -is [string]) { $_.ToLower() } }) -contains 'all') {
    Switch-All -DefaultYes $defaultYes
    exit 0
}

for ($i = 1; $i -lt $args.Count; $i++) {
    if (($args[$i]) -is [System.Object[]]) {
        foreach ($item in $args[$i]) {
            if ($item -notlike '-*') {
                Switch-Vulnerability -VulnerabilityName $item -Action $actionState -DefaultYes $defaultYes
            }
        }
    }
    else {
        if ($args[$i] -notlike '-*') {
            Switch-Vulnerability -VulnerabilityName $args[$i] -Action $actionState -DefaultYes $defaultYes
        }
    }
}