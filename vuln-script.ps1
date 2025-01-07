$vulnerabilities = @{
    'printerbug' = @{
        'description' = 'RPC vulnerability using the Print Spooler service (MS-RPRN)'
        'code'        = 0
        'enable'      = {
            Write-Host '  Enabling Print Spooler Service...'
            Start-Service -Name Spooler
        }
        'disable'     = {
            Write-Host '  Disabling Print Spooler Service...'
            Stop-Service -Name Spooler
        }
    }
    # Might require more than just this. (todo)
    'petitpotam' = @{
        'description' = 'RPC vulnerability using the SMB service (MS-EFSRPC)'
        'code'        = 1
        'enable'      = {
            Write-Host '  Enabling SMB Service...'
            Start-Service -Name LanmanServer
        }
        'disable'     = {
            Write-Host '  Disabling SMB Service...'
            Stop-Service -Name LanmanServer
        }
    }
    # todo - DFSCoerce, ShadowCoerce, CheeseOunce (others?)
}

$seenVulnerabilities = New-Object 'System.Collections.Generic.HashSet[string]'

function Show-HelpMenu {
    Write-Host '=== Vulnerability Enabler Script ==='
    Write-Host 'Enables and Disables vulnerabilities in a Windows Domain Controller'
    Write-Host '* Run without vulnerabilities to open the interactive shell'
    Write-Host ''
    Write-Host 'Usage: vuln-script.ps1 <enable/disable> [<vulnerabilities>] (or "all")'
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
        [string]$Action
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
            & $vulnerabilities[$vulnerabilityName][$action]
            Write-Host 'Done!' -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to $action $vulnerabilityName" -ForegroundColor Red
        }
    }
    else {
        Write-Host 'Skipping (not found): ' -ForegroundColor Red -NoNewline
        Write-Host "$($vulnerabilityName ? $vulnerabilityName : $vulnerabilityCode)"
    }
}

function Switch-All {
    foreach ($vulnerabilityName in $vulnerabilities.Keys) {
        Switch-Vulnerability -VulnerabilityName $vulnerabilityName -Action $actionState
    }
}

if ($args.Count -eq 0 -or $args.Contains('-h') -or $args.Contains('--help')) {
    Show-HelpMenu
    Show-VulnerabilityList
    exit 0
}

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
    Switch-All
    exit 0
}

for ($i = 1; $i -lt $args.Count; $i++) {
    if (($args[$i]) -is [System.Object[]]) {
        foreach ($item in $args[$i]) {
            Switch-Vulnerability -VulnerabilityName $item -Action $actionState
        }
    }
    else {
        Switch-Vulnerability -VulnerabilityName $args[$i] -Action $actionState
    }
}