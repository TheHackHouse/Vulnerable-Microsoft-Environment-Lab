# Base Lists 
$Global:HumansNames = Get-Content -Path ".\deps\HumanNames.txt"
$Global:BadPasswords = Get-Content -Path ".\deps\BadPasswords.txt"
$Global:ACLperm = @('GenericAll', 'GenericWrite', 'WriteOwner', 'WriteDACL', 'Self')
$Global:ServicesAccountsAndSPNs = @('mssql_svc,mssqlserver', 'http_svc,httpserver', 'exchange_svc,exserver')
$Global:Groups = @('Office Admin', 'IT Admins', 'Executives', 'Senior management', 'Project management', 'IT Helpdesk', 'Marketing', 'Sales', 'Accounting')
$Global:HighGroups = @('Office Admin', 'IT Admins', 'Executives')
$Global:MidGroups = @('Senior management', 'Project management', 'IT Helpdesk')
$Global:NormalGroups = @('Marketing', 'Sales', 'Accounting')
$Global:OfficeAdmin = @()
$Global:ITAdmins = @()
$Global:Executives = @()
$Global:ITHelpdesk = @()
$Global:Marketing = @()
$Global:Sales = @()
$Global:Accounting = @()
$Global:Seniormanagement = @()  # corresponds to "Senior management"
$Global:Projectmanagement = @()  # corresponds to "Project management"
$Global:InitialAccessUsers = @()
$Global:CreatedUsers = @()
$Global:RemainingUsers = @()
$Global:AllObjects = @()
$Global:ACLUser = ""
$Global:Domain = ""

# Strings 
$Global:Spacing = " "
$Global:PlusLine = "[+]"
$Global:ErrorLine = "[-]"
$Global:InfoLine = "[*]"

$Global:Characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'.ToCharArray()

function Write-Good { param($String) Write-Host $Global:PlusLine $String -ForegroundColor 'Green' }
function Write-Bad { param($String) Write-Host $Global:ErrorLine $String -ForegroundColor 'Red' }
function Write-Info { param($String) Write-Host $Global:InfoLine $String -ForegroundColor 'Gray'; echo $String >> generate.log }

function ShowBanner {
    $banner = @()
    $banner += $Global:Spacing + ''
    $banner += $Global:Spacing + 'By wazehell @safe_buffer - Modified by WaterExecution - Modified by p0rtL'
    $banner += $Global:Spacing + ''
    $banner | ForEach-Object {
        Write-Host $_ -ForegroundColor (Get-Random -InputObject @('Green', 'Cyan', 'Yellow', 'Gray', 'White'))
    }
}

function VulnAD-GetRandom {
    Param(
        [array]$InputList
    )
    return Get-Random -InputObject $InputList
}

function Prompt-ForInput {
    param (
        [string]$PromptText,
        [string]$DefaultValue = ""
    )
    $input = Read-Host $PromptText
    if ([string]::IsNullOrWhiteSpace($input) -and $DefaultValue) {
        return $DefaultValue
    }
    return $input
}

function VulnAD-AddADUser {
    Param(
        [int]$limit = 1
    )
    Add-Type -AssemblyName System.Web
    for ($i = 1; $i -le $limit; $i++) {
        $firstname = (VulnAD-GetRandom -InputList $Global:HumansNames)
        $lastname = (VulnAD-GetRandom -InputList $Global:HumansNames)
        $fullname = "{0} {1}" -f ($firstname , $lastname)
        $SamAccountName = ("{0}.{1}" -f ($firstname, $lastname)).ToLower()
        $principalname = "{0}.{1}" -f ($firstname, $lastname)
        $generated_pw = ([System.Web.Security.Membership]::GeneratePassword(7, 2))
        Write-Info "Creating $SamAccountName User"
        Try {
            New-ADUser -Name "$firstname $lastname" `
                -GivenName $firstname -Surname $lastname `
                -SamAccountName $SamAccountName `
                -UserPrincipalName $principalname@$Global:Domain `
                -AccountPassword (ConvertTo-SecureString $generated_pw -AsPlainText -Force) `
                -PassThru | Enable-ADAccount
        }
        Catch {}
        $Global:CreatedUsers += $SamAccountName
        $Global:RemainingUsers += $SamAccountName
    }
}

function VulnAD-AddADGroup {
    Param(
        [array]$GroupList
    )
    $noOfGroup = [Math]::Floor($Global:CreatedUsers.length / 30)
    $Users = $Global:CreatedUsers.length - (30 * $noOfGroup)
    
    foreach ($group in $GroupList) {
        Write-Info "Creating $group Group"
        Try { New-ADGroup -Name $group -GroupScope Global } Catch {}

        if ($Global:HighGroups -contains $group) {
            $noOfUsers = $noOfGroup * 2
        }
        elseif ($Global:MidGroups -contains $group) {
            if ($Users -ge 15) {
                $noOfUsers = [Math]::Floor(
                  ($Global:CreatedUsers.length - (($noOfGroup + 1) * 15) - ($noOfGroup * 6)) / 3
                )
            }
            else {
                $noOfUsers = $noOfGroup * 3
            }
        }
        elseif ($Global:NormalGroups -contains $group) {
            if ($Users -lt 30 -and $Users -gt 15) {
                $noOfUsers = [Math]::Floor( ($noOfGroup + 1) * 15 / 3 )
            }
            elseif ($Users -le 15 -and $Users -ne 0) {
                $noOfUsers = [Math]::Floor( ($noOfGroup * 15 + $Users) / 3 )
            }
            else {
                $noOfUsers = $noOfGroup * 5
            }
        }
        else {
            $noOfUsers = 0
        }

        # Cap membership to what's left
        $noOfUsers = [Math]::Min($noOfUsers, $Global:RemainingUsers.Count)

        for ($i = 1; $i -le $noOfUsers; $i++) {
            if ($Global:RemainingUsers.Count -eq 0) { break }

            $randomuser = (VulnAD-GetRandom -InputList $Global:RemainingUsers)
            Write-Info "Adding $randomuser to $group"
            Try { Add-ADGroupMember -Identity $group -Members $randomuser } Catch {}
            
            switch ($group) {
                "Office Admin" { $Global:OfficeAdmin += $randomuser }
                "IT Admins" { $Global:ITAdmins += $randomuser }
                "Executives" { $Global:Executives += $randomuser }
                "Senior management" { $Global:Seniormanagement += $randomuser }
                "Project management" { $Global:Projectmanagement += $randomuser }
                "IT Helpdesk" { $Global:ITHelpdesk += $randomuser }
                "Marketing" { $Global:Marketing += $randomuser }
                "Sales" { $Global:Sales += $randomuser }
                "Accounting" { $Global:Accounting += $randomuser }
            }
            $Global:RemainingUsers = $Global:RemainingUsers -ne $randomuser
        }

        $Global:AllObjects += $group
    }

    # Attempt to nest "IT Admins" inside "Domain Admins"
    Try {
        Add-ADGroupMember -Identity "Domain Admins" -Members "IT Admins"
    }
    Catch {}
}

function VulnAD-AddACL {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Destination,

        [Parameter(Mandatory = $true)]
        [System.Security.Principal.IdentityReference]$Source,

        [Parameter(Mandatory = $true)]
        [string]$Rights
    )
    $ADObject = [ADSI]("LDAP://" + $Destination)
    $identity = $Source
    $adRights = [System.DirectoryServices.ActiveDirectoryRights]$Rights
    $type = [System.Security.AccessControl.AccessControlType] "Allow"
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity, $adRights, $type, $inheritanceType
    $ADObject.psbase.ObjectSecurity.AddAccessRule($ACE)
    $ADObject.psbase.commitchanges()
}

function VulnAD-Acls {
    foreach ($abuse in $Global:ACLperm) {
        $ngroup = VulnAD-GetRandom -InputList $Global:MidGroups
        $mgroup = VulnAD-GetRandom -InputList $Global:NormalGroups
        $SrcGroup = Get-ADGroup -Identity $mgroup
        $DstGroup = Get-ADGroup -Identity $ngroup
        VulnAD-AddACL -Source $SrcGroup.sid -Destination $DstGroup.DistinguishedName -Rights $abuse
        Write-Info "ACL $mgroup has $abuse permission for $ngroup"
    }
    foreach ($abuse in $Global:ACLperm) {
        $hgroup = VulnAD-GetRandom -InputList $Global:HighGroups
        $mgroup = VulnAD-GetRandom -InputList $Global:MidGroups
        $SrcGroup = Get-ADGroup -Identity $hgroup
        $DstGroup = Get-ADGroup -Identity $mgroup
        VulnAD-AddACL -Source $SrcGroup.sid -Destination $DstGroup.DistinguishedName -Rights $abuse
        Write-Info "ACL $hgroup has $abuse permission for $mgroup"
    }
    foreach ($abuse in $Global:ACLperm) {
        $hgroup = VulnAD-GetRandom -InputList $Global:HighGroups
        $ngroup = VulnAD-GetRandom -InputList $Global:NormalGroups
        $SrcGroup = Get-ADGroup -Identity $hgroup
        $DstGroup = Get-ADGroup -Identity $ngroup
        VulnAD-AddACL -Source $SrcGroup.sid -Destination $DstGroup.DistinguishedName -Rights $abuse
        Write-Info "ACL $hgroup has $abuse permission for $ngroup"
    }
}

function VulnAD-Kerberoasting {
    foreach ($sv in $Global:ServicesAccountsAndSPNs) {
        $svc = $sv.split(',')[0]
        $spn = $sv.split(',')[1]
        if ((Get-Random -Maximum 2)) {
            $password = VulnAD-GetRandom -InputList $Global:BadPasswords
        }
        else {
            $password = ([System.Web.Security.Membership]::GeneratePassword(7, 2))
        }
        Try {
            New-ADUser -Name $svc -SamAccountName $svc -ServicePrincipalNames "$svc/$spn.$Global:Domain" `
                -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru |
            Enable-ADAccount
        }
        Catch {}
        $randomgroup = (VulnAD-GetRandom -InputList $Global:MidGroups)
        Add-ADGroupMember -Identity $randomgroup -Members $svc
        Write-Info "Creating $svc services account"
        Write-Info "$svc in $randomgroup"
    }
}

function VulnAD-ASREPRoasting {
    for ($i = 1; $i -le (Get-Random -Minimum 1 -Maximum 6); $i++) {
        $randomuser = (VulnAD-GetRandom -InputList (Get-Random -InputObject @($Global:Marketing, $Global:Sales, $Global:Accounting)))
        $password = VulnAD-GetRandom -InputList $Global:BadPasswords
        Set-ADAccountPassword -Identity $randomuser -Reset -NewPassword (ConvertTo-SecureString $password -AsPlainText -Force)
        Set-ADAccountControl -Identity $randomuser -DoesNotRequirePreAuth 1
        Write-Info "AS-REPRoasting $randomuser"
        $Global:InitialAccessUsers += $randomuser
    }
}

function VulnAD-DnsAdmins {
    Set-ADGroup -Identity "DnsAdmins" -GroupScope Universal
    Set-ADGroup -Identity "DnsAdmins" -GroupScope Global
    Add-Type -AssemblyName System.Web

    $firstname = (VulnAD-GetRandom -InputList $Global:HumansNames)
    $lastname = (VulnAD-GetRandom -InputList $Global:HumansNames)
    $fullname = "{0} {1}" -f ($firstname , $lastname)
    $SamAccountName = ("{0}.{1}" -f ($firstname, $lastname)).ToLower()
    $principalname = "{0}.{1}" -f ($firstname, $lastname)
    $password = "UberSecurePassword"
    Try {
        New-ADUser -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname `
            -SamAccountName $SamAccountName -UserPrincipalName $principalname@$Global:Domain `
            -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru |
        Enable-ADAccount
    }
    Catch {}

    Add-ADGroupMember -Identity "DnsAdmins" -Members $SamAccountName
    Set-ADUser $SamAccountName -Description "DNS Admin"
    Write-Info "DnsAdmins : $SamAccountName"
}

function VulnAD-DefaultPassword {
    for ($i = 1; $i -le (Get-Random -Minimum 1 -Maximum 6); $i++) {
        $randomuser = (VulnAD-GetRandom -InputList (Get-Random -InputObject @($Global:Marketing, $Global:Sales, $Global:Accounting)))
        $password = ([System.Web.Security.Membership]::GeneratePassword(7, 2))
        Set-AdAccountPassword -Identity $randomuser -Reset -NewPassword (ConvertTo-SecureString $password -AsPlainText -Force)
        Set-ADUser $randomuser -Description "New user generated password: $password" -ChangePasswordAtLogon $true
        Write-Info "Password in Description : $randomuser $password"
        $Global:InitialAccessUsers += $randomuser
    }
}

function VulnAD-PasswordSpraying {
    $same_password = ($Global:Domain -replace "\.\w+", "") + ([string](Get-Random -Maximum 100)).PadLeft(3, '0')
    for ($i = 1; $i -le (Get-Random -Minimum 2 -Maximum 6); $i++) {
        $randomuser = (VulnAD-GetRandom -InputList (Get-Random -InputObject @($Global:Marketing, $Global:Sales, $Global:Accounting)))
        Set-AdAccountPassword -Identity $randomuser -Reset -NewPassword (ConvertTo-SecureString $same_password -AsPlainText -Force)
        Set-ADUser $randomuser -Description "Company default password(Reset ASAP)" -ChangePasswordAtLogon $true
        Write-Info "Same Password (Password Spraying) : $randomuser"
        $Global:InitialAccessUsers += $randomuser
    }
}

function Counter {
    param([string]$path)
    $counter = @{}
    foreach ($letter in [char[]]$path) {
        $letter = [string]$letter
        if (-not $counter.Contains($letter)) {
            $counter[$letter] = 0
        }
        $counter[$letter] += 1
    }
    return $counter
}

function getList {
    param(
        [string]$path,
        [array]$list
    )
    $newlist = [System.Collections.ArrayList]::new()
    foreach ($o in $list) {
        $null = $newlist.Add($o)
    }
    $mapping = @("Marketing", "Sales", "Accounting", "Senior management", "Project management", "IT Helpdesk", "Office Admin", "IT Admins", "Executives")
    foreach ($i in (Counter($path)).keys) {
        if ((Counter($path))[$i] -ge 2) {
            foreach ($j in (Counter($path)).keys) {
                $null = $newlist.Remove($mapping[$j - 1])
            }
        }
    }
    return $newlist
}

function getPath {
    $mapping = @{
        "Marketing"          = "1"
        "Sales"              = "2"
        "Accounting"         = "3"
        "Senior management"  = "4"
        "Project management" = "5"
        "IT Helpdesk"        = "6"
        "Office Admin"       = "7"
        "IT Admins"          = "8"
        "Executives"         = "9"
    }
    $path = ""
    $path2 = ""
    $end = VulnAD-GetRandom -InputList $Global:HighGroups
    $middle = VulnAD-GetRandom -InputList $Global:MidGroups
    $start = VulnAD-GetRandom -InputList $Global:NormalGroups

    $path += $mapping[$start]
    $path2 += $mapping[$middle]

    if ((Get-Random -Maximum 2)) {
        while ($path[-1] -ne $mapping[$end]) {
            $path += $mapping[(VulnAD-GetRandom -InputList (getList -path $path -list ($Global:NormalGroups + $end)))]
        }
        Write-Info "Path: $path"
        return $path
    }
    else {
        while ($path[-1] -ne $mapping[$middle]) {
            $path += $mapping[(VulnAD-GetRandom -InputList (getList -path $path -list ($Global:NormalGroups + $middle)))]
        }
        while ($path2[-1] -ne $mapping[$end]) {
            $path2 += $mapping[(VulnAD-GetRandom -InputList (getList -path ($path + $path2) -list ($Global:MidGroups + $end)))]
        }
        Write-Info "Path: $path$path2"
        return $path + $path2
    }
}

function VulnAD-UserAcl {
    param(
        [string]$src,
        [string]$dst
    )
    $mapping = @("", "Marketing", "Sales", "Accounting", "Senior management", "Project management", "IT Helpdesk", "Office Admin", "IT Admins", "Executives")
    $firstname = (VulnAD-GetRandom -InputList $Global:HumansNames)
    $lastname = (VulnAD-GetRandom -InputList $Global:HumansNames)
    $SamAccountName = ("{0}.{1}" -f ($firstname, $lastname)).ToLower()
    Try {
        New-ADUser -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -SamAccountName $SamAccountName `
            -UserPrincipalName "$SamAccountName@$Global:Domain" `
            -AccountPassword (ConvertTo-SecureString ([System.Web.Security.Membership]::GeneratePassword(7, 2)) -AsPlainText -Force) -PassThru |
        Enable-ADAccount
    }
    Catch {}
    Try {
        Add-ADGroupMember -Identity $mapping[$dst] -Members $SamAccountName
    }
    Catch {}

    if ($Global:ACLUser) {
        $SrcUser = Get-ADUser -Identity $Global:ACLUser
    }
    else {
        $SrcUser = Get-ADUser -Identity (VulnAD-GetRandom -InputList $Global:InitialAccessUsers)
        $Global:InitialAccessUsers = $Global:InitialAccessUsers -ne $SrcUser
    }
    $DstUser = Get-ADUser -Identity $SamAccountName
    $Global:ACLUser = Get-ADUser -Identity $SamAccountName

    VulnAD-AddACL -Source $SrcUser.sid -Destination $DstUser.DistinguishedName -Rights "GenericAll"
    Write-Info ("Giving " + $SrcUser.Name + " GenericAll over " + $DstUser.Name + "(" + $mapping[$dst] + ")")
}

function VulnAD-GroupUserAcl {
    param(
        [string]$src,
        [string]$dst
    )
    $mapping = @("", "Marketing", "Sales", "Accounting", "Senior management", "Project management", "IT Helpdesk", "Office Admin", "IT Admins", "Executives")
    $firstname = (VulnAD-GetRandom -InputList $Global:HumansNames)
    $lastname = (VulnAD-GetRandom -InputList $Global:HumansNames)
    $SamAccountName = ("{0}.{1}" -f ($firstname, $lastname)).ToLower()
    Try {
        New-ADUser -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -SamAccountName $SamAccountName `
            -UserPrincipalName "$SamAccountName@$Global:Domain" `
            -AccountPassword (ConvertTo-SecureString ([System.Web.Security.Membership]::GeneratePassword(7, 2)) -AsPlainText -Force) -PassThru |
        Enable-ADAccount
    }
    Catch {}
    Try {
        Add-ADGroupMember -Identity $mapping[$dst] -Members $SamAccountName
    }
    Catch {}

    $SrcGroup = Get-ADGroup -Identity $mapping[$src]
    $DstUser = Get-ADUser -Identity $SamAccountName
    $Global:ACLUser = Get-ADUser -Identity $SamAccountName

    VulnAD-AddACL -Source $SrcGroup.sid -Destination $DstUser.DistinguishedName -Rights "GenericAll"
    Write-Info ("Giving " + $SrcGroup.Name + " GenericAll over " + $DstUser.Name + "(" + $mapping[$dst] + ")")
}

function VulnAD-UserGroupAcl {
    param([string]$dst)
    $mapping = @("", "Marketing", "Sales", "Accounting", "Senior management", "Project management", "IT Helpdesk", "Office Admin", "IT Admins", "Executives")
    $DstGroup = Get-ADGroup -Identity $mapping[$dst]
    VulnAD-AddACL -Source $Global:ACLUser.sid -Destination $DstGroup.DistinguishedName -Rights "GenericAll"
    Write-Info ("Giving " + $Global:ACLUser.Name + " GenericAll over " + $DstGroup.Name)
}

function VulnAD-GroupAcl {
    param(
        [string]$src,
        [string]$dst
    )
    $mapping = @("", "Marketing", "Sales", "Accounting", "Senior management", "Project management", "IT Helpdesk", "Office Admin", "IT Admins", "Executives")
    $SrcGroup = Get-ADGroup -Identity $mapping[$src]
    $DstGroup = Get-ADGroup -Identity $mapping[$dst]
    $abuse = Get-Random -InputObject @('GenericAll', 'WriteProperty', 'Self', 'WriteOwner', 'DoublePerm')
    if ($abuse -eq "DoublePerm") {
        VulnAD-AddACL -Source $SrcGroup.sid -Destination $DstGroup.DistinguishedName -Rights "WriteDACL"
        VulnAD-AddACL -Source $SrcGroup.sid -Destination $DstGroup.DistinguishedName -Rights "WriteOwner"
        Write-Info ("Giving " + $SrcGroup.Name + " WriteDACL & WriteOwner over " + $DstGroup.Name)
    }
    else {
        VulnAD-AddACL -Source $SrcGroup.sid -Destination $DstGroup.DistinguishedName -Rights $abuse
        Write-Info ("Giving " + $SrcGroup.Name + " " + $abuse + " over " + $DstGroup.Name)
    }
}

function VulnAD-BadAcls {
    $mapping = @(
        $Global:Marketing,
        $Global:Sales,
        $Global:Accounting,
        $Global:Seniormanagement,
        $Global:Projectmanagement,
        $Global:ITHelpdesk,
        $Global:OfficeAdmin,
        $Global:ITAdmins,
        $Global:Executives
    )
    $path = getPath
    if ($path[0] -eq $path[1]) {
        $DstUser = Get-ADUser -Identity (VulnAD-GetRandom -InputList ($mapping[[string]$path[1] - 1]))
        $InitialUser = Get-ADUser -Identity (VulnAD-GetRandom -InputList $Global:InitialAccessUsers)
        $Global:InitialAccessUsers = $Global:InitialAccessUsers -ne $InitialUser
        $Global:ACLUser = Get-ADUser -Identity $DstUser
        VulnAD-AddACL -Source $InitialUser.sid -Destination $DstUser.DistinguishedName -Rights "GenericAll"
        Write-Info ("Giving " + $InitialUser.Name + " GenericAll over " + $DstUser.Name)
    }
    else {
        $mapping = @("Marketing", "Sales", "Accounting", "Senior management", "Project management", "IT Helpdesk", "Office Admin", "IT Admins", "Executives")
        $SrcGroup = Get-ADGroup -Identity $mapping[[string]$path[0]]
    }
    $count = 0
    $Duplicates = @()
    foreach ($i in (Counter($path)).keys) {
        if ((Counter($path))[$i] -ge 2) {
            $Duplicates += $i
        }
    }
    $DupPosition = @()
    $DupPosition2 = @()
    foreach ($i in $Duplicates) {
        $DupPosition += [string]$path.LastIndexOf($i)
        $DupPosition2 += [string]($path.LastIndexOf($i) + 2)
    }
    $intersect = $DupPosition | Where-Object { $DupPosition2 -contains $_ }

    foreach ($num in [char[]]$path[1..(([char[]]$path).Count - 1)]) {
        $count++
        if ([string]$path[[string]$count - 1] -eq [string]$path[$count] -or $intersect -eq $count + 1) {
            VulnAD-UserAcl -src ([string]$path[[string]$count - 1]) -dst ([string]$path[$count])
        }
        elseif ($DupPosition.Contains([string]$count)) {
            VulnAD-GroupUserAcl -src ([string]$path[[string]$count - 1]) -dst ([string]$path[$count])
        }
        elseif ($DupPosition2.Contains([string]($count + 1))) {
            VulnAD-UserGroupAcl -dst ([string]$path[$count])
        }
        else {
            VulnAD-GroupAcl -src ([string]$path[[string]$count - 1]) -dst ([string]$path[$count])
        }
    }
    $mapping = @("Marketing", "Sales", "Accounting", "Senior management", "Project management", "IT Helpdesk", "Office Admin", "IT Admins", "Executives")
    VulnAD-DCSync -group ($mapping[[string]$path[-1] - 1])

    foreach ($abuse in $Global:ACLperm) {
        $hgroup = VulnAD-GetRandom -InputList $Global:HighGroups
        $mgroup = VulnAD-GetRandom -InputList $Global:MidGroups
        $DstGroup = Get-ADGroup -Identity $hgroup
        $SrcGroup = Get-ADGroup -Identity $mgroup
        VulnAD-AddACL -Source $SrcGroup.sid -Destination $DstGroup.DistinguishedName -Rights $abuse
        Write-Info "BadACL $hgroup has $abuse permission for $mgroup"
    }
    for ($i = 1; $i -le (Get-Random -Minimum 10 -Maximum 30); $i++) {
        $abuse = (VulnAD-GetRandom -InputList $Global:ACLperm)
        $randomuser = VulnAD-GetRandom -InputList $Global:CreatedUsers
        $randomgroup = VulnAD-GetRandom -InputList $Global:AllObjects
        if ((Get-Random -Maximum 2)) {
            $Dstobj = Get-ADUser -Identity $randomuser
            $Srcobj = Get-ADGroup -Identity $randomgroup
        }
        else {
            $Srcobj = Get-ADUser -Identity $randomuser
            $Dstobj = Get-ADGroup -Identity $randomgroup
        }
        VulnAD-AddACL -Source $Srcobj.sid -Destination $Dstobj.DistinguishedName -Rights $abuse
        Write-Info "BadACL $randomgroup has $abuse permission for $randomuser"
    }
    for ($i = 1; $i -le (Get-Random -Minimum 1 -Maximum 30); $i++) {
        $abuse = (VulnAD-GetRandom -InputList $Global:ACLperm)
        $randomuser = VulnAD-GetRandom -InputList $Global:CreatedUsers
        $randomuser2 = VulnAD-GetRandom -InputList $Global:CreatedUsers
        if (-not($randomuser -eq $randomuser2)) {
            $Dstobj = Get-ADUser -Identity $randomuser
            $Srcobj = Get-ADUser -Identity $randomuser2
            VulnAD-AddACL -Source $Srcobj.sid -Destination $Dstobj.DistinguishedName -Rights $abuse
            Write-Info "BadACL $randomuser has $abuse permission for $randomuser2"
        }
    }
}

function VulnAD-DCSync {
    param(
        [string]$group
    )
    $Identity = (Get-ADGroup -Identity $group)
    $RootDSE = [ADSI]"LDAP://RootDSE"
    $DefaultNamingContext = $RootDse.defaultNamingContext
    $ConfigurationNamingContext = $RootDse.configurationNamingContext
    $UserPrincipal = New-Object Security.Principal.NTAccount("$Identity")

    DSACLS "$DefaultNamingContext" /G "$($UserPrincipal):CA;Replicating Directory Changes" | Out-Null
    DSACLS "$ConfigurationNamingContext" /G "$($UserPrincipal):CA;Replicating Directory Changes" | Out-Null

    DSACLS "$DefaultNamingContext" /G "$($UserPrincipal):CA;Replicating Directory Changes All" | Out-Null
    DSACLS "$ConfigurationNamingContext" /G "$($UserPrincipal):CA;Replicating Directory Changes All" | Out-Null

    DSACLS "$DefaultNamingContext" /G "$($UserPrincipal):CA;Replicating Directory Changes In Filtered Set" | Out-Null
    DSACLS "$ConfigurationNamingContext" /G "$($UserPrincipal):CA;Replicating Directory Changes In Filtered Set" | Out-Null
    Write-Info "Giving DCSync to : $group"
}

function VulnAD-DisableSMBSigning {
    Set-SmbClientConfiguration -RequireSecuritySignature 0 -EnableSecuritySignature 0 -Confirm:$false -Force
}

function VulnAD-EnableWinRM {
    Enable-PSRemoting -Force
    Set-Item wsman:\localhost\client\trustedhosts * -Force
    Set-PSSessionConfiguration -Name "Microsoft.PowerShell" `
        -SecurityDescriptorSddl "O:NSG:BAD:P(A;;GA;;;BA)(A;;GA;;;WD)(A;;GA;;;IU)S:P(AU;FA;GA;;;WD)(AU;SA;GXGW;;;WD)"
}

function VulnAD-AnonymousLDAP {
    $Dcname = Get-ADDomain | Select-Object -ExpandProperty DistinguishedName
    $Adsi = 'LDAP://CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,' + $Dcname
    $AnonADSI = [ADSI]$Adsi
    $AnonADSI.Put("dSHeuristics", "0000002")
    $AnonADSI.SetInfo()

    $ADSI = [ADSI]('LDAP://CN=Users,' + $Dcname)
    $Anon = New-Object System.Security.Principal.NTAccount("ANONYMOUS LOGON")
    $SID = $Anon.Translate([System.Security.Principal.SecurityIdentifier])
    $adRights = [System.DirectoryServices.ActiveDirectoryRights] "GenericRead"
    $type = [System.Security.AccessControl.AccessControlType] "Allow"
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, $adRights, $type, $inheritanceType
    $ADSI.PSBase.ObjectSecurity.ModifyAccessRule([System.Security.AccessControl.AccessControlModification]::Add, $ace, [ref]$false)
    $ADSI.PSBase.CommitChanges()
}

function VulnAD-PublicSMBShare {
    New-Item -ItemType Directory -Path 'C:\Common' -Force | Out-Null
    echo "$password = ConvertTo-SecureString 'UberSecurePassword' -AsPlainText -Force
`$credential = New-Object System.Management.Automation.PSCredential ('administrator', `$password)
Invoke-Command -ComputerName . -Credential `$credential -ScriptBlock { Restart-Service -Name 'DNS Server' }" > C:\Common\DNSrestart.ps1

    New-SmbShare -Name Common -Path C:\Common -FullAccess Everyone
    Enable-LocalUser -Name "Guest"
    $acl = Get-Acl C:\Common
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Guest", "FullControl", "Allow")
    $acl.SetAccessRule($AccessRule)
    $acl | Set-Acl C:\Common

    Set-Itemproperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'EveryoneIncludesAnonymous' -value '1'
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name "NullSessionShares" `
        -PropertyType MultiString -Value "C:\Common" | Out-Null
}

function VulnAD-FirewallOff {
    netsh advfirewall set allprofiles state off
}

function Read-Boolean {
    param([string]$Prompt)
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
    param(
        [string]$Name,
        [string]$ExpectedState,
        [string]$ReadableName = $null
    )
    if (-not $ReadableName) {
        $ReadableName = $Name
    }
    $isExpectedState = ((Get-Service -Name $Name).Status -eq $ExpectedState)
    if ($isExpectedState) {
        Write-Host "  $ReadableName Service is $($ExpectedState.ToLower()), skipping..." -ForegroundColor Red
    }
    return $isExpectedState
}

function Set-ServiceStatus {
    param(
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

# Dictionary of vulnerabilities
$Global:NTLMvulnerabilities = @{
    'printerbug'   = @{
        'description' = 'RPC vulnerability using the Print Spooler service (MS-RPRN)'
        'enable'      = { param ([bool]$DefaultYes) Set-ServiceStatus -On  -Name 'Spooler'     -ReadableName 'Print Spooler' -DefaultYes $DefaultYes | Out-Null }
        'disable'     = { param ([bool]$DefaultYes) Set-ServiceStatus -Off -Name 'Spooler'     -ReadableName 'Print Spooler' -DefaultYes $DefaultYes | Out-Null }
    }
    'petitpotam'   = @{
        'description' = 'RPC vulnerability using the SMB service (MS-EFSRPC)'
        'enable'      = { param ([bool]$DefaultYes) Set-ServiceStatus -On  -Name 'LanmanServer' -ReadableName 'SMB' -DefaultYes $DefaultYes | Out-Null }
        'disable'     = {
            param ([bool]$DefaultYes)
            if (-not (Set-ServiceStatus -Off -Name 'LanmanServer' -ReadableName 'SMB' -DefaultYes $DefaultYes)) {
                Write-Host '  See external resources:' -ForegroundColor Red -NoNewline
                Write-Host ' https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services...'
            }
        }
    }
    'shadowcoerce' = @{
        'description' = 'RPC vulnerability using Microsoft File Server Remote VSS Protocol (MS-FSRVP)'
        'enable'      = { param ([bool]$DefaultYes) Set-ServiceStatus -On  -Name 'VSS' -ReadableName 'Volume Shadow Copy' -DefaultYes $DefaultYes | Out-Null }
        'disable'     = {
            param ([bool]$DefaultYes)
            if (-not (Set-ServiceStatus -On -Name 'VSS' -ReadableName 'Volume Shadow Copy' -DefaultYes $DefaultYes)) {
                Write-Host '  See external resources:' -ForegroundColor Red -NoNewline
                Write-Host ' https://support.microsoft.com/...kb5015527-shadow-copy-operations-using-vss-on-remote-smb-shares-denied-access...'
            }
        }
    }
    'dfscoerce'    = @{
        'description' = 'RPC vulnerability using the Distributed File System service (MS-DFSNM)'
        'enable'      = { param ([bool]$DefaultYes) Set-ServiceStatus -On  -Name 'DFS' -ReadableName 'Distributed File System' -DefaultYes $DefaultYes | Out-Null }
        'disable'     = { param ([bool]$DefaultYes) Set-ServiceStatus -Off -Name 'DFS' -ReadableName 'Distributed File System' -DefaultYes $DefaultYes | Out-Null }
    }
}


function Invoke-NTLMCoercionLab {
    do {
        Write-Host "`nNTLM Coercion Vulnerabilities:"
        Write-Host "1. Enable/Disable Printerbug    ($($Global:NTLMvulnerabilities['printerbug'].description))"
        Write-Host "2. Enable/Disable PetitPotam     ($($Global:NTLMvulnerabilities['petitpotam'].description))"
        Write-Host "3. Enable/Disable ShadowCoerce   ($($Global:NTLMvulnerabilities['shadowcoerce'].description))"
        Write-Host "4. Enable/Disable DFSCoerce      ($($Global:NTLMvulnerabilities['dfscoerce'].description))"
        Write-Host "5. Return to Main Menu"

        $subChoice = Read-Host "Enter your selection (1..5)"
        switch ($subChoice) {
            "1" {
                Switch-NTLMSubVuln 'printerbug'
            }
            "2" {
                Switch-NTLMSubVuln 'petitpotam'
            }
            "3" {
                Switch-NTLMSubVuln 'shadowcoerce'
            }
            "4" {
                Switch-NTLMSubVuln 'dfscoerce'
            }
            "5" {
                Write-Host "Returning to Main Menu..."
                return
            }
            default {
                Write-Host "Invalid selection, please try again."
            }
        }
    } while ($true)
}

function Switch-NTLMSubVuln {
    param(
        [string]$VulnName
    )
    Write-Host "`nYou selected $VulnName : $($Global:NTLMvulnerabilities[$VulnName].description)"
    $ans = Read-Host "Enable or Disable this vulnerability? (e/d or q=quit)"
    switch ($ans) {
        'e' { & $Global:NTLMvulnerabilities[$VulnName]['enable'] -DefaultYes:$false; Write-Host "Done enabling $VulnName." }
        'd' { & $Global:NTLMvulnerabilities[$VulnName]['disable'] -DefaultYes:$false; Write-Host "Done disabling $VulnName." }
        'q' { Write-Host "Cancelled. Returning to sub-menu..."; return }
        default { Write-Host "Invalid. Must be e/d/q. Returning to sub-menu." }
    }
}

function Enable-ADModule {
    if (-not (Get-WindowsFeature -Name RSAT-AD-PowerShell).Installed) {
        Write-Host 'Active Directory module not found, installing...'
        Install-WindowsFeature RSAT-AD-PowerShell | Out-Null
        Import-Module ActiveDirectory
    } else {
        Write-Host 'Active Directory module found, skipping...'
    }
}

function Enable-ADCS {
    if (-not (Get-WindowsFeature -Name AD-Certificate).Installed) {
        Write-Host 'Active Directory Certificate Services not found, installing...'
        Install-WindowsFeature -Name AD-Certificate -IncludeManagementTools | Out-Null
    }
    else {
        Write-Host 'Active Directory Certificate Services found, skipping...'
    }

    try {
        Write-Host 'Enabling Enterprise CA...'
        Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CACommonName "VulnerableEnterpriseCA" -Force | Out-Null
    }
    catch {
        Write-Host 'Error enabling Enterprise CA (may already be enabled)'
    }
}

function Enable-WebEnrollment {
    if (-not (Get-WindowsFeature -Name Adcs-Web-Enrollment).Installed) {
        Write-Host 'Web Enrollment not enabled, enabling...'
        Add-WindowsFeature Adcs-Web-Enrollment | Out-Null
        Install-AdcsWebEnrollment -Force | Out-Null
    }
    else {
        Write-Host 'Web Enrollment already enabled, skipping...'
    }
}

function New-VulnerableUserTemplate {
    Write-Host 'Creating vulnerable template...'
    Import-Module '.\deps\ADCSTemplate'
    $randomTemplateSuffix = -join ((1..4) | ForEach-Object { $Global:Characters | Get-Random })
    New-ADCSTemplate -DisplayName "VulnerableUserTemplate-$randomTemplateSuffix" -JSON (Get-Content '.\deps\VulnerableUserTemplate.json' -Raw) -Publish -Identity "$Global:Domain\Domain Users"
}

function Invoke-ADCSLab {
    do {
        Write-Host "`nAD CS Vulnerabilities:"
        Write-Host "1. Enable ESC1     Domain escalation via No Issuance Requirements + Enrollable Client Authentication/Smart Card Logon OID templates + CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT"
        Write-Host "2. (NOT IMPLEMENTED) Enable ESC2     Domain escalation via No Issuance Requirements + Enrollable Any Purpose EKU or no EKU"
        Write-Host "3. (NOT IMPLEMENTED) Enable ESC3     Domain escalation via No Issuance Requirements + Certificate Request Agent EKU + no enrollment agent restrictions"
        Write-Host "4. (NOT IMPLEMENTED) Enable ESC4     Domain escalation via misconfigured certificate template access control"
        Write-Host "5. (NOT IMPLEMENTED) Enable ESC5     Domain escalation via vulnerable PKI AD Object Access Control"
        Write-Host "6. (NOT IMPLEMENTED) Enable ESC6     Domain escalation via the EDITF_ATTRIBUTESUBJECTALTNAME2 setting on CAs + No Manager Approval + Enrollable Client Authentication/Smart Card Logon OID templates"
        Write-Host "7. (NOT IMPLEMENTED) Enable ESC7     Vulnerable Certificate Authority Access Control"
        Write-Host "8. Enable ESC8     NTLM Relay to AD CS HTTP Endpoints"
        Write-Host "9. Return to Main Menu"

        $subChoice = Read-Host "Enter your selection (1..9)"
        switch ($subChoice) {
            "1" {
                Write-Host 'Enabling ESC1...'
                Enable-ADModule
                Enable-ADCS
                New-VulnerableUserTemplate
                Write-Host 'Done!'
            }
            "2" {
                Write-Host 'This vulnerability has not been implemented yet.'
            }
            "3" {
                Write-Host 'This vulnerability has not been implemented yet.'
            }
            "4" {
                Write-Host 'This vulnerability has not been implemented yet.'
            }
            "5" {
                Write-Host 'This vulnerability has not been implemented yet.'
            }
            "6" {
                Write-Host 'This vulnerability has not been implemented yet.'
            }
            "7" {
                Write-Host 'This vulnerability has not been implemented yet.'
            }
            "8" {
                Write-Host 'Enabling ESC8...'
                Enable-ADModule
                Enable-ADCS
                Enable-WebEnrollment
                New-VulnerableUserTemplate
                Write-Host 'Done!'
            }
            "9" {
                Write-Host "Returning to Main Menu..."
                return
            }
            default {
                Write-Host "Invalid selection, please try again."
            }
        }
    } while ($true)
}

function Invoke-VulnAD {
    ShowBanner
	
    $CurrentDomain = (Get-ADDomain).DNSRoot
    $DomainName = Prompt-ForInput -PromptText "Enter the Domain Name (default: $CurrentDomain)" -DefaultValue $CurrentDomain
    
    $Global:Domain = $DomainName

    Set-ADDefaultDomainPasswordPolicy -Identity $Global:Domain `
        -LockoutDuration 00:01:00 `
        -LockoutObservationWindow 00:01:00 `
        -ComplexityEnabled $false `
        -ReversibleEncryptionEnabled $false `
        -MinPasswordLength 4

    $quit = $false
    do {
        Write-Output "`nSelect the vulnerabilities to deploy:"
        Write-Output "1.  ACL"
        Write-Output "2.  Kerberoasting"
        Write-Output "3.  AS-REPRoasting"
        Write-Output "4.  DNS Admins"
        Write-Output "5.  Default Password"
        Write-Output "6.  Password Spraying"
        Write-Output "7.  Bad ACL"
        Write-Output "8.  Disable SMB Signing"
        Write-Output "9.  Enable WinRM"
        Write-Output "10. Anonymous LDAP"
        Write-Output "11. Public SMB Share"
        Write-Output "12. Firewall Off"
        Write-Output "13. NTLM Coercion Vulnerabilities"
        Write-Output "14. AD CS Vulnerabilities (ESC)"
        Write-Output "15. Add Users"
        Write-Output "99. Quit"

        $selectedOption = Read-Host "Enter your selection (1..14, or 99 to quit)"

        switch ($selectedOption) {
            "1" {
                VulnAD-Acls
                Write-Good "ACL Done"
            }
            "2" {
                $UsersLimit = [int](Prompt-ForInput -PromptText "Enter the number of users to create (default: 50)" -DefaultValue "50")
                VulnAD-AddADUser -limit $UsersLimit
                VulnAD-AddADGroup -GroupList $Global:Groups
                VulnAD-Kerberoasting
                Write-Good "Kerberoasting Done"
            }
            "3" {
                $UsersLimit = [int](Prompt-ForInput -PromptText "Enter the number of users to create (default: 50)" -DefaultValue "50")
                VulnAD-AddADUser -limit $UsersLimit
                VulnAD-AddADGroup -GroupList $Global:Groups
                VulnAD-ASREPRoasting
                Write-Good "AS-REPRoasting Done"
            }
            "4" {
                $UsersLimit = [int](Prompt-ForInput -PromptText "Enter the number of users to create (default: 50)" -DefaultValue "50")
                VulnAD-AddADUser -limit $UsersLimit
                VulnAD-AddADGroup -GroupList $Global:Groups
                VulnAD-DnsAdmins
                Write-Good "DNS Admins Done"
            }
            "5" {
                VulnAD-DefaultPassword
                Write-Good "Default Passwords Set"
            }
            "6" {
                VulnAD-PasswordSpraying
                Write-Good "Password Spraying Done"
            }
            "7" {
                VulnAD-BadAcls
                Write-Good "Bad ACLs Set"
            }
            "8" {
                VulnAD-DisableSMBSigning
                Write-Good "SMB Signing Disabled"
            }
            "9" {
                VulnAD-EnableWinRM
                Write-Good "Windows Remote Management Enabled"
            }
            "10" {
                VulnAD-AnonymousLDAP
                Write-Good "Anonymous LDAP Queries Enabled"
            }
            "11" {
                VulnAD-PublicSMBShare
                Write-Good "Public SMB Share Created"
            }
            "12" {
                VulnAD-FirewallOff
                Write-Good "Firewall Turned Off"
            }
            "13" {
                # Launch sub-menu for NTLM Coercion vulns
                Invoke-NTLMCoercionLab
            }
            "14" {
                Invoke-ADCSLab
            }
            "15" {
                $UsersLimit = [int](Prompt-ForInput -PromptText "Enter the number of users to create (default: 50)" -DefaultValue "50")
                VulnAD-AddADUser -limit $UsersLimit
                Write-Good "Users Created"
            }
            "99" {
                Write-Output "Exiting the application..."
                $quit = $true
            }
            default {
                Write-Output "Invalid selection, please try again."
            }
        }
    } while (-not $quit)
}

Invoke-VulnAD
