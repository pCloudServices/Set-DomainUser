### Script to help move the PSM users from local to domain users

<#
.SYNOPSIS
This script will update the connector server to a domain user setup. It will also onboard the domain users into the portal inside the PSM safe.
.DESCRIPTION
Does the Domain User for PSM setup.
.PARAMETER pvwaAddress
The PVWA Address (https://tenant.privilegecloud.cyberark.com, or on-prem URL)
.PARAMETER domain
The domain of the domain user account(s).
.PARAMETER NETBIOS
The NETBIOS for the domain user account(s).
.PARAMETER safe
The safe in which to store PSM user credentials
.PARAMETER tinaCreds
Tenant Administrator/InstallerUser credentials
.PARAMETER psmConnectCredentials
PSMConnect domain user credentials
.PARAMETER psmAdminCredentials
PSMAdminConnect domain user credentials
.PARAMETER TestPsmConnectCredentials
Validate psmConnectCredentials domain user credentials
.PARAMETER TestPsmAdminCredentials
Validate PSMAdminConnect domain user credentials
.PARAMETER IgnoreShadowPermissionErrors
Ignore errors while granting PSMAdminConnect user shadow permissions
.PARAMETER PlatformName
The name of the platform to be created for the PSM accounts
.PARAMETER PSMConnectAccountName
The Account Name for the object in the vault which will contain the PSMConnect account. Defaults to "PSMConnect".
.PARAMETER PSMAdminConnectAccountName
The Account Name for the object in the vault which will contain the PSMAdminConnect account. Defaults to "PSMAdminConnect".
#>



[CmdletBinding()]
param(
    [Parameter(
        Mandatory = $false,
        HelpMessage = "Please enter the full PVWA Address IE: https://tenantname.privilegecloud.cyberark.cloud")]
    [string]$pvwaAddress,
    [Parameter(
        Mandatory = $false,
        HelpMessage = "Please enter the domain of the created accounts IE: lab.net")]
    [string]$domain,
    [Parameter(
        Mandatory = $false,
        HelpMessage = "Please enter the NETBIOS of the created accounts IE: LAB")]
    [string]$NETBIOS,
    [Parameter(
        Mandatory = $false,
        HelpMessage = "Please enter the account credentials for the tenant administrator or installer user.")]
    [PSCredential]$tinaCreds,
    [Parameter(
        Mandatory = $false,
        HelpMessage = "Please enter the account credentials for the PSMConnect domain account.")]
    [PSCredential]$psmConnectCredentials,
    [Parameter(
        Mandatory = $false,
        HelpMessage = "Please enter the account credentials for the PSMAdminConnect domain account.")]
    [PSCredential]$psmAdminCredentials,
    [Parameter(
        Mandatory = $false,
        HelpMessage = "Please enter the Safe to save the domain accounts in, By default it is PSM")]
    [String]$safe = "PSM",     
    [Parameter(
        Mandatory = $false,
        HelpMessage = "Verify the provided PSMConnect credentials")]
    [switch]$TestPsmConnectCredentials,
    [Parameter(
        Mandatory = $false,
        HelpMessage = "Verify the provided PSMAdminConnect credentials")]
    [switch]$TestPsmAdminCredentials,
    [Parameter(
        Mandatory = $false,
        HelpMessage = "Ignore errors while granting PSMAdminConnect user shadow permissions")]
    [switch]$IgnoreShadowPermissionErrors,
    [Parameter(
        Mandatory = $false,
        HelpMessage = "Name of Platform to be used for PSM accounts")]
    [String]$PlatformName = "WIN-DOM-PSMADMIN-ACCOUNT",
    [Parameter(
        Mandatory = $false,
        HelpMessage = "Name of Platform to be used for PSM accounts")]
    [String]$PSMConnectAccountName = "PSMConnect",
    [Parameter(
        Mandatory = $false,
        HelpMessage = "Name of Platform to be used for PSM accounts")]
    [String]$PSMAdminConnectAccountName = "PSMAdminConnect"
)

#Functions

Function Get-DomainDnsName {
    if ($env:USERDNSDOMAIN) {
        return $env:USERDNSDOMAIN
    }
    else {
        Write-Host "Unable to determine domain DNS name. Please provide it on the command line."
        exit 1
    }
}

Function Get-DomainNetbiosName {
    if ($env:USERDOMAIN) {
        return $env:USERDOMAIN
    }
    else {
        Write-Host "Unable to determine domain NETBIOS name. Please provide it on the command line."
        exit 1
    }
}

Function Get-PvwaAddress {
    <#
    .SYNOPSIS
    Backs up PSMConfig ps1 scripts
    .DESCRIPTION
    Copies PSM config items to -backup.ps1
    .PARAMETER psmRootInstallLocation
    PSM root installation folder
    #>
    param (
        [Parameter(Mandatory = $true)]
        $psmRootInstallLocation
    )
    try {
        $VaultIni = Get-Content "$psmRootInstallLocation\vault\vault.ini"
        $VaultIniAddressesLine = $VaultIni | Select-String "^Addresses"
        $null = $VaultIniAddressesLine -match "(https://[\.0-9a-zA-Z]*)"
        $Address = $Matches[0]
        If (!($Address)) {
            Throw
        }
        return $Address
    }
    catch {
        Write-Host "Unable to detect PVWA address automatically. Please rerun script and provide it using the -PvwaAddress parameter."
        exit 1
    }
}


Function ValidateCredentials {
    <#
    .SYNOPSIS
    Tests whether the provided credentials are valid
    .DESCRIPTION
    Returns boolean test result, $true indicates success
    .EXAMPLE
    ValidateCredentials -Domain $domain -Credential $credential
    #>
    param(
        [Parameter(Mandatory = $true)][string]$domain,
        [Parameter(Mandatory = $true)][PSCredential]$Credential
    )
    Process {
        try {
            Add-Type -AssemblyName System.DirectoryServices.AccountManagement
            $Directory = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain, $domain)
            return $Directory.ValidateCredentials($Credential.UserName, $Credential.GetNetworkCredential().Password)
        }
        catch {
            return $false
        }
    }
}

Function IsUserDomainJoined {
    <#
    .SYNOPSIS
    Checks if a user is part of a domain
    .DESCRIPTION
    Returns boolean of userprincipal context type
    .EXAMPLE
    IsUserDomainJoined
    #>
    Process {
        try {
            Add-Type -AssemblyName System.DirectoryServices.AccountManagement
            $UserPrincipal = [System.DirectoryServices.AccountManagement.UserPrincipal]::Current
            if ($UserPrincipal.ContextType -eq "Domain") {
                return $true
            }
            else {
                return $false
            }   
        }
        catch {
            return $false
        }
    }
}

Function Get-ServiceInstallPath {
    <#
    .SYNOPSIS
    Get the installation path of a service
    .DESCRIPTION
    The function receive the service name and return the path or returns NULL if not found
    .EXAMPLE
    (Get-ServiceInstallPath $<ServiceName>) -ne $NULL
    .PARAMETER ServiceName
    The service name to query. Just one.
    #>
    param ($ServiceName)
    Begin {
        
    }
    Process {
        $retInstallPath = $null
        try {
            Set-Variable -Name m_ServiceList -Value $(Get-ChildItem "HKLM:\System\CurrentControlSet\Services" | ForEach-Object { Get-ItemProperty $_.pspath }) -Scope Script
            $regPath = $m_ServiceList | Where-Object { $_.PSChildName -eq $ServiceName }
            If ($Null -ne $regPath) {
                $retInstallPath = $regPath.ImagePath.Substring($regPath.ImagePath.IndexOf('"'), $regPath.ImagePath.LastIndexOf('"') + 1)
            }
        }
        catch {
            Throw $(New-Object System.Exception ("Cannot get Service Install path for $ServiceName", $_.Exception))
        }
        
        return $retInstallPath
    }
    End {
        
    }
}

Function New-ConnectionToRestAPI {
    <#
    .SYNOPSIS
    Get the installation path of a service
    .DESCRIPTION
    The function receive the service name and return the path or returns NULL if not found
    .EXAMPLE
    (Get-ServiceInstallPath $<ServiceName>) -ne $NULL
    .PARAMETER pvwaAddress
    The PVWA server address (e.g. https://subdomain.privilegecloud.cyberark.cloud)
    .PARAMETER tinaCreds
    Tenant administrator/installer user credentials
    #>
    # Get PVWA and login informatioN
    param (
        [Parameter(Mandatory = $true)]
        $pvwaAddress,
        [Parameter(Mandatory = $true)]
        [PSCredential]$tinaCreds        
    )
    $url = $pvwaAddress + "/PasswordVault/API/auth/Cyberark/Logon"
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($tinaCreds.Password)
    
    $headerPass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    $body = @{
        username = $tinaCreds.UserName
        password = $headerPass
    }
    $json = $body | ConvertTo-Json
    Try {
        $pvwaToken = Invoke-RestMethod -Method 'Post' -Uri $url -Body $json -ContentType 'application/json'
    }
    Catch {
        Write-Host "Failed to retrieve token. Response received:"
        Write-Host "$_.Exception.Message"
        exit 1
    }
    if ($pvwaToken -match "[0-9a-zA-Z]{200,256}") {
        return $pvwaToken
    }
    else {
        Write-Host "Failed to retrieve token. Response received:"
        Write-Host "$_.Exception.Message"
        exit 1
    }
}

Function Test-PvwaToken {
    <#
    .SYNOPSIS
    Test a PVWA token to ensure it is valid
    .DESCRIPTION
    The function receive the service name and return the path or returns NULL if not found
    .EXAMPLE
    Test-PvwaToken -Token $Token -PvwaAddress https://subdomain.privilegecloud.cyberark.cloud
    .PARAMETER pvwaAddress
    The PVWA server address (e.g. https://subdomain.privilegecloud.cyberark.cloud)
    .PARAMETER Token
    PVWA Token
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$pvwaAddress,
        [Parameter(Mandatory = $true)]
        [string]$Token        
    )
    $url = $pvwaAddress + "/PasswordVault/API/Accounts?limit=1"
    $Headers = @{
        Authorization = $pvwaToken
    }
    $testToken = Invoke-RestMethod -Method 'Get' -Uri $url -Headers $Headers -ContentType 'application/json'
    if ($testToken) {
        return $true
    }
    else {
        return $false
    }
}

Function Backup-PSMConfig {
    <#
    .SYNOPSIS
    Backs up PSMConfig ps1 scripts
    .DESCRIPTION
    Copies PSM config items to -backup.ps1
    .PARAMETER psmRootInstallLocation
    PSM root installation folder
    .PARAMETER BackupSuffix
    Append this string to the end of backup file names
    #>
    param (
        [Parameter(Mandatory = $true)]
        $psmRootInstallLocation,
        [Parameter(Mandatory = $true)]
        [string]$BackupSuffix
    )
    try {
        $PSMHardeningBackupFileName = ("{0}\Hardening\PSMHardening.{1}.bkp" -f $psmRootInstallLocation, $BackupSuffix)
        $PSMConfigureAppLockerBackupFileName = ("{0}\Hardening\PSMConfigureAppLocker.{1}.bkp" -f $psmRootInstallLocation, $BackupSuffix)
        $BasicPSMBackupFileName = ("{0}\basic_psm.{1}.bkp" -f $psmRootInstallLocation, $BackupSuffix)
        
        Copy-Item -path "$psmRootInstallLocation\Hardening\PSMHardening.ps1" -Destination $PSMHardeningBackupFileName
        Copy-Item -path "$psmRootInstallLocation\Hardening\PSMConfigureAppLocker.ps1" -Destination $PSMConfigureAppLockerBackupFileName
        Copy-Item -Path "$psmRootInstallLocation\basic_psm.ini" -Destination $BasicPSMBackupFileName
        
        If (!(Test-Path $PSMHardeningBackupFileName)) {
            Write-Error "Failed to backup PSMHardening.ps1" -ErrorAction Stop
        }
        ElseIf (!(Test-Path $PSMConfigureAppLockerBackupFileName)) {
            Write-Error "Failed to backup PSMConfigureAppLocker.ps1" -ErrorAction Stop
        }
        ElseIf (!(Test-Path $BasicPSMBackupFileName )) {
            Write-Error "Failed to backup basic_psm.ini" -ErrorAction Stop
        }
    }
    catch {
        write-output "Could not copy one of the scripts to backup. Exiting"
        write-output $_
        exit
    }
}

Function Update-PSMConfig {
    <#
    .SYNOPSIS
    Updates PSM scripts and basic_psm.ini to have domain user(s) in them rather than local user(s).
    .DESCRIPTION
    Updates PSM scripts and basic_psm.ini to have domain user(s) in them rather than local user(s).
    .PARAMETER psmRootInstallLocation
    PSM root installation folder
    .PARAMETER domain
    The user domain
    .PARAMETER PsmConnectUsername
    PSM Connect User name
    .PARAMETER PsmAdminUsername
    PSM Admin Connect user name
    #>
    param (
        [Parameter(Mandatory = $true)]
        $psmRootInstallLocation,
        [Parameter(Mandatory = $true)]
        $domain,
        [Parameter(Mandatory = $true)]
        $PsmConnectUsername,
        [Parameter(Mandatory = $true)]
        $PsmAdminUsername
    )
    try {
        #PSMHardening
        #-------------------------   
        $psmHardeningContent = Get-Content -Path $psmRootInstallLocation\Hardening\PSMHardening.ps1
        
        $newPsmHardeningContent = $psmHardeningContent -replace '^(\$PSM_CONNECT_USER\s*=) .*', ('$1 "{0}\{1}"' -f $domain, $PsmConnectUsername)
        $newPsmHardeningContent = $newPsmHardeningContent -replace '^(\$PSM_ADMIN_CONNECT_USER\s*=) .*$', ('$1 "{0}\{1}"' -f $domain, $PsmAdminUsername)
        $newPsmHardeningContent | Set-Content -Path "$psmRootInstallLocation\Hardening\test-psmhardening.ps1"
        
        #PSMApplocker    
        #------------------------- 
        
        
        $psmApplockerContent = Get-Content -Path $psmRootInstallLocation\Hardening\PSMConfigureApplocker.ps1
        
        $newPsmApplockerContent = $psmApplockerContent -replace '^(\$PSM_CONNECT\s*=) .*', ('$1 "{0}\{1}"' -f $domain, $PsmConnectUsername)
        $newPsmApplockerContent = $newPsmApplockerContent -replace '^(\$PSM_ADMIN_CONNECT\s*=) .*$', ('$1 "{0}\{1}"' -f $domain, $PsmAdminUsername)
        
        $newPsmApplockerContent | Set-Content -Path "$psmRootInstallLocation\Hardening\test-psm-applocker.ps1"
        
        
        #basic_psm.ini
        #-------------------------   
        
        
        $psmBasicPSMContent = Get-Content -Path $psmRootInstallLocation\basic_psm.ini
        
        $psmBasicPSMAdminLine = 'PSMServerAdminId="PSMAdminConnect"'
        $newBasicPSMContent = $psmBasicPSMContent -replace 'PSMServerAdminId=".+$', $psmBasicPSMAdminLine
        
        $newBasicPSMContent | Set-Content -Path "$psmRootInstallLocation\test_basic_psm.ini"
        
        
        # Write corrected contents out to correct file(s)
        #-------------------------
        Copy-Item -Path "$psmRootInstallLocation\Hardening\test-psm-applocker.ps1" -Destination "$psmRootInstallLocation\Hardening\PSMConfigureApplocker.ps1" -Force
        Copy-Item -Path "$psmRootInstallLocation\Hardening\test-psmhardening.ps1" -Destination "$psmRootInstallLocation\Hardening\PSMHardening.ps1" -Force
        Copy-Item -Path "$psmRootInstallLocation\test_basic_psm.ini" -Destination "$psmRootInstallLocation\basic_psm.ini" -Force
    }
    catch {
        Write-host "Failed to update PSM Config, please verify the files manually."
        Write-host $_
        Exit
    }
}

Function Invoke-PSMHardening {
    <#
    .SYNOPSIS
    Runs the PSMHardening script
    .DESCRIPTION
    Runs the PSMHardening script
    .PARAMETER psmRootInstallLocation
    PSM root installation folder
    #>
    param (
        [Parameter(Mandatory = $true)]
        $psmRootInstallLocation
    ) 
    Write-Verbose "Starting PSM Hardening"
    $hardeningScriptRoot = "$psmRootInstallLocation\Hardening"
    $CurrentLocation = Get-Location
    Set-Location $hardeningScriptRoot
    & "$hardeningScriptRoot\PSMHardening.ps1"
    Set-Location $CurrentLocation
}

Function Invoke-PSMConfigureAppLocker {
    <#
    .SYNOPSIS
    Runs the AppLocker PowerShell script
    .DESCRIPTION
    Runs the AppLocker PowerShell script
    .PARAMETER psmRootInstallLocation
    PSM root installation folder
    #>
    param (
        [Parameter(Mandatory = $true)]
        $psmRootInstallLocation
    ) 
    Write-Verbose "Starting PSMConfigureAppLocker"
    $hardeningScriptRoot = "$psmRootInstallLocation\Hardening"
    $CurrentLocation = Get-Location
    Set-Location $hardeningScriptRoot
    & "$hardeningScriptRoot\PSMConfigureAppLocker.ps1"
    Set-Location $CurrentLocation 
}

Function New-VaultAdminObject {
    <#
    .SYNOPSIS
    Onboards an account in the vault
    .DESCRIPTION
    Onboards an account in the vault
    .PARAMETER pvwaAddress
    Address of the PVWA
    .PARAMETER pvwaToken
    Token to log into PVWA using APIs
    .PARAMETER name
    Name of the account (PSMConnect/PSMAdminConnect)
    .PARAMETER domain
    Domain of the users needed to be onboarded
    .PARAMETER Credentials
    Credentials to be onboarded (has both the username and password)     
    .PARAMETER platformID
    The Platform to onboard the account to. We will use the PlatformID in this script from what we create.
    #>
    param (
        [Parameter(Mandatory = $true)]
        $pvwaAddress,
        [Parameter(Mandatory = $true)]
        $pvwaToken,
        [Parameter(Mandatory = $true)]
        $name,
        [Parameter(Mandatory = $true)]
        [String]$domain,
        [Parameter(Mandatory = $true)]
        [PSCredential]$Credentials,
        [Parameter(Mandatory = $true)]
        $platformID,
        [Parameter(Mandatory = $false)]
        $safe = "PSM"
    ) 
    
    $username = $Credentials.username.Replace('\', '')
    $password = $Credentials.GetNetworkCredential().password
    $body = @{
        name                      = $name
        address                   = $domain
        userName                  = $username
        safeName                  = $safe
        secretType                = "password"
        secret                    = $password
        platformID                = $platformID
        platformAccountProperties = @{"LogonDomain" = $domain }
    }
    $url = $pvwaAddress + "/PasswordVault/api/Accounts"
    $json = $body | ConvertTo-Json
    try {
        $result = Invoke-RestMethod -Method POST -Uri $url -Body $json -Headers @{ "Authorization" = $pvwaToken } -ContentType "application/json" -ErrorVariable ResultError
        return $result
    }
    catch {
        try {
            $ErrorMessage = $ResultError.Message | ConvertFrom-Json
            return $ErrorMessage
        }
        catch {
            Write-Error ("Error creating user: {0}" -f $ResultError.Message)
            exit 1
        }
    }
}

Function Add-AdminUserToTS {
    <#
    .SYNOPSIS
    Updates RDS settings to add the Admin Account.
    .DESCRIPTION
    Updates RDS settings to add the Admin Account. Ensures we can still do recording with PSMAdminConnect
    .PARAMETER NETBIOS
    NETBIOS of the domain user
    .PARAMETER Credentials
    Credential of the user to setup RDP for (mainly need the username)
    #>
    param (
        [Parameter(Mandatory = $true)]
        [String]$NETBIOS,
        [Parameter(Mandatory = $true)]
        [PSCredential]$Credentials,
        [Parameter(Mandatory = $true)]
        [switch]$IgnoreShadowPermissionErrors
    )
    $username = "{0}\{1}" -f $NETBIOS, $Credentials.username
    #    $cmd1 = "wmic.exe /namespace:\\root\CIMV2\TerminalServices PATH Win32_TSPermissionsSetting WHERE (TerminalName=""RDP-Tcp"") CALL AddAccount ""$NETBIOS\$username"",0"
    #    $cmd2 = "wmic.exe /namespace:\\root\cimv2\TerminalServices PATH Win32_TSAccount WHERE ""TerminalName='RDP-Tcp' AND AccountName='$NETBIOS\\$username'"" CALL ModifyPermissions TRUE,4"
    try {
        $RDPPermissionSetting = Get-WmiObject -Class "Win32_TSPermissionsSetting" -Namespace "root\CIMV2\terminalservices" | Where-Object TerminalName -eq "RDP-Tcp"
        return $RDPPermissionSetting.AddAccount($username, 0)

    }
    catch {
        return @{
            Error       = $_.Exception.Message
            ReturnValue = 1
        }
    }
}

Function Add-AdminUserTSShadowPermission {
    <#
    .SYNOPSIS
    Updates RDS settings to add the Admin Account.
    .DESCRIPTION
    Updates RDS settings to add the Admin Account. Ensures we can still do recording with PSMAdminConnect
    .PARAMETER NETBIOS
    NETBIOS of the domain user
    .PARAMETER Credentials
    Credential of the user to setup RDP for (mainly need the username)
    #>
    param (
        [Parameter(Mandatory = $true)]
        [String]$NETBIOS,
        [Parameter(Mandatory = $true)]
        [PSCredential]$Credentials,
        [Parameter(Mandatory = $true)]
        [switch]$IgnoreShadowPermissionErrors
    )
    $username = "{0}\{1}" -f $NETBIOS, $Credentials.username
    #    $cmd1 = "wmic.exe /namespace:\\root\CIMV2\TerminalServices PATH Win32_TSPermissionsSetting WHERE (TerminalName=""RDP-Tcp"") CALL AddAccount ""$NETBIOS\$username"",0"
    #    $cmd2 = "wmic.exe /namespace:\\root\cimv2\TerminalServices PATH Win32_TSAccount WHERE ""TerminalName='RDP-Tcp' AND AccountName='$NETBIOS\\$username'"" CALL ModifyPermissions TRUE,4"
    try {
        $RDPPermissionUserSetting = Get-WmiObject -Class "Win32_TSAccount" -Namespace "root\CIMV2\terminalservices" | Where-Object TerminalName -eq "RDP-Tcp" | Where-Object AccountName -eq $username
        return $RDPPermissionUserSetting.ModifyPermissions(4, $true)
    }
    catch {
        return @{
            Error       = $_.Exception.Message
            ReturnValue = 1
        }
    }
}

Function Duplicate-Platform {
    <#
    .SYNOPSIS
    Duplicating the windows domain user platform so we can onboard the accounts into that platform
    .DESCRIPTION
    Duplicating the windows domain user platform so we can onboard the accounts into that platform
    .PARAMETER pvwaAddress
    PVWA address to run API commands on
    .PARAMETER pvwaToken
    Token to authenticate into the PVWA
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$pvwaAddress,
        [Parameter(Mandatory = $true)]
        [string]$pvwaToken,
        [Parameter(Mandatory = $true)]
        [string]$NewPlatformName,
        [Parameter(Mandatory = $true)]
        [string]$NewPlatformDescription,
        [Parameter(Mandatory = $true)]
        [string]$CurrentPlatformId
    )
    try {
        $url = $pvwaAddress + "/PasswordVault/api/Platforms/Targets/$CurrentPlatformId/Duplicate"
        $body = @{ 
            Name        = $NewPlatformName
            Description = $NewPlatformDescription
        }
        $json = $body | ConvertTo-Json
        $null = Invoke-RestMethod -Method 'Post' -Uri $url -Body $json -Headers @{ 'Authorization' = $pvwaToken } -ContentType 'application/json'
    }
    catch {
        Write-Host "Error duplicating platform"
        Write-Host $_.ErrorDetails.Message
        exit 1
    }
}

Function Get-PlatformStatus {
    <#
    .SYNOPSIS
    Get the platform status to check whether it exists and is active
    .DESCRIPTION
    Get the platform status to check whether it exists and is active
    .PARAMETER pvwaAddress
    PVWA address to run API commands on
    .PARAMETER pvwaToken
    Token to authenticate into the PVWA
    .PARAMETER PlatformId
    ID (string) of platform to retrieve
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$pvwaAddress,
        [Parameter(Mandatory = $true)]
        [string]$pvwaToken,
        [Parameter(Mandatory = $true)]
        [string]$PlatformId
    
    )
    try {
        $url = $pvwaAddress + "/PasswordVault/api/Platforms/targets?search=" + $PlatformId
        $Getresult = Invoke-RestMethod -Method 'Get' -Uri $url -Headers @{ 'Authorization' = $pvwaToken } -ErrorAction SilentlyContinue -ErrorVariable GetPlatformError
        # This query returns a list of platforms where the name contains the search string. Find and return just the one with an exactly matching name.
        $TargetPlatform = $Getresult.Platforms | Where-Object Name -eq $PlatformId
        if ($TargetPlatform) {
            return $TargetPlatform
        }
        else {
            return $false 
        }
    }
    catch {
        Write-Host "Error getting platform status."
        Write-Host $_.ErrorDetails.Message
        exit 1
    }
}

Function Activate-Platform {
    <#
    .SYNOPSIS
    Activate the required platform
    .DESCRIPTION
    Activate the required platform
    .PARAMETER pvwaAddress
    PVWA address to run API commands on
    .PARAMETER pvwaToken
    Token to authenticate into the PVWA
    .PARAMETER PlatformNumId
    Numeric ID of platform to activate
    #>
    param (
        [Parameter(Mandatory = $true)]
        $pvwaAddress,
        [Parameter(Mandatory = $true)]
        $pvwaToken,
        [Parameter(Mandatory = $true)]
        [string]$PlatformNumId
    )
    try {
        $url = $pvwaAddress + "/PasswordVault/api/Platforms/Targets/$PlatformNumId/activate"
        $null = Invoke-RestMethod -Method 'Post' -Uri $url -Headers @{ 'Authorization' = $pvwaToken } -ContentType 'application/json'
    }
    catch {
        Write-Host "Error activating platform"
        Write-Host $_.ErrorDetails.Message
        exit 1
    }
}
Function Set-SafePermissionsFull {
    <#
    .SYNOPSIS
    Adds safe permission to a specific safe
    .DESCRIPTION
    Adds safe permission to a specific safe
    .PARAMETER pvwaAddress
    PVWA address to run API commands on
    .PARAMETER pvwaToken
    Token to authenticate into the PVWA
    .PARAMETER safe
    Which Safe to give permission to (Default PSM)
    .PARAMETER SafeMember
    Which Member to give the safe permission
    .PARAMETER memberType
    What type of member to give permission to (group,role,user)    
    #>
    param (
        [Parameter(Mandatory = $true)]
        $pvwaAddress,
        [Parameter(Mandatory = $true)]
        $pvwaToken,
        [Parameter(Mandatory = $false)]
        $safe = "PSM",
        [Parameter(Mandatory = $false)]
        $SafeMember = "Vault Admins",
        [Parameter(Mandatory = $false)]
        $memberType = "Group"   
    )
    try {
        $url = $pvwaAddress + "/PasswordVault/api/Safes/$safe/members"
        $body = @{ 
            memberName  = $SafeMember
            memberType  = $memberType
            permissions = @{
                useAccounts                            = $True 
                retrieveAccounts                       = $True
                listAccounts                           = $True
                addAccounts                            = $True 
                updateAccountContent                   = $True
                updateAccountProperties                = $True
                initiateCPMAccountManagementOperations = $True
                specifyNextAccountContent              = $True
                renameAccounts                         = $True
                deleteAccounts                         = $True
                unlockAccounts                         = $True
                manageSafe                             = $True
                manageSafeMembers                      = $True
                backupSafe                             = $True
                viewAuditLog                           = $True
                viewSafeMembers                        = $True
                accessWithoutConfirmation              = $True
                createFolders                          = $True
                deleteFolders                          = $True
                moveAccountsAndFolders                 = $True
                requestsAuthorizationLevel1            = $True 
                requestsAuthorizationLevel2            = $False
            }
        }
        $json = $body | ConvertTo-Json
        $null = Invoke-RestMethod -Method 'Post' -Uri $url -Body $json -Headers @{ 'Authorization' = $pvwaToken } -ContentType 'application/json'
    }
    catch {
        Write-Host $_.ErrorDetails.Message 
    }
}

Function Check-UM {
    <#
    .SYNOPSIS
    Checks to see if tenant is UM or not (from the connector server)
    .DESCRIPTION
    Checks to see if tenant is UM or not (from the connector server)
    .PARAMETER psmRootInstallLocation
    PSM Folder
    #>
    param (
        [Parameter(Mandatory = $true)]
        $psmRootInstallLocation
    )
    $psmBasicPSMContent = Get-Content -Path $psmRootInstallLocation\basic_psm.ini 
    $validation = $psmBasicPSMContent -match "IdentityUM.*=.*Yes"
    return ("" -ne $validation) 
}

#Running Set-DomainUser script

if ($null -eq $psmConnectCredentials) {
    $psmConnectCredentials = Get-Credential -Message "Please enter PSMConnect domain user credentials"
    if (!($psmConnectCredentials)) {
        Write-Error "No credentials provided. Exiting."
        exit 1
    }
}

if ($TestPsmConnectCredentials) {
    if (ValidateCredentials -domain $domain -Credential $psmConnectCredentials) {
        Write-Host "PSMConnect user credentials validated"
    }
    else {
        Write-Error "PSMConnect user validation failed. Please validate PSMConnect user name and password or remove -TestPsmConnectCredentials to skip this test"
        exit 1
    }
}

if ($null -eq $psmAdminCredentials) {
    $psmAdminCredentials = Get-Credential -Message "Please enter PSMAdminConnect domain user credentials"
    if (!($psmAdminCredentials)) {
        Write-Error "No credentials provided. Exiting."
        exit 1
    }
}

if ($TestPsmAdminCredentials) {
    if (ValidateCredentials -domain $domain -Credential $psmAdminCredentials) {
        Write-Host "PSMAdminConnect user credentials validated"
    }
    else {
        Write-Error "PSMAdminConnect user validation failed. Please validate PSMConnect user name and password or remove -TestPsmAdminCredentials to skip this test."
        exit 1
    }
}

$REGKEY_PSMSERVICE = "Cyber-Ark Privileged Session Manager"
$psmRootInstallLocation = ($(Get-ServiceInstallPath $REGKEY_PSMSERVICE)).Replace("CAPSM.exe", "").Replace('"', "").Trim()

If (Check-UM -psmRootInstallLocation $psmRootInstallLocation) {
    $UM = $true
}
else { 
    $UM = $false
}

if ($null -eq $tinaCreds) {
    if ($UM) {
        $TinaUserType = "installer user"
    }
    else {
        $TinaUserType = "tenant administrator"
    }
    $tinaCreds = Get-Credential -Message ("Please enter {0} credentials" -f $TinaUserType)
    if (!($tinaCreds)) {
        Write-Error "No credentials provided. Exiting."
        exit 1
    }
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$BackupSuffix = (Get-Date).ToString('yyyMMdd-HHmmss')
$DomainNameAutodetected = $false

$Tasks = @(
    "Configure PSM to use the domain PSM accounts"
    "Modify local/group policies to allow PSM users to use Remote Desktop"
)

if (IsUserDomainJoined) {
    # Get-Variables
    Write-Host "Getting PVWA address"
    $pvwaAddress = Get-PvwaAddress -psmRootInstallLocation $psmRootInstallLocation
    Write-Host "Getting domain details"
    if (!($domain)) {
        $DomainNameAutodetected = $true
        $domain = Get-DomainDnsName
    }
    if (!($NETBIOS)) {
        $DomainNameAutodetected = $true
        $NETBIOS = Get-DomainNetbiosName
    }
    If ($DomainNameAutodetected) {
        Write-Host "Detected the following domain names. Is this correct?"
        Write-Host "DNS name:     $domain"
        Write-Host "NETBIOS name: $NETBIOS"
        $DomainConfirmPrompt = Read-Host "Please type 'y' for yes or 'n' for no."
        if ($DomainConfirmPrompt -ne 'y') {
            Write-Host "Please rerun the script and provide the correct domain DNS and NETBIOS names on the command line."
            exit 1
        }
    }
    Write-Host "Logging in to CyberArk"
    $pvwaToken = New-ConnectionToRestAPI -pvwaAddress $pvwaAddress -tinaCreds $tinaCreds
    if (Test-PvwaToken -Token $pvwaToken -pvwaAddress $pvwaAddress) {
        # Get platform info
        Write-Host "Checking current platform status"
        $platformStatus = Get-PlatformStatus -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken -PlatformId $PlatformName
        if ($platformStatus -eq $false) {
            # function returns false if platform does not exist
            # Creating Platform
            Write-Host "Creating new platform"
            Duplicate-Platform -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken -CurrentPlatformId "7" -NewPlatformName $PlatformName -NewPlatformDescription "Platform for PSM accounts"
            $Tasks += ("Set appropriate policies and settings on platform `"{0}`"" -f $PlatformName)
            # Get platform info again so we can ensure it's activated
            $platformStatus = Get-PlatformStatus -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken -PlatformId $PlatformName
        }
        else {
            Write-Warning ('Platform {0} already exists. Please verify it meets requirements.' -f $PlatformName)
            $Tasks += ("Verify that the existing platform `"{0}`" is configured correctly" -f $PlatformName)
        }
        if ($platformStatus.Active -eq $false) {
            Write-Host "Platform is deactivated. Activating."
            Activate-Platform -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken -Platform $platformStatus.Id
        }
        # Giving Permission on the safe if we are using UM, The below will give full permission to vault admins
        If ($UM) {
            Write-Host "Granting administrators access to PSM safe"
            Set-SafePermissionsFull -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken -safe $safe
        }
        # Creating PSMConnect, We can now add a safe need as well for the below line if we have multiple domains
        Write-Host "Onboarding PSMConnect Account"
        $OnboardResult = New-VaultAdminObject -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken -name $PSMConnectAccountName -domain $domain -Credentials $psmConnectCredentials -platformID $PlatformName -safe $safe
        If ($OnboardResult.name) {
            Write-Host "User successfully onboarded"
        }
        ElseIf ($OnboardResult.ErrorCode -eq "PASWS027E") {
            Write-Warning "Object with name $PSMConnectAccountName already exists. Please verify that it contains correct account details, or specify an alternative account name."
            $Tasks += "Verify that the $PSMConnectAccountName object in $safe safe contains correct PSMConnect user details"
        } 
        Else {
            Write-Error "Error onboarding account: {0}" -f $OnboardResult
            exit 1
        }
        # Creating PSMAdminConnect
        Write-Host "Onboarding PSMAdminConnect Account"
        $OnboardResult = New-VaultAdminObject -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken -name $PSMAdminConnectAccountName -domain $domain -Credentials $psmAdminCredentials -platformID $PlatformName -safe $safe
        If ($OnboardResult.name) {
            Write-Host "User successfully onboarded"
        }
        ElseIf ($OnboardResult.ErrorCode -eq "PASWS027E") {
            Write-Warning "Object with name $PSMAdminConnectAccountName already exists. Please verify that it contains correct account details, or specify an alternative account name."
            $Tasks += "Verify that the $PSMAdminConnectAccountName object in $safe safe contains correct PSMAdminConnect user details"
        } 
        Else {
            Write-Error "Error onboarding account: {0}" -f $OnboardResult
            exit 1
        }
        Write-Host "Stopping CyberArk Privileged Session Manager Service"
        Stop-Service $REGKEY_PSMSERVICE
        Write-Host "Backing up PSM configuration files and scripts"
        Backup-PSMConfig -psmRootInstallLocation $psmRootInstallLocation -BackupSuffix $BackupSuffix
        Write-Host "Updating PSM configuration files and scripts"
        Update-PSMConfig -psmRootInstallLocation $psmRootInstallLocation -domain $domain -PsmConnectUsername $psmConnectCredentials.username.Replace('\', '') -PsmAdminUsername $psmAdminCredentials.username.Replace('\', '')
        #TODO: Update Basic_ini
        Write-Host "Adding PSMAdminConnect user to Terminal Services configuration"
        # Adding PSMAdminConnect user to Terminal Services configuration
        $AddAdminUserToTSResult = Add-AdminUserToTS -NETBIOS $NETBIOS -Credentials $psmAdminCredentials -IgnoreShadowPermissionErrors:$IgnoreShadowPermissionErrors
        If ($AddAdminUserToTSResult.ReturnValue -eq 0) {
            Write-Host "Successfully added PSMAdminConnect user to Terminal Services configuration"
            # Grant shadow permission only if first command was succesful
            Write-Host "Granting PSMAdminConnect user permission to shadow sessions"
            $AddAdminUserTSShadowPermissionResult = Add-AdminUserTSShadowPermission -NETBIOS $NETBIOS -Credentials $psmAdminCredentials -IgnoreShadowPermissionErrors:$IgnoreShadowPermissionErrors
            If ($AddAdminUserTSShadowPermissionResult.ReturnValue -eq 0) {
                Write-Host "Successfully granted PSMAdminConnect permission to shadow sessions"
            }
            else {
                # Failed to grant permission (2nd command)
                Write-Host $AddAdminUserTSShadowPermissionResult.Error
                Write-Warning "Failed to grant PSMAdminConnect permission to shadow sessions."
                if ($IgnoreShadowPermissionErrors) {
                    Write-Host "Continuing because `"-IgnoreShadowPermissionErrors`" switch enabled"  
                    $Tasks += "Resolve issue preventing PSMAdminConnect user being granted permission to shadow sessions and rerun this script"

                }
                else {
                    Write-Host "Run this script with the `"-IgnoreShadowPermissionErrors`" switch to ignore this error"
                    Write-Host "Exiting."
                    exit 1
                }
            }
        }
        else {
            # Failed to add user (1st command)
            write-host $AddAdminUserToTSResult.Error
            Write-Host "Failed to add PSMAdminConnect user to Terminal Services."
            if ($IgnoreShadowPermissionErrors) {
                Write-Host "Continuing because `"-IgnoreShadowPermissionErrors`" switch enabled"
                $Tasks += "Resolve issue preventing PSMAdminConnect user being added to Terminal Services configuration and rerun this script"

            }
            else {
                Write-Host "Run this script with the `"-IgnoreShadowPermissionErrors`" switch to ignore this error"
                Write-Host "Exiting."
                exit 1
            }
        }
        Write-Host "Running PSM Hardening script"
        Invoke-PSMHardening -psmRootInstallLocation $psmRootInstallLocation
        Write-Host "Running PSM Configure AppLocker script"
        Invoke-PSMConfigureAppLocker -psmRootInstallLocation $psmRootInstallLocation
        Write-Host "Restarting CyberArk Privileged Session Manager Service"
        Restart-Service $REGKEY_PSMSERVICE
        Write-Host ""
        Write-Host "All tasks completed. The following additional steps may be required:"
        $Tasks += "Restart Server"
        foreach ($Task in $Tasks) {
            Write-Host " - $Task"
        }
    }
    else {
        Write-Host "PVWA Token validation failed."
        exit 1
    }
}
else {
    Write-Host "Stopping. Please run this script as a domain user"
}
