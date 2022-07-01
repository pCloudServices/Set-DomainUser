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
.PARAMETER DoNotHarden
Skip running the PSMHardening.ps1 script to speed up execution if step has already been completed.
.PARAMETER DoNotConfigureAppLocker
Skip running the PSMConfigureAppLocker.ps1 script to speed up execution if step has already been completed.
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
    [String]$PSMAdminConnectAccountName = "PSMAdminConnect",
    [Parameter(
        Mandatory = $false)]
    [switch]$DoNotHarden,
    [Parameter(
        Mandatory = $false)]
    [switch]$DoNotConfigureAppLocker
)

#Functions
Function Get-RestMethodError {
    <# Invoke-RestMethod can have several different possible results
    Connection failure: The connection error will be contained in $_.Exception.Message
    Successful connection:
        200 result
            The request was successful: This function should not be called in this case
        Some other result
            JSON data returned: We should return the JSON, contained in $_.ErrorDetails.Message
            non-JSON data returned: We should return the non-JSON data, contained in $_.ErrorDetails.Message

    TODO: Convert other functions to use this function to return useful errors.
    This is lower priority as, if New-ConnectionToRestAPI and Test-PvwaToken succeed,
    others are unlikely to have issues.

    NOTE: This function should only be called if Invoke-RestMethod fails.
    Do not use it to catch errors from any other commands.
    #>
    param(
        [Parameter(Mandatory = $true)][System.Management.Automation.ErrorRecord]$ErrorRecord
    )
    If ($ErrorRecord.ErrorDetails.Message) {
        # If the connection was successful but the server returned a non-200 result, Invoke-RestMethod will treat it as an error.
        # But if it's valid JSON, we'd rather know what the server said than what Invoke-RestMethod thought about it.
        try {
            return $ErrorRecord.ErrorDetails.Message | ConvertFrom-Json
        }
        catch {
            # Doesn't seem to have been valid JSON, so we'll construct our own object with the server's response (which is in the ErrorDetails property)
            return @{
                ErrorCode    = "Unknown"
                ErrorMessage = $ErrorRecord.ErrorDetails.Message
            }
        }
    }
    else {
        # If there's no ErrorDetails.Message property, likely the connection failed entirely, so we'll return something based on the Exception.Message instead, which will be what Invoke-RestMethod thought.
        return @{
            ErrorCode    = "Unknown"
            ErrorMessage = $ErrorRecord.Exception.Message
        }
    }
}

Function Write-LogMessage {
    <# 
.SYNOPSIS 
	Method to log a message on screen and in a log file

.DESCRIPTION
	Logging The input Message to the Screen and the Log File. 
	The Message Type is presented in colours on the screen based on the type

.PARAMETER LogFile
	The Log File to write to. By default using the LOG_FILE_PATH
.PARAMETER MSG
	The message to log
.PARAMETER Header
	Adding a header line before the message
.PARAMETER SubHeader
	Adding a Sub header line before the message
.PARAMETER Footer
	Adding a footer line after the message
.PARAMETER Type
	The type of the message to log (Info, Warning, Error, Debug)
#>
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowEmptyString()]
        [String]$MSG,
        [Parameter(Mandatory = $false)]
        [Switch]$Header,
        [Parameter(Mandatory = $false)]
        [Switch]$Early,
        [Parameter(Mandatory = $false)]
        [Switch]$SubHeader,
        [Parameter(Mandatory = $false)]
        [Switch]$Footer,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Debug", "Verbose", "Success", "LogOnly")]
        [String]$type = "Info",
        [Parameter(Mandatory = $false)]
        [String]$LogFile = $LOG_FILE_PATH
    )
    Try {
        If ($Header) {
            "=======================================" | Out-File -Append -FilePath $LogFile 
            Write-Host "=======================================" -ForegroundColor Magenta
        }
        ElseIf ($SubHeader) { 
            "------------------------------------" | Out-File -Append -FilePath $LogFile 
            Write-Host "------------------------------------" -ForegroundColor Magenta
        }
		
        $msgToWrite = "[$(Get-Date -Format "yyyy-MM-dd hh:mm:ss")]`t"
        $writeToFile = $true
        # Replace empty message with 'N/A'
        if ([string]::IsNullOrEmpty($Msg)) { $Msg = "N/A" }
		
        # Mask Passwords
        if ($Msg -match '((?:password|credentials|secret)\s{0,}["\:=]{1,}\s{0,}["]{0,})(?=([\w`~!@#$%^&*()-_\=\+\\\/|;:\.,\[\]{}]+))') {
            $Msg = $Msg.Replace($Matches[2], "****")
        }
        # Check the message type
        switch ($type) {
            { ($_ -eq "Info") -or ($_ -eq "LogOnly") } { 
                If ($_ -eq "Info") {
                    Write-Host $MSG.ToString() -ForegroundColor $(If ($Header -or $SubHeader) { "magenta" } Elseif ($Early) { "DarkGray" } Else { "White" })
                }
                $msgToWrite += "[INFO]`t$Msg"
            }
            "Success" { 
                Write-Host $MSG.ToString() -ForegroundColor Green
                $msgToWrite += "[SUCCESS]`t$Msg"
            }
            "Warning" {
                Write-Host $MSG.ToString() -ForegroundColor Yellow
                $msgToWrite += "[WARNING]`t$Msg"
            }
            "Error" {
                Write-Host $MSG.ToString() -ForegroundColor Red
                $msgToWrite += "[ERROR]`t$Msg"
            }
            "Debug" { 
                if ($InDebug -or $InVerbose) {
                    Write-Debug $MSG
                    $msgToWrite += "[DEBUG]`t$Msg"
                }
                else { $writeToFile = $False }
            }
            "Verbose" { 
                if ($InVerbose) {
                    Write-Verbose -Msg $MSG
                    $msgToWrite += "[VERBOSE]`t$Msg"
                }
                else { $writeToFile = $False }
            }
        }

        If ($writeToFile) { $msgToWrite | Out-File -Append -FilePath $LogFile }
        If ($Footer) { 
            "=======================================" | Out-File -Append -FilePath $LogFile 
            Write-Host "=======================================" -ForegroundColor Magenta
        }
    }
    catch {
        Throw $(New-Object System.Exception ("Cannot write message"), $_.Exception)
    }
}

Function Get-DomainDnsName {
    if ($env:USERDNSDOMAIN) {
        return $env:USERDNSDOMAIN
    }
    else {
        Write-LogMessage -Type Error -MSG "Unable to determine domain DNS name. Please provide it on the command line."
        exit 1
    }
}

Function Get-DomainNetbiosName {
    if ($env:USERDOMAIN) {
        return $env:USERDOMAIN
    }
    else {
        Write-LogMessage -Type Error -MSG "Unable to determine domain NETBIOS name. Please provide it on the command line."
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
        $null = $VaultIniAddressesLine -match "(https://[0-9a-zA-Z][\.\-0-9a-zA-Z]*)"
        $Address = $Matches[0]
        If (!($Address)) {
            Throw
        }
        return $Address
    }
    catch {
        Write-LogMessage -Type Error -MSG "Unable to detect PVWA address automatically. Please rerun script and provide it using the -PvwaAddress parameter."
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
        $Result = Invoke-RestMethod -Method 'Post' -Uri $url -Body $json -ContentType 'application/json'
        return @{
            ErrorCode = "Success"
            Response  = $Result
        }
    }
    Catch {
        return Get-RestMethodError $_
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
        Authorization = $Token
    }
    $testToken = Invoke-RestMethod -Method 'Get' -Uri $url -Headers $Headers -ContentType 'application/json'
    if ($testToken) {
        return @{
            ErrorCode = "Success"
        }
    }
    Catch {
        return Get-RestMethodError $_
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
            Write-LogMessage -Type Error -MSG "Failed to backup PSMHardening.ps1" -ErrorAction Stop
        }
        ElseIf (!(Test-Path $PSMConfigureAppLockerBackupFileName)) {
            Write-LogMessage -Type Error -MSG "Failed to backup PSMConfigureAppLocker.ps1" -ErrorAction Stop
        }
        ElseIf (!(Test-Path $BasicPSMBackupFileName )) {
            Write-LogMessage -Type Error -MSG "Failed to backup basic_psm.ini" -ErrorAction Stop
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
        Write-LogMessage -Type Error -MSG "Failed to update PSM Config, please verify the files manually."
        Write-LogMessage -Type Error -MSG $_
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
            Write-LogMessage -Type Error -MSG ("Error creating user: {0}" -f $ResultError.Message)
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
        [PSCredential]$Credentials
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
        [PSCredential]$Credentials
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
        Write-LogMessage -Type Error -MSG "Error duplicating platform"
        Write-LogMessage -Type Error -MSG $_.Exception.Message
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
        Write-LogMessage -Type Error -MSG "Error getting platform status."
        Write-LogMessage -Type Error -MSG $_.ErrorDetails.Message
        exit 1
    }
}

Function Get-SafeStatus {
    <#
    .SYNOPSIS
    Get the safe status to check whether it exists and is active
    .DESCRIPTION
    Get the safe status to check whether it exists and is active
    .PARAMETER pvwaAddress
    PVWA address to run API commands on
    .PARAMETER pvwaToken
    Token to authenticate into the PVWA
    .PARAMETER SafeName
    Name of safe to retrieve
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$pvwaAddress,
        [Parameter(Mandatory = $true)]
        [string]$pvwaToken,
        [Parameter(Mandatory = $true)]
        [string]$SafeName

    )
    try {
        $url = $pvwaAddress + "/PasswordVault/api/safes?search=$SafeName"
        $SafeRequest = Invoke-RestMethod -Method 'Get' -Uri $url -Headers @{ 'Authorization' = $pvwaToken } -ErrorAction SilentlyContinue
        # This query returns a list of safes where the name contains the search string. Find and return just the one with an exactly matching name.
        $Safe = $SafeRequest.Value | Where-Object safeName -eq $SafeName
        if ($Safe) {
            return $Safe
        }
        else {
            return $false
        }
    }
    catch {
        Write-LogMessage -Type Error -MSG "Error getting safe status."
        Write-LogMessage -Type Error -MSG $_.ErrorDetails.Message
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
        Write-LogMessage -Type Error -MSG "Error activating platform"
        Write-LogMessage -Type Error -MSG $_.ErrorDetails.Message
        exit 1
    }
}

Function Create-PSMSafe {
    <#
    .SYNOPSIS
    Creates a new PSM Safe with correct permissions
    .DESCRIPTION
    Creates a new PSM safe with correct permissions
    .PARAMETER pvwaAddress
    PVWA address to run API commands on
    .PARAMETER pvwaToken
    Token to authenticate into the PVWA
    .PARAMETER safe
    Safe Name to create
    #>
    param (
        [Parameter(Mandatory = $true)]
        $pvwaAddress,
        [Parameter(Mandatory = $true)]
        $pvwaToken,
        [Parameter(Mandatory = $false)]
        $safe,
        [Parameter(Mandatory = $false)]
        $description = "Safe for PSM Users"  
    )
    try {
        $url = $pvwaAddress + "/PasswordVault/api/Safes"
        $body = @{ 
            safeName    = $safe
            description = $description
        }
        $json = $body | ConvertTo-Json    
        $null = Invoke-RestMethod -Method 'Post' -Uri $url -Body $json -Headers @{ 'Authorization' = $pvwaToken } -ContentType 'application/json'
        #Permissions for the needed accounts
        #PSMMaster full permissions
        New-SafePermissions -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken -safe $safe -safeMember "PSMMaster"
        #PVWAAppUser and PVWAAppUsers permissions
        $PVWAAppUser = @{
            useAccounts                            = $False 
            retrieveAccounts                       = $True
            listAccounts                           = $True
            addAccounts                            = $False 
            updateAccountContent                   = $True
            updateAccountProperties                = $False
            initiateCPMAccountManagementOperations = $False
            specifyNextAccountContent              = $False
            renameAccounts                         = $False
            deleteAccounts                         = $False
            unlockAccounts                         = $False
            manageSafe                             = $False
            manageSafeMembers                      = $False
            backupSafe                             = $False
            viewAuditLog                           = $False
            viewSafeMembers                        = $False
            accessWithoutConfirmation              = $False
            createFolders                          = $False
            deleteFolders                          = $False
            moveAccountsAndFolders                 = $False
            requestsAuthorizationLevel1            = $False 
            requestsAuthorizationLevel2            = $False
        }
        New-SafePermissions -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken -safe $safe -safeMember "PVWAAppUser" -memberType "user" -safePermissions $PVWAAppUser
        New-SafePermissions -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken -safe $safe -safeMember "PVWAAppUsers" -safePermissions $PVWAAppUser
        #PSMAppUsers
        $PSMAppUsers = @{
            useAccounts                            = $False 
            retrieveAccounts                       = $True
            listAccounts                           = $True
            addAccounts                            = $False 
            updateAccountContent                   = $False
            updateAccountProperties                = $False
            initiateCPMAccountManagementOperations = $False
            specifyNextAccountContent              = $False
            renameAccounts                         = $False
            deleteAccounts                         = $False
            unlockAccounts                         = $False
            manageSafe                             = $False
            manageSafeMembers                      = $False
            backupSafe                             = $False
            viewAuditLog                           = $False
            viewSafeMembers                        = $False
            accessWithoutConfirmation              = $False
            createFolders                          = $False
            deleteFolders                          = $False
            moveAccountsAndFolders                 = $False
            requestsAuthorizationLevel1            = $False 
            requestsAuthorizationLevel2            = $False
        }
        Set-SafePermissions -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken -safe $safe -safeMember "PSMAppUsers" -safePermissions $PSMAppUsers  
        return $true      
    }
    catch {
        Write-LogMessage -Type Error $_.ErrorDetails.Message
        return $false
    }
}

Function Set-SafePermissions {
    <#
    .SYNOPSIS
    Update a member's safe permission on a specific safe
    .DESCRIPTION
    Update a member's safe permission on a specific safe
    .PARAMETER pvwaAddress
    PVWA address to run API commands on
    .PARAMETER pvwaToken
    Token to authenticate into the PVWA
    .PARAMETER safe
    Which Safe to give permission to (Default PSM)
    .PARAMETER SafeMember
    Which Member to give the safe permission
    #>
    param (
        [Parameter(Mandatory = $true)]
        $pvwaAddress,
        [Parameter(Mandatory = $true)]
        $pvwaToken,
        [Parameter(Mandatory = $false)]
        $safe = "PSM",
        [Parameter(Mandatory = $false)]
        $safeMember = "Vault Admins",
        [Parameter(Mandatory = $false)]
        $memberType = "Group",
        [Parameter(Mandatory = $false)]
        $safePermissions = @{
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
    )
    try {
        $url = $pvwaAddress + "/PasswordVault/api/Safes/$safe/members/$SafeMember"
        $body = @{ 
            permissions = $safePermissions
        }
        $json = $body | ConvertTo-Json
        $null = Invoke-RestMethod -Method 'Put' -Uri $url -Body $json -Headers @{ 'Authorization' = $pvwaToken } -ContentType 'application/json'
    }
    catch {
        Write-LogMessage -Type Error -MSG $_.ErrorDetails.Message 
    }
}

Function New-SafePermissions {
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
        $safeMember = "Vault Admins",
        [Parameter(Mandatory = $false)]
        $memberType = "Group",
        [Parameter(Mandatory = $false)]
        $safePermissions = @{
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
    )
    try {
        $url = $pvwaAddress + "/PasswordVault/api/Safes/$safe/members"
        $body = @{
            memberName  = $SafeMember
            memberType  = $memberType
            permissions = $safePermissions
        }
        $json = $body | ConvertTo-Json
        $null = Invoke-RestMethod -Method 'Post' -Uri $url -Body $json -Headers @{ 'Authorization' = $pvwaToken } -ContentType 'application/json'
    }
    catch {
        Write-LogMessage -Type Error -MSG $_.ErrorDetails.Message
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
Function Get-PSMServerId {
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
    $PsmServerIdLine = Get-Content -Path $psmRootInstallLocation\basic_psm.ini | Where-Object { $_ -like 'PSMServerId="*"' }
    $null = $PsmServerIdLine -match 'PSMServerId="(.*)"$'
    return $Matches[1]
}

function Test-CredentialFormat {
    param (
        [Parameter(Mandatory = $true)][PSCredential]$Credential
    )
    if ($Credential.username -match '[/\\\[\]:;|=,+*?<>@"]') {
        return $false
    }
    return $true
}

#Running Set-DomainUser script

$global:InVerbose = $PSBoundParameters.Verbose.IsPresent
$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path
$global:LOG_FILE_PATH = "$ScriptLocation\_Set-DomainUser.log"

if ($null -eq $psmConnectCredentials) {
    $psmConnectCredentials = Get-Credential -Message "Please enter PSMConnect domain user credentials"
    if (!($psmConnectCredentials)) {
        Write-LogMessage -Type Error -MSG "No credentials provided. Exiting."
        exit 1
    }
}

if ($null -eq $psmAdminCredentials) {
    $psmAdminCredentials = Get-Credential -Message "Please enter PSMAdminConnect domain user credentials"
    if (!($psmAdminCredentials)) {
        Write-LogMessage -Type Error -MSG "No credentials provided. Exiting."
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
        Write-LogMessage -Type Error -MSG "No credentials provided. Exiting."
        exit 1
    }
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$BackupSuffix = (Get-Date).ToString('yyyMMdd-HHmmss')
$DomainNameAutodetected = $false

$Tasks = @(
    "Modify local/group policies to allow PSM users to use Remote Desktop"
)

Write-LogMessage -Type Info -MSG "Gathering information"

Write-LogMessage -Type Verbose -MSG "Checking if user is a domain user"
if (IsUserDomainJoined) {
    Write-LogMessage -Type Verbose -MSG "User is a domain user"
}
else {
    Write-LogMessage -Type Error -MSG "Stopping. Please run this script as a domain user"
    exit 1
}

# Test if PSM credentials were entered in the right format

Write-LogMessage -Type Verbose -MSG "Verifying PSM credentials were provided in expected format"
If (!(Test-CredentialFormat -Credential $psmConnectCredentials)) {
    Write-LogMessage -Type Error -MSG "Username provided for PSMConnect user contained invalid characters."
    Write-LogMessage -Type Error -MSG "Please provide the pre-Windows 2000 username without DOMAIN\ or @domain."
    exit 1

}

If (!(Test-CredentialFormat -Credential $psmAdminCredentials)) {
    Write-LogMessage -Type Error -MSG "Username provided for PSMAdminConnect user contained invalid characters."
    Write-LogMessage -Type Error -MSG "Please provide the pre-Windows 2000 username without DOMAIN\ or @domain."
    exit 1

}

# Get-Variables
if (!($pvwaAddress)) {
    Write-LogMessage -Type Verbose -MSG "Getting PVWA address"
    $pvwaAddress = Get-PvwaAddress -psmRootInstallLocation $psmRootInstallLocation
}
Write-LogMessage -Type Verbose -MSG "Getting domain details"
if (!($domain)) {
    $DomainNameAutodetected = $true
    $domain = Get-DomainDnsName
}
if (!($NETBIOS)) {
    $DomainNameAutodetected = $true
    $NETBIOS = Get-DomainNetbiosName
}
If ($DomainNameAutodetected) {
    Write-LogMessage -Type Info -MSG "Detected the following domain names. Is this correct?"
    Write-LogMessage -Type Info -MSG "DNS name:     $domain"
    Write-LogMessage -Type Info -MSG "NETBIOS name: $NETBIOS"
    $DomainConfirmPrompt = Read-Host "Please type 'y' for yes or 'n' for no."
    if ($DomainConfirmPrompt -ne 'y') {
        Write-LogMessage -Type Error -MSG "Please rerun the script and provide the correct domain DNS and NETBIOS names on the command line."
        exit 1
    }
    Write-LogMessage -Type Info "Domain details confirmed"
}

# Test PSM credentials
if ($TestPsmConnectCredentials) {
    if (ValidateCredentials -domain $domain -Credential $psmConnectCredentials) {
        Write-LogMessage -Type Verbose -MSG "PSMConnect user credentials validated"
    }
    else {
        Write-LogMessage -Type Error -MSG "PSMConnect user validation failed. Please validate PSMConnect user name and password or remove -TestPsmConnectCredentials to skip this test"
        exit 1
    }
}

if ($TestPsmAdminCredentials) {
    if (ValidateCredentials -domain $domain -Credential $psmAdminCredentials) {
        Write-LogMessage -Type Verbose -MSG "PSMAdminConnect user credentials validated"
    }
    else {
        Write-LogMessage -Type Error -MSG "PSMAdminConnect user validation failed. Please validate PSMConnect user name and password or remove -TestPsmAdminCredentials to skip this test."
        exit 1
    }
}

# Reverse logic on script invocation setting because double negatives suck
$DoHardening = !$DoNotHarden
$DoConfigureAppLocker = !$DoNotConfigureAppLocker

Write-Host "Logging in to CyberArk"
$pvwaTokenResponse = New-ConnectionToRestAPI -pvwaAddress $pvwaAddress -tinaCreds $tinaCreds
if ($pvwaTokenResponse.ErrorCode -ne "Success") {
    # ErrorCode will always be "Success" if Invoke-RestMethod got a 200 response from server.
    # If it's anything else, it will have been caught by New-ConnectionToRestAPI error handler and an error response generated.
    # The error message shown could be from a JSON response, e.g. wrong password, or a connection error.
    Write-LogMessage -Type Error "Logon to PVWA failed. Result:"
    Write-LogMessage -Type Error ("Error code: {0}" -f $pvwaTokenResponse.ErrorCode)
    Write-LogMessage -Type Error ("Error message: {0}" -f $pvwaTokenResponse.ErrorMessage)
    exit 1
}
if (!($pvwaTokenResponse.Response -match "[0-9a-zA-Z]{200,256}")) {
    # If we get here, it means we got a 200 response from the server, but the data it returned was not a valid token.
    # In this case, we display the response we got from the server to aid troubleshooting.
    Write-LogMessage -Type Error "Response from server was not a valid token:"
    Write-LogMessage -Type Error $pvwaTokenResponse.Response
    exit 1
}
# If we get here, the token was retrieved successfully and looks valid. We'll still test it though.
$PvwaTokenTestResponse = Test-PvwaToken -Token $pvwaTokenResponse.Response -pvwaAddress $pvwaAddress
if ($PvwaTokenTestResponse.ErrorCode -eq "Success") {
    $pvwaToken = $pvwaTokenResponse.Response
}
else {
    Write-LogMessage -Type Error -MSG "PVWA Token validation failed. Result:"
    Write-LogMessage -Type Error -MSG $PvwaTokenTestResponse.Response
    exit 1
}
# Get platform info
Write-LogMessage -Type Verbose -MSG "Checking current platform status"
$platformStatus = Get-PlatformStatus -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken -PlatformId $PlatformName
if ($platformStatus -eq $false) {
    # function returns false if platform does not exist
    # Creating Platform
    Write-LogMessage -Type Verbose -MSG "Creating new platform"
    Duplicate-Platform -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken -CurrentPlatformId "7" -NewPlatformName $PlatformName -NewPlatformDescription "Platform for PSM accounts"
    $Tasks += ("Set appropriate policies and settings on platform `"{0}`"" -f $PlatformName)
    # Get platform info again so we can ensure it's activated
    $platformStatus = Get-PlatformStatus -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken -PlatformId $PlatformName
}
else {
    Write-LogMessage -Type Warning -MSG ('Platform {0} already exists. Please verify it meets requirements.' -f $PlatformName)
    $Tasks += ("Verify that the existing platform `"{0}`" is configured correctly" -f $PlatformName)
}
if ($platformStatus.Active -eq $false) {
    Write-LogMessage -Type Verbose -MSG "Platform is deactivated. Activating."
    Activate-Platform -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken -Platform $platformStatus.Id
}
Write-LogMessage -Type Verbose -MSG "Checking current safe status"
$safeStatus = Get-SafeStatus -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken -SafeName $Safe
if ($safeStatus -eq $false) {
    # function returns false if safe does not exist
    Write-LogMessage -Type Verbose -MSG "Safe $Safe does not exist. Creating the safe now"
    $CreateSafeResult = Create-PSMSafe -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken -safe $Safe
    If ($CreateSafeResult) {
        Write-LogMessage -type Verbose "Successfully created safe $safe"
    }
    else {
        Write-LogMessage -Type Error -MSG "Creating PSM safe $Safe failed. Please resolve the error and try again."
        exit 1
    }
}
If (!($safeStatus.managingCpm)) {
    # Safe exists but no CPM assigned
    Write-LogMessage -Type Warning -MSG ("There is no Password Manager (CPM) assigned to safe `"{0}`"" -f $Safe)
    $Tasks += ("Assign a Password Manager (CPM) to safe `"{0}`"" -f $Safe)
}
# Giving Permission on the safe if we are using UM, The below will give full permission to vault admins
If ($UM) {
    Write-LogMessage -Type Verbose -MSG "Granting administrators access to PSM safe"
    New-SafePermissions -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken -safe $safe
}
# Creating PSMConnect, We can now add a safe need as well for the below line if we have multiple domains
Write-LogMessage -Type Verbose -MSG "Onboarding PSMConnect Account"
$OnboardResult = New-VaultAdminObject -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken -name $PSMConnectAccountName -domain $domain -Credentials $psmConnectCredentials -platformID $PlatformName -safe $safe
If ($OnboardResult.name) {
    Write-LogMessage -Type Verbose -MSG "User successfully onboarded"
}
ElseIf ($OnboardResult.ErrorCode -eq "PASWS027E") {
    Write-LogMessage -Type Warning -MSG "Object with name $PSMConnectAccountName already exists. Please verify that it contains correct account details, or specify an alternative account name."
    $Tasks += "Verify that the $PSMConnectAccountName object in $safe safe contains correct PSMConnect user details"
}
Else {
    Write-LogMessage -Type Error -MSG "Error onboarding account: {0}" -f $OnboardResult
    exit 1
}
# Creating PSMAdminConnect
Write-LogMessage -Type Verbose -MSG "Onboarding PSMAdminConnect Account"
$OnboardResult = New-VaultAdminObject -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken -name $PSMAdminConnectAccountName -domain $domain -Credentials $psmAdminCredentials -platformID $PlatformName -safe $safe
If ($OnboardResult.name) {
    Write-LogMessage -Type Verbose -MSG "User successfully onboarded"
}
ElseIf ($OnboardResult.ErrorCode -eq "PASWS027E") {
    Write-LogMessage -Type Warning -MSG "Object with name $PSMAdminConnectAccountName already exists. Please verify that it contains correct account details, or specify an alternative account name."
    $Tasks += "Verify that the $PSMAdminConnectAccountName object in $safe safe contains correct PSMAdminConnect user details"
}
Else {
    Write-LogMessage -Type Error -MSG "Error onboarding account: {0}" -f $OnboardResult
    exit 1
}
Write-LogMessage -Type Info -MSG "Performing local configuration and restarting service"

$PSMServerId = Get-PSMServerId -psmRootInstallLocation $psmRootInstallLocation
Write-LogMessage -Type Verbose -MSG "Stopping CyberArk Privileged Session Manager Service"
Stop-Service $REGKEY_PSMSERVICE
Write-LogMessage -Type Verbose -MSG "Backing up PSM configuration files and scripts"
Backup-PSMConfig -psmRootInstallLocation $psmRootInstallLocation -BackupSuffix $BackupSuffix
Write-LogMessage -Type Verbose -MSG "Updating PSM configuration files and scripts"
Update-PSMConfig -psmRootInstallLocation $psmRootInstallLocation -domain $domain -PsmConnectUsername $psmConnectCredentials.username.Replace('\', '') -PsmAdminUsername $psmAdminCredentials.username.Replace('\', '')
#TODO: Update Basic_ini
Write-LogMessage -Type Verbose -MSG "Adding PSMAdminConnect user to Terminal Services configuration"
# Adding PSMAdminConnect user to Terminal Services configuration
$AddAdminUserToTSResult = Add-AdminUserToTS -NETBIOS $NETBIOS -Credentials $psmAdminCredentials
If ($AddAdminUserToTSResult.ReturnValue -eq 0) {
    Write-LogMessage -Type Verbose -MSG "Successfully added PSMAdminConnect user to Terminal Services configuration"
}
else {
    # Failed to add user (1st command)
    if ($IgnoreShadowPermissionErrors) {
        Write-LogMessage -Type Warning -MSG $AddAdminUserToTSResult.Error
        Write-LogMessage -Type Warning -MSG "Failed to add PSMAdminConnect user to Terminal Services configuration."
        Write-LogMessage -Type Warning -MSG "Continuing because `"-IgnoreShadowPermissionErrors`" switch enabled"  
        $Tasks += "Resolve issue preventing PSMAdminConnect user being added to Terminal Services configuration and rerun this script"
    }
    else {
        Write-LogMessage -Type Error -MSG $AddAdminUserToTSResult.Error
        Write-LogMessage -Type Error -MSG "Failed to add PSMAdminConnect user to Terminal Services configuration."
        Write-LogMessage -Type Error -MSG "Run this script with the `"-IgnoreShadowPermissionErrors`" switch to ignore this error"
        Write-LogMessage -Type Error -MSG "Exiting."
        exit 1
    }
}
If ($AddAdminUserToTSResult.ReturnValue -eq 0) {
    # Grant shadow permission only if first command was succesful
    Write-LogMessage -Type Verbose -MSG "Granting PSMAdminConnect user permission to shadow sessions"
    $AddAdminUserTSShadowPermissionResult = Add-AdminUserTSShadowPermission -NETBIOS $NETBIOS -Credentials $psmAdminCredentials
    If ($AddAdminUserTSShadowPermissionResult.ReturnValue -eq 0) {
        Write-LogMessage -Type Verbose -MSG "Successfully granted PSMAdminConnect permission to shadow sessions"
    }
    else {
        # Failed to grant permission (2nd command)
        if ($IgnoreShadowPermissionErrors) {
            Write-LogMessage -Type Warning -MSG $AddAdminUserTSShadowPermissionResult.Error
            Write-LogMessage -Type Warning -MSG "Failed to grant PSMAdminConnect permission to shadow sessions."
            Write-LogMessage -Type Warning -MSG "Continuing because `"-IgnoreShadowPermissionErrors`" switch enabled"
            $Tasks += "Resolve issue preventing PSMAdminConnect user being granted permission to shadow sessions and rerun this script"
        }
        else {
            Write-LogMessage -Type Error -MSG $AddAdminUserTSShadowPermissionResult.Error
            Write-LogMessage -Type Error -MSG "Failed to grant PSMAdminConnect permission to shadow sessions."
            Write-LogMessage -Type Error -MSG "Please see the following article for information on resolving this error"
            Write-LogMessage -Type Error -MSG "https://cyberark-customers.force.com/s/article/PSM-Unable-to-run-WMIC-command"
            Write-LogMessage -Type Error -MSG "Run this script with the `"-IgnoreShadowPermissionErrors`" switch to ignore this error"
            exit 1
        }
    }
}

If ($DoHardening) {
    Write-LogMessage -Type Info -MSG "Running PSM Hardening script"
    Write-LogMessage -Type Info -MSG "---"
    Invoke-PSMHardening -psmRootInstallLocation $psmRootInstallLocation
    Write-LogMessage -Type Info -MSG "---"
    Write-LogMessage -Type Info -MSG "End of PSM Hardening script output"
}
else {
    Write-LogMessage -Type Info -MSG "Skipping Hardening due to -DoNotHarden parameter"
    $Tasks += "Run script for perform server hardening (PSMHardening.ps1)"
}
If ($DoConfigureAppLocker) {
    Write-LogMessage -Type Info -MSG "Running PSM Configure AppLocker script"
    Write-LogMessage -Type Info -MSG "---"
    Invoke-PSMConfigureAppLocker -psmRootInstallLocation $psmRootInstallLocation
    Write-LogMessage -Type Info -MSG "---"
    Write-LogMessage -Type Info -MSG "End of PSM Configure AppLocker script output"
}  
else {
    Write-LogMessage -Type Info -MSG "Skipping configuration of AppLocker due to -DoNotConfigureAppLocker parameter"
    $Tasks += "Run script to configure AppLocker (PSMConfigureAppLocker.ps1)"
}  
Write-LogMessage -Type Verbose -MSG "Restarting CyberArk Privileged Session Manager Service"
Restart-Service $REGKEY_PSMSERVICE
Write-LogMessage -Type Success -MSG "All tasks completed."
Write-LogMessage -type Info -MSG "The following additional steps may be required:"
$Tasks += "Restart Server"
foreach ($Task in $Tasks) {
    Write-LogMessage -Type Info " - $Task"
}
Write-LogMessage -Type Info -MSG " - Provide CyberArk support with the following required details for updating the backend:"
Write-LogMessage -Type Info -MSG ("     Portal address: {0}" -f $pvwaAddress)
Write-LogMessage -Type Info -MSG ("     PSM Server ID: {0}" -f $PSMServerId)
Write-LogMessage -Type Info -MSG ("     PSM Safe: {0}" -f $Safe)
Write-LogMessage -Type Info -MSG ("     PSMConnect Account Name: {0}" -f $PSMConnectAccountName)
Write-LogMessage -Type Info -MSG ("     PSMAdminConnect Account Name: {0}" -f $PSMAdminConnectAccountName)

