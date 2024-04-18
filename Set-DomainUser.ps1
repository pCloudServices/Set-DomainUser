<#
.SYNOPSIS
 This script will update the connector server to a domain user setup. It will also onboard the domain users into the portal inside the PSM safe.
.DESCRIPTION 
 Configures PSM to use domain-based PSMConnect and PSMAdminConnect users instead of the default local users. 
.PARAMETER PrivilegeCloudUrl
 The PVWA Address (e.g. https://tenant.privilegecloud.cyberark.cloud, or on-prem URL)
.PARAMETER VaultAddress
 The Vault Address (e.g. vault-SUBDOMAIN.privilegecloud.cyberark.cloud)
.PARAMETER DomainDNSName
 The fully qualified domain name of the domain user account(s).
.PARAMETER DomainNetbiosName
 The NETBIOS name for the domain user account(s).
.PARAMETER Safe
 The safe in which to store PSM user credentials
.PARAMETER InstallUser
 Tenant Administrator/InstallerUser credentials
.PARAMETER psmConnectCredentials
 PSMConnect domain user credentials
.PARAMETER psmAdminCredentials
 PSMAdminConnect domain user credentials
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
.PARAMETER LocalConfigurationOnly
 Do not onboard accounts in Privilege Cloud. Use on subsequent servers after first run.
.PARAMETER SkipPSMUserTests
 Do not check the configuration of the PSM domain users for errors
.PARAMETER SkipPSMObjectUpdate
 Do not update the PSM server object in backend
.PARAMETER SkipSecurityPolicyConfiguration
 Do not update Local Security Policy to allow PSM users to log on with Remote Desktop
.PARAMETER SkipAddingUsersToRduGroup
 Do not add PSM users to the Remote Desktop Users group
.PARAMETER SkipExistingAccountCheck
 Do not check whether PSM users already exist in the vault
.PARAMETER NotFirstRun
 This script is being run on additional servers following the first. Skip platform and safe creation and account onboarding.
.VERSION 14.1.1
.AUTHOR CyberArk
#>

[CmdletBinding()]
param(
    [Parameter(
        Mandatory = $false,
        HelpMessage = "Do not onboard accounts in Privilege Cloud. Use on subsequent servers after first run.")]
    [switch]$LocalConfigurationOnly,

    [Parameter(
        Mandatory = $false,
        HelpMessage = "Please enter the account credentials for the tenant administrator or installer user.")]
    [Alias("tinaCreds")]
    [PSCredential]$InstallUser,

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
        HelpMessage = "Please enter the domain of the created accounts IE: lab.net")]
    [Alias("domain")]
    [string]$DomainDNSName,

    [Parameter(
        Mandatory = $false,
        HelpMessage = "Please enter the NETBIOS of the created accounts IE: LAB")]
    [Alias("NETBIOS")]
    [string]$DomainNetbiosName,

    [Parameter(
        Mandatory = $false,
        HelpMessage = "Do not test PSM user configurations")]
    [switch]$SkipPSMUserTests,

    [Parameter(
        Mandatory = $false,
        HelpMessage = "Ignore errors while granting PSMAdminConnect user shadow permissions")]
    [switch]$IgnoreShadowPermissionErrors,

    [Parameter(
        Mandatory = $false,
        HelpMessage = "Please enter the full PVWA Address IE: https://tenantname.privilegecloud.cyberark.cloud")]
    [Alias("pvwaAddress")]
    [string]$PrivilegeCloudUrl,

    [Parameter(
        Mandatory = $false,
        HelpMessage = "Please enter the full Vault Address e.g.: vault-SUBDOMAIN.privilegecloud.cyberark.cloud")]
    [string]$VaultAddress,

    [Parameter(
        Mandatory = $false,
        HelpMessage = "Please enter the Safe to save the domain accounts in, By default it is PSM")]
    [String]$Safe = "PSM",

    [Parameter(
        Mandatory = $false,
        HelpMessage = "Name of Platform to be used for PSM accounts")]
    [String]$PlatformName = "WIN-DOM-PSMADMIN-ACCOUNT",

    [Parameter(
        Mandatory = $false,
        HelpMessage = "Account name in CyberArk of the PSMConnect user")]
    [String]$PSMConnectAccountName = "PSMConnect",

    [Parameter(
        Mandatory = $false,
        HelpMessage = "Account name in CyberArk of the PSMAdminConnect user")]
    [String]$PSMAdminConnectAccountName = "PSMAdminConnect",

    [Parameter(
        Mandatory = $false,
        HelpMessage = "Do not run Hardening script after configuration")]
    [switch]$DoNotHarden,

    [Parameter(
        Mandatory = $false,
        HelpMessage = "Do not run AppLocker script after configuration")]
    [switch]$DoNotConfigureAppLocker,

    [Parameter(
        Mandatory = $false,
        HelpMessage = "Do not update PSM Server Object configuration in backend")]
    [switch]$SkipPSMObjectUpdate,

    [Parameter(
        Mandatory = $false,
        HelpMessage = "Do not update Local Security Policy to allow PSM users to log on with Remote Desktop")]
    [switch]$SkipSecurityPolicyConfiguration,

    [Parameter(
        Mandatory = $false,
        HelpMessage = "Do not add PSM users to the Remote Desktop Users group")]
    [switch]$SkipAddingUsersToRduGroup,

    [Parameter(
        Mandatory = $false,
        HelpMessage = "Do not check whether PSM users already exist in the vault")]
    [switch]$SkipExistingAccountCheck,

    [Parameter(
        Mandatory = $false,
        HelpMessage = "Safe and platform configuration and account onboarding should be skipped as the script is being run on subsequent PSM servers.")]
    [switch]$NotFirstRun,

    [Parameter(
        Mandatory = $false,
        HelpMessage = "Proxy Server in address:port format or `"none`" for no proxy")]
    [string]$Proxy
)

<#
Script Order of Operations (search for a comment to find the relevant script section)
# Functions
# Determine what operations need to be performed
# Initialise variables
## Import previously validated inputs, if available
# Perform initial checks
## Proxy configuration
## Check if domain user
## Get Privilege Cloud URL
## Identify AD domain
# Gather information from user
## PSMConnect user
## PSMAdminConnect user
## InstallerUser/Tina
# Validate detected AD domain details
# Test users
## Test PSM user credential format
## Test PSM user credentials
## Test PSM user configuration
## Test InstallerUser/Tina user credentials
# List detected PSM user configuration errors
# Save validated inputs
# Remote Configuration
# Perform local configuration
# Post-configuration
## Group membership and security policy changes
## Invoke hardening scripts and restart service
# Display summary and additional tasks
#>

# Functions
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

Function Get-DifferencePosition {
    param(
        [Parameter(Mandatory = $true)][string]$String1,
        [Parameter(Mandatory = $true)][string]$String2
    )
    $DifferencePosition = $( # work out the position where the current value differs from the expected value by comparing them 1 character at a time ...
        $ExpectedValueLength = $String1.length
        $i = 0
        While ($i -le $ExpectedValueLength) {
            If ($String1[$i] -eq $String2[$i]) {
                $i++
            }
            else {
                $DifferencePosition = $i
                return $DifferencePosition
            }
        }
    )
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
        Write-LogMessage -Type Error -MSG "Unable to determine domain DNS name. Please provide it on the command line with the -DomainDNSName parameter."
        exit 1
    }
}

Function Get-DomainNetbiosName {
    if ($env:USERDOMAIN) {
        return $env:USERDOMAIN
    }
    else {
        Write-LogMessage -Type Error -MSG "Unable to determine domain NETBIOS name. Please provide it on the command line with the -DomainNetbiosName parameter."
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
        return $false
    }
}

Function Set-ValidatedInputs {
    param (
        [Parameter(Mandatory = $true)]
        $Data,
        [Parameter(Mandatory = $true)]
        $OutputFile
    )
    try {
        Export-Clixml -Depth 5 -Path $ValidatedInputFile -InputObject $ValidatedInputs -Force
        return $true
    }
    catch {
        return $false
    }
}

Function Get-CurrentSecurityPolicy {
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
        [string]
        $OutFile,
        [Parameter(Mandatory = $true)]
        [string]
        $LogFile
    )

    $LogFileSplit = ($LogFile -split "\.")
    $LogFileLength = $LogFileSplit.Count
    $LogFileBase = ($LogFileSplit)[0..($LogFileLength - 2)]
    $StdOutLogFile = (($LogFileBase -join ".") + ".stdout.log")

    try {
        $SecEditExe = Get-Command secedit.exe
        $process = Start-Process -Wait -FilePath $SecEditExe -PassThru -NoNewWindow -RedirectStandardOutput $StdOutLogFile `
            -ArgumentList @("/export", "/cfg", "`"$OutFile`"", "/log", "`"$LogFile`"")
        If ($process.ExitCode -eq 0) {
            return $True
        }
        return $False
    }
    catch {
        return $False
    }
}

Function Set-CurrentSecurityPolicy {
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
        [string]
        $DatabaseFile,
        [Parameter(Mandatory = $true)]
        [string]
        $ConfigFile,
        [Parameter(Mandatory = $true)]
        [string]
        $LogFile
    )

    $LogFileSplit = ($LogFile -split "\.")
    $LogFileLength = $LogFileSplit.Count
    $LogFileBase = ($LogFileSplit)[0..($LogFileLength - 2)]
    $StdOutLogFile = (($LogFileBase -join ".") + ".stdout.log")

    try {
        $SecEditExe = Get-Command secedit.exe
        $process = Start-Process -Wait -FilePath $SecEditExe -PassThru  -NoNewWindow -RedirectStandardOutput $StdOutLogFile `
            -ArgumentList @("/configure", "/db", "`"$DatabaseFile`"", "/cfg", "`"$ConfigFile`"", "/log", "`"$LogFile`"")
        If ($process.ExitCode -eq 0) {
            return $True
        }
        return $False
    }
    catch {
        return $False
    }
}

Function Get-ProxyDetails {
    try {
        $ProxyStatus = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').ProxyEnable
        If ($ProxyStatus -eq 1) {
            $ProxyString = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').proxyServer
            If ($ProxyString) {
                If ($ProxyString -match "^http://(.*)") {
                    return $Matches[1]
                }
                else {
                    return $ProxyString
                }
            }
            else {
                Write-LogMessage -type Verbose -MSG "No proxy detected"
                return $false
            }
        }
        else {
            Write-LogMessage -type Verbose -MSG "No proxy detected"
            return $false
        }
    }
    catch {
        Write-LogMessage -type Verbose -MSG "Error detecting proxy. Proceeding with no proxy."
        return $false
    }
}

Function Get-VaultAddress {
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
        $VaultIniAddressesLine = $VaultIni | Select-String "^ADDRESS\s*="
        $VaultAddress = $VaultIniAddressesLine.toString().Split("=")[1].trim()
        return $VaultAddress
    }
    catch {
        Write-LogMessage -Type Error -MSG "Unable to detect vault address automatically. Please rerun script and provide it using the -VaultAddress parameter."
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
            else {
                Write-LogMessage -type Error -MSG "Could not find PSM installation. Exiting."
                exit 1
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
    .PARAMETER InstallUser
    Tenant administrator/installer user credentials
    #>
    # Get PVWA and login informatioN
    param (
        [Parameter(Mandatory = $true)]
        $pvwaAddress,
        [Parameter(Mandatory = $true)]
        [PSCredential]$InstallUser
    )
    $url = $pvwaAddress + "/PasswordVault/API/auth/Cyberark/Logon"
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($InstallUser.Password)

    $headerPass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    $body = @{
        username = $InstallUser.UserName
        password = $headerPass
    }
    $json = $body | ConvertTo-Json
    Try {
        $Result = Invoke-RestMethod -Method 'Post' -Uri $url -Body $json -ContentType 'application/json' -WebSession $WebRequestSession
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
    try {
        $testToken = Invoke-RestMethod -Method 'Get' -Uri $url -Headers $Headers -ContentType 'application/json' -WebSession $Global:WebRequestSession
        if ($testToken) {
            return @{
                ErrorCode = "Success"
            }
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
    .PARAMETER BackupPath
    Append this string to the end of backup file names
    #>
    param (
        [Parameter(Mandatory = $true)]
        $psmRootInstallLocation,
        [Parameter(Mandatory = $true)]
        [string]$BackupPath
    )
    try {
        If (!(Test-Path -Path $BackupPath -PathType Container)) {
            $null = New-Item -ItemType Directory -Path $BackupPath
        }
        $PSMHardeningBackupFileName = ("{0}\PSMHardening.ps1" -f $BackupPath)
        $PSMConfigureAppLockerBackupFileName = ("{0}\PSMConfigureAppLocker.ps1" -f $BackupPath)
        $BasicPSMBackupFileName = ("{0}\basic_psm.ini" -f $BackupPath)

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
    .PARAMETER PSMAdminConnectAccountName
    PSM Admin Connect account name
    #>
    param (
        [Parameter(Mandatory = $true)]
        $psmRootInstallLocation,
        [Parameter(Mandatory = $true)]
        $domain,
        [Parameter(Mandatory = $true)]
        $PsmConnectUsername,
        [Parameter(Mandatory = $true)]
        $PsmAdminUsername,
        [Parameter(Mandatory = $true)]
        $PSMAdminConnectAccountName
    )
    try {
        #PSMHardening
        #-------------------------
        $psmHardeningContent = Get-Content -Path $psmRootInstallLocation\Hardening\PSMHardening.ps1

        $newPsmHardeningContent = $psmHardeningContent -replace '^(\$(Global:)?PSM_CONNECT_USER\s*=).*', ('$1 "{0}\{1}"' -f $domain, $PsmConnectUsername)
        $newPsmHardeningContent = $newPsmHardeningContent -replace '^(\$(Global:)?PSM_ADMIN_CONNECT_USER\s*=).*', ('$1 "{0}\{1}"' -f $domain, $PsmAdminUsername)
        $newPsmHardeningContent | Set-Content -Path "$psmRootInstallLocation\Hardening\test-psmhardening.ps1"

        #PSMApplocker
        #-------------------------


        $psmApplockerContent = Get-Content -Path $psmRootInstallLocation\Hardening\PSMConfigureApplocker.ps1

        $newPsmApplockerContent = $psmApplockerContent -replace '^(\$(Global:)?PSM_CONNECT\s*=).*', ('$1 "{0}\{1}"' -f $domain, $PsmConnectUsername)
        $newPsmApplockerContent = $newPsmApplockerContent -replace '^(\$(Global:)?PSM_ADMIN_CONNECT\s*=).*', ('$1 "{0}\{1}"' -f $domain, $PsmAdminUsername)

        $newPsmApplockerContent | Set-Content -Path "$psmRootInstallLocation\Hardening\test-psm-applocker.ps1"


        #basic_psm.ini
        #-------------------------


        $psmBasicPSMContent = Get-Content -Path $psmRootInstallLocation\basic_psm.ini

        $psmBasicPSMAdminLine = "PSMServerAdminId=`"$PSMAdminConnectAccountName`""
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
        $result = Invoke-RestMethod -Method POST -Uri $url -Body $json -Headers @{ "Authorization" = $pvwaToken } `
            -ContentType "application/json" -ErrorVariable ResultError -WebSession $Global:WebRequestSession
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

Function Get-VaultAccountDetails {
    <#
    .SYNOPSIS
    Onboards an account in the vault
    .DESCRIPTION
    Onboards an account in the vault
    .PARAMETER pvwaAddress
    Address of the PVWA
    .PARAMETER pvwaToken
    Token to log into PVWA using APIs
    .PARAMETER safe
    Safe to search
    #>
    param (
        [Parameter(Mandatory = $true)]
        $pvwaAddress,
        [Parameter(Mandatory = $true)]
        $pvwaToken,
        [Parameter(Mandatory = $false)]
        $safe = "PSM"
    )

    $url = ("{0}/PasswordVault/api/Accounts?filter=safename eq {1}" -f $pvwaAddress, $safe)
    try {
        $result = Invoke-RestMethod -Method GET -Uri $url -Headers @{ "Authorization" = $pvwaToken } `
            -ContentType "application/json" -ErrorVariable ResultError -WebSession $Global:WebRequestSession
        $Accounts = $result.value
        return $Accounts
    }
    catch {
        try {
            $ErrorMessage = $ResultError.Message | ConvertFrom-Json
            return $ErrorMessage
        }
        catch {
            Write-LogMessage -Type Error -MSG ("Error retrieving account details: {0}" -f $ResultError.Message)
            exit 1
        }
    }
}

Function Get-VaultAccountPassword {
    <#
    .SYNOPSIS
    Onboards an account in the vault
    .DESCRIPTION
    Onboards an account in the vault
    .PARAMETER pvwaAddress
    Address of the PVWA
    .PARAMETER pvwaToken
    Token to log into PVWA using APIs
    .PARAMETER safe
    Safe to search
    #>
    param (
        [Parameter(Mandatory = $true)]
        $pvwaAddress,
        [Parameter(Mandatory = $true)]
        $pvwaToken,
        [Parameter(Mandatory = $true)]
        $AccountId
    )

    $url = ("{0}/PasswordVault/API/Accounts/{1}/Password/Retrieve/" -f $pvwaAddress, $AccountId)
    try {
        $result = Invoke-RestMethod -Method POST -Uri $url -Headers @{ "Authorization" = $pvwaToken } `
            -ContentType "application/json" -ErrorVariable ResultError -WebSession $Global:WebRequestSession
        return $result
    }
    catch {
        try {
            $ErrorMessage = $ResultError.Message | ConvertFrom-Json
            return $ErrorMessage
        }
        catch {
            Write-LogMessage -Type Error -MSG ("Error retrieving account password: {0}" -f $ResultError.Message)
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
    try {
        $CimInstance = Get-CimInstance -Namespace root/cimv2/terminalservices -Query "SELECT * FROM Win32_TSPermissionsSetting WHERE TerminalName = 'RDP-Tcp'"
        $result = $CimInstance | Invoke-CimMethod -MethodName AddAccount -Arguments @{AccountName = "$username"; PermissionPreSet = 0 }
        return $result
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
    try {
        $CimInstance = Get-CimInstance -Namespace root/cimv2/terminalservices -Query "SELECT * FROM Win32_TSAccount WHERE TerminalName = 'RDP-Tcp'" | Where-Object AccountName -eq $username
        $result = $CimInstance | Invoke-CimMethod -MethodName ModifyPermissions -Arguments @{PermissionMask = 4; Allow = $true }
        return $result
    }
    catch {
        return @{
            Error       = $_.Exception.Message
            ReturnValue = 1
        }
    }
}

Function Copy-Platform {
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
        $null = Invoke-RestMethod -Method 'Post' -Uri $url -Body $json -Headers @{ 'Authorization' = $pvwaToken } -ContentType 'application/json' -WebSession $Global:WebRequestSession
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
        $Getresult = Invoke-RestMethod -Method 'Get' -Uri $url -Headers @{ 'Authorization' = $pvwaToken } -ErrorAction SilentlyContinue -ErrorVariable GetPlatformError -WebSession $Global:WebRequestSession
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

Function Get-PlatformStatusById {
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
        $url = $pvwaAddress + "/PasswordVault/api/Platforms/targets"
        $Getresult = Invoke-RestMethod -Method 'Get' -Uri $url -Headers @{ 'Authorization' = $pvwaToken } -ErrorAction SilentlyContinue -ErrorVariable GetPlatformError -WebSession $Global:WebRequestSession
        # This query returns a list of platforms where the name contains the search string. Find and return just the one with an exactly matching name.
        $TargetPlatform = $Getresult.Platforms | Where-Object PlatformID -eq $PlatformId
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
        $SafeRequest = Invoke-RestMethod -Method 'Get' -Uri $url -Headers @{ 'Authorization' = $pvwaToken } -ErrorAction SilentlyContinue -WebSession $Global:WebRequestSession
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

Function Enable-Platform {
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
        $null = Invoke-RestMethod -Method 'Post' -Uri $url -Headers @{ 'Authorization' = $pvwaToken } -ContentType 'application/json' -WebSession $Global:WebRequestSession
    }
    catch {
        Write-LogMessage -Type Error -MSG "Error activating platform"
        Write-LogMessage -Type Error -MSG $_.ErrorDetails.Message
        exit 1
    }
}

Function New-PSMSafe {
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
        $null = Invoke-RestMethod -Method 'Post' -Uri $url -Body $json -Headers @{ 'Authorization' = $pvwaToken } -ContentType 'application/json' -WebSession $Global:WebRequestSession
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
        $null = Invoke-RestMethod -Method 'Put' -Uri $url -Body $json -Headers @{ 'Authorization' = $pvwaToken } -ContentType 'application/json' -WebSession $Global:WebRequestSession
    }
    catch {
        Write-LogMessage -Type Error -MSG $_.ErrorDetails.Message
    }
}

Function Get-SafePermissions {
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
        $SearchIn = "Vault",
        [Parameter(Mandatory = $false)]
        $memberType = "Group"
    )
    try {
        $url = $pvwaAddress + "/PasswordVault/api/Safes/$safe/members/$safeMember/"
        $result = Invoke-RestMethod -Method 'Get' -Uri $url -Headers @{ 'Authorization' = $pvwaToken } -ContentType 'application/json' -WebSession $Global:WebRequestSession
        if ($result) {
            return $result.permissions
        }
        else {
            throw
        }
    }
    catch {
        return $false
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
        $SearchIn = "Vault",
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
            searchIn    = $SearchIn
            permissions = $safePermissions
        }
        $json = $body | ConvertTo-Json
        $null = Invoke-RestMethod -Method 'Post' -Uri $url -Body $json -Headers @{ 'Authorization' = $pvwaToken } -ContentType 'application/json' -WebSession $Global:WebRequestSession
    }
    catch {
        Write-LogMessage -Type Error -MSG $_.ErrorDetails.Message
    }
}

Function Test-UM {
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
    if ($Credential.username.Length -gt 20) {
        return $false
    }
    return $true
}

function Test-PSMUserConfiguration {
    param (
        [Parameter(Mandatory = $true)][System.DirectoryServices.DirectoryEntry]$UserObject,
        [Parameter(Mandatory = $true)][string]$UserType,
        [Parameter(Mandatory = $true)][string]$PSMInstallLocation

    )
    # Define the settings we'll be comparing against
    $PSMComponentsPath = $PSMInstallLocation + "Components"
    $PSMInitSessionPath = $PSMComponentsPath + "\PSMInitSession.exe"
    $SettingsToCheck = @(
        @{
            UserType      = "All"
            Name          = "TerminalServicesInitialProgram"
            DisplayName   = "Initial Program"
            ExpectedValue = $PSMInitSessionPath
            SettingType   = "StringCompare"
        },
        @{
            UserType      = "All"
            Name          = "TerminalServicesWorkDirectory"
            DisplayName   = "Working Directory"
            ExpectedValue = $PSMComponentsPath
            Path          = $true
            SettingType   = "StringCompare"
        },
        @{
            UserType      = "All"
            Name          = "ConnectClientDrivesAtLogon"
            DisplayName   = "Connect client drives at logon"
            ExpectedValue = 0
            SettingType   = "Value"
        },
        @{
            UserType      = "All"
            Name          = "ConnectClientPrintersAtLogon"
            DisplayName   = "Connect client drives at logon"
            ExpectedValue = 0
            SettingType   = "Value"
        },
        @{
            UserType      = "All"
            Name          = "DefaultToMainPrinter"
            DisplayName   = "Default to main client printer"
            ExpectedValue = 0
            SettingType   = "Value"
        },
        @{
            UserType      = "All"
            Name          = "EnableRemoteControl"
            DisplayName   = "Enable remote control"
            ExpectedValue = 2, 4
            SettingType   = "Value"
        },
        @{
            UserType      = "PSMConnect"
            Name          = "MaxDisconnectionTime"
            DisplayName   = "End a disconnected session"
            ExpectedValue = 1
            SettingType   = "Value"
        },
        @{
            UserType      = "PSMConnect"
            Name          = "ReconnectionAction"
            DisplayName   = "Allow reconnection"
            ExpectedValue = 1
            SettingType   = "Value"
        },
        @{
            UserType      = "All"
            Name          = "userWorkstations"
            DisplayName   = "`"Log On To`" Restrictions"
            ExpectedValue = $env:computername
            SettingType   = "LogOnTo"
        }
    )
    $UserName = $UserObject.Name
    $SettingsToCheck | ForEach-Object { # For each aspect of the configuration
        $SettingName = $_.Name
        $SettingUserType = $_.UserType
        $SettingDisplayName = $_.DisplayName
        $SettingExpectedValue = $_.ExpectedValue
        $SettingCurrentValue = Get-UserProperty -UserObject $UserObject -Property $SettingName
        $SettingType = $_.SettingType

        If ($_.Path) {
            # If the value we're checking is a directory, trim training backslashes as they don't matter
            $SettingCurrentValue = ($SettingCurrentValue -replace "\\*$", "")
        }

        if ($SettingUserType -in "All", $UserType) {
            # If the setting that we are checking applies to the user we're checking, or all users
            If ($SettingType -eq "LogOnTo") {
                # split $SettingCurrentValue into an array
                $SettingCurrentValue = $SettingCurrentValue -split ","
            }
            If (
                (
                ($SettingType -in "Value", "StringCompare") -and
                ($SettingCurrentValue -notin $SettingExpectedValue)
                    # For Value and StringCompare setting types, we check if the current value is one of the expected values
                ) -or
                (
                ($SettingType -eq "LogOnTo") -and (
                    ($SettingCurrentValue) -and
                    ($SettingExpectedValue -notin $SettingCurrentValue)
                    )
                    # but for Log On To, it's the other way round - the expected value must be in the current value (or be empty - "all workstations")
                )
            ) {
                $ThisUserConfigurationError = [PSCustomObject]@{ # add it to the array containing the list of misconfigurations
                    Username    = $Username
                    User        = $UserType
                    SettingName = $SettingDisplayName
                    Current     = $SettingCurrentValue
                    Expected    = $SettingExpectedValue
                    SettingType = $SettingType
                }
                if ($SettingType -eq "LogOnTo") {
                    $ThisUserConfigurationError.Expected = "Must include `"$SettingExpectedValue`""
                }
                return @{
                    Result = "Error"
                    Errors = $ThisUserConfigurationError
                }
            }
            return @{
                Result = "Success"
            }
        }
    }
}

function Test-PasswordCharactersValid {
    param (
        [Parameter(Mandatory = $true)][PSCredential]$Credential
    )
    if ($Credential.GetNetworkCredential().Password -match '^[A-Za-z0-9~!@#$%^&*_\-+=`|\(){}[\]:;"''<>,.?\\\/ ]+$') {
        # The above special characters without escape characters:      ~!@#$%^&*_ -+=`| (){}[ ]:;" '<>,.? \ /
        # space character is also valid
        return $true
    }
    return $false
}



function Get-UserDNFromSamAccountName {
    param (
        [Parameter(Mandatory = $True)]
        [string]
        $Username
    )
    $Searcher = [adsisearcher]"samaccountname=$Username"
    $Result = $Searcher.FindAll()
    If ($Result) {
        return $Result.Path
    }
    return $False
}

function Get-UserObjectFromDN {
    param (
        [Parameter(Mandatory = $True)]
        [string]
        $DistinguishedName
    )
    $UserObject = [adsi]"$DistinguishedName"
    If ($UserObject) {
        return $UserObject
    }
    return $False
}

function Get-UserProperty {
    param (
        [Parameter(Mandatory = $True)]
        [System.DirectoryServices.DirectoryEntry]
        $UserObject,
        [Parameter(Mandatory = $True)]
        [string]
        $Property
    )
    try {
        $Result = $UserObject.InvokeGet($Property)
    }
    catch {
        $Result = "Unset"
    }
    return $Result
}

function Update-ValidatedInputs {
    param (
        [Parameter(Mandatory = $True)]
        [hashtable]$Object,

        [Parameter(Mandatory = $True)]
        [string]$InputName,

        [Parameter(Mandatory = $False)]
        $Value

    )
    If ($Value) {
        # Value is set so update or add a value
        If ($Object.$InputName) {
            $Object.$InputName = $Value
        }
        else {
            $Object += @{
                $InputName = $Value
            }
        }
    }
    else {
        # Value is empty so remove a value instead
        $Object.Remove($InputName)
    }
    return $Object
}

Function Set-PSMServerObject {
    param (
        [Parameter(Mandatory = $True)]
        [String]
        $VaultOperationsFolder,
        [Parameter(Mandatory = $True)]
        [String]
        $VaultAddress,
        [Parameter(Mandatory = $True)]
        [PSCredential]
        $VaultCredentials,
        [Parameter(Mandatory = $True)]
        [String]
        $PSMServerId,
        [Parameter(Mandatory = $True)]
        [String]
        $PSMSafe,
        [Parameter(Mandatory = $True)]
        [String]
        $PSMConnectAccountName,
        [Parameter(Mandatory = $True)]
        [String]
        $PSMAdminConnectAccountName,
        [Parameter(Mandatory = $False)]
        [string]
        $Proxy
    )

    $VaultOperationsExe = "$VaultOperationsFolder\VaultOperationsTester.exe"
    $stdoutFile = "$VaultOperationsFolder\Log\stdout.log"
    $LOG_FILE_PATH_CasosArchive = "$VaultOperationsFolder\Log\old"

    #Cleanup log file if it gets too big
    if (Test-Path $LOG_FILE_PATH_CasosArchive) {
        if (Get-ChildItem $LOG_FILE_PATH_CasosArchive | Measure-Object -Property length -Sum | Where-Object { $_.sum -gt 5MB }) {
            Write-LogMessage -type Verbose -MSG "Archive log folder is getting too big, deleting it."
            Write-LogMessage -type Verbose -MSG "Deleting $LOG_FILE_PATH_CasosArchive"
            Remove-Item $LOG_FILE_PATH_CasosArchive -Recurse -Force
        }
    }

    #create log file
    New-Item -Path $stdoutFile -Force | Out-Null

    # Create vault.ini
    New-Item -Path "$VaultOperationsFolder\Vault.ini" -Force
    Add-Content -Path "$VaultOperationsFolder\Vault.ini" -Force -Value ('VAULT = "Vault"')

    If ("None" -ne $Proxy) {
        $ProxyAddress = $Proxy.Split(":")[0]
        $ProxyPort = $Proxy.Split(":")[1]
        Add-Content -Path "$VaultOperationsFolder\Vault.ini" -Force -Value ('PROXYADDRESS = {0}' -f $ProxyAddress)
        Add-Content -Path "$VaultOperationsFolder\Vault.ini" -Force -Value ('PROXYPORT = {0}' -f $ProxyPort)
        Add-Content -Path "$VaultOperationsFolder\Vault.ini" -Force -Value ('PROXYTYPE = https')
    }

    #Get Credentials
    $VaultUser = $VaultCredentials.UserName
    $VaultPass = $VaultCredentials.GetNetworkCredential().Password
    $Operation = "EditConfigNode"
    $ConfigString = ("//PSMServer[@ID='{0}']/ConnectionDetails/Server Safe={1},Object={2},AdminObject={3}" `
            -f $PSMServerId, $Safe, $PSMConnectAccountName, $PSMAdminConnectAccountName)
    try {
        $VaultOperationsTesterProcess = $VaultOperationsTesterProcess = Start-Process -FilePath $VaultOperationsExe `
            -WorkingDirectory "$VaultOperationsFolder" -NoNewWindow -PassThru -Wait -RedirectStandardOutput $stdoutFile `
            -ArgumentList $VaultUser, $VaultPass, $VaultAddress, $Operation, $ConfigString
    }
    catch {
        return @{
            ErrorCode = "Unknown"
            Result    = $false
        }
    }

    if ($VaultOperationsTesterProcess.ExitCode -ne 0) {
        $ErrorLine = Get-Content $stdoutFile | Select-String "^Extra details:"
        $ErrorString = ($ErrorLine -split ":")[1].Trim()
        $null = $ErrorString -Match "([A-Z0-9]*) (.*)"
        If ($Matches[1]) {
            $ErrorCode = $Matches[1]
        }
        else {
            $ErrorCode = "Unknown"
        }
        If ($Matches[1]) {
            $ErrorDetails = $Matches[2]
        }
        else {
            $ErrorDetails = "Unknown"
        }
        return @{
            Result       = $false
            ErrorCode    = $ErrorCode
            ErrorDetails = $ErrorDetails
        }
    }
    else {
        return @{
            Result = $true
        }
    }
}

# End of function definitions

# Running Set-DomainUser script
$OperationsToPerform = @{
    GetInstallerUserCredentials       = $true
    TestInstallerUserCredentials      = $true
    GetPSMConnectUserCredentials      = $true
    GetPSMAdminConnectUserCredentials = $true
    GetPSMConnectUserName             = $false
    GetPSMAdminConnectUserName        = $false
    UserTests                         = $true
    GetPrivilegeCloudUrl              = $true
    DomainNetbiosNameDetection        = $true
    DomainDNSNameDetection            = $true
    PsmConfiguration                  = $true
    SecurityPolicyConfiguration       = $true
    RemoteDesktopUsersGroupAddition   = $true
    CreateSafePlatformAndAccounts     = $true
    ServerObjectConfiguration         = $true
    Hardening                         = $true
    ConfigureAppLocker                = $true
    DetectProxy                       = $true
    ExistingAccountCheck              = $true
}

# Determine what operations need to be performed
switch ($PSBoundParameters) {
    { $_.SkipExistingAccountCheck } {
        $OperationsToPerform.ExistingAccountCheck = $false
    }
    { $_.psmConnectCredentials } {
        $OperationsToPerform.GetPSMConnectUserCredentials = $false
    }
    { $_.psmAdminCredentials } {
        $OperationsToPerform.GetPSMAdminConnectUserCredentials = $false
    }
    { $_.NotFirstRun } {
        $OperationsToPerform.UserTests = $false
        $OperationsToPerform.CreateSafePlatformAndAccounts = $false
    }
    { $_.SkipPSMUserTests } {
        $OperationsToPerform.UserTests = $false
    }
    { $_.PrivilegeCloudUrl } {
        $OperationsToPerform.GetPrivilegeCloudUrl = $false
    }
    { $_.DomainNetbiosName } {
        $OperationsToPerform.DomainNetbiosNameDetection = $false
    }
    { $_.DomainDNSName } {
        $OperationsToPerform.DomainDNSNameDetection = $false
    }
    { $_.LocalConfigurationOnly } {
        $OperationsToPerform.CreateSafePlatformAndAccounts = $false
        $OperationsToPerform.ServerObjectConfiguration = $false
        $OperationsToPerform.UserTests = $false
        $OperationsToPerform.GetInstallerUserCredentials = $false
        $OperationsToPerform.TestInstallerUserCredentials = $false
        $OperationsToPerform.ExistingAccountCheck = $false
    }
    { $_.DoNotHarden } {
        $OperationsToPerform.Hardening = $false
    }
    { $_.SkipPSMObjectUpdate } {
        $OperationsToPerform.ServerObjectConfiguration = $false
    }
    { $_.SkipSecurityPolicyConfiguration } {
        $OperationsToPerform.SecurityPolicyConfiguration = $false
    }
    { $_.SkipAddingUsersToRduGroup } {
        $OperationsToPerform.RemoteDesktopUsersGroupAddition = $false
    }
    { $_.DoNotConfigureAppLocker } {
        $OperationsToPerform.ConfigureAppLocker = $false
    }
    { $_.Proxy } {
        $OperationsToPerform.DetectProxy = $false
    }
}

# If not doing any remote work, skip proxy detection
If (!($OperationsToPerform.CreateSafePlatformAndAccounts -or $OperationsToPerform.ServerObjectConfiguration)) {
    $OperationsToPerform.DetectProxy = $false
    $Proxy = "None"
}

# Initialise variables
$StandardSeparator = ("-" * 50)
$SectionSeparator = ("#" * 50)
$global:InVerbose = $PSBoundParameters.Verbose.IsPresent
$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path
$global:LOG_FILE_PATH = "$ScriptLocation\_Set-DomainUser.log"
$PsmServiceNames = "Cyber-Ark Privileged Session Manager", "CyberArk Privileged Session Manager"
$PsmService = Get-Service | Where-Object Name -in $PsmServiceNames
$REGKEY_PSMSERVICE = $PsmService.Name
$psmRootInstallLocation = ($(Get-ServiceInstallPath $REGKEY_PSMSERVICE)).Replace("CAPSM.exe", "").Replace('"', "").Trim()
$BackupSubDirectory = (Get-Date).ToString('yyyMMdd-HHmmss')
$BackupPath = "$psmRootInstallLocation\Backup\Set-DomainUser\$BackupSubDirectory"
$ValidatedInputFileName = "_Set-DomainUserValidatedInputs.xml"
$ValidatedInputFile = "$ScriptLocation\$ValidatedInputFileName"
$ValidationFailed = $false
$PSMServerId = Get-PSMServerId -psmRootInstallLocation $psmRootInstallLocation
$PSMConnectUserName = ""
$PSMAdminConnectUserName = ""
$TasksTop = @()

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Host ""
Write-LogMessage -type Info -MSG "Gathering information"

# Initialise the variable to store inputs as they are validated
$ValidatedInputs = @{}

## Import previously validated inputs, if available, and not provided on command line (command-line parameters take precedence)
If (Test-Path $ValidatedInputFile) {
    # For credentials:
    # If user names present in validated inputs, remember them for later
    $RawValidatedInputs = Import-Clixml -Path $ValidatedInputFile
    If (($null -eq $psmConnectCredentials) -and ($RawValidatedInputs.PSMConnectUserName)) {
        # If PSMConnectUserName has been validated previously
        $ValidatedInputs += @{ PSMConnectUserName = $RawValidatedInputs.PSMConnectUserName }
        $PSMConnectUserName = $RawValidatedInputs.PSMConnectUserName
        # Store it for later
    }

    If (($null -eq $psmAdminCredentials) -and ($RawValidatedInputs.PSMAdminConnectUserName)) {
        # If PSMAdminConnectUserName has been validated previously
        $ValidatedInputs += @{ PSMAdminConnectUserName = $RawValidatedInputs.PSMAdminConnectUserName }
        $PSMAdminConnectUserName = $RawValidatedInputs.PSMAdminConnectUserName
        # Store it for later
    }

    If (($null -eq $InstallUser) -and ($RawValidatedInputs.InstallUserName)) {
        # If InstallUserName has been validated previously
        $ValidatedInputs += @{ InstallUserName = $RawValidatedInputs.InstallUserName }
        $InstallUserName = $RawValidatedInputs.InstallUserName
        # Store it for later
    }

    # For domain details:
    ## Take from command line parameters
    ## if not provided in parameters, take from import
    ## if not present in import, do nothing
    If (([String]::IsNullOrWhiteSpace($DomainDNSName)) -and ($RawValidatedInputs.DomainDNSName)) {
        $ValidatedInputs += @{ DomainDNSName = $RawValidatedInputs.DomainDNSName }
        $DomainDNSName = $RawValidatedInputs.DomainDNSName
        $OperationsToPerform.DomainDNSNameDetection = $false
    }

    If (([String]::IsNullOrWhiteSpace($DomainNetbiosName)) -and ($RawValidatedInputs.DomainNetbiosName)) {
        $ValidatedInputs += @{ DomainNetbiosName = $RawValidatedInputs.DomainNetbiosName }
        $DomainNetbiosName = $RawValidatedInputs.DomainNetbiosName
        $OperationsToPerform.DomainNETBIOSNameDetection = $false
    }
    Write-LogMessage -type Info -MSG "Imported the following details from $ValidatedInputFileName`:"
    Write-LogMessage -type Info -MSG $StandardSeparator
    $MessageString = ($ValidatedInputs | Out-String).Trim()
    Write-LogMessage -type Info -MSG $MessageString
    Write-LogMessage -type Info -MSG $StandardSeparator
}

# Perform initial checks
If (Test-UM -psmRootInstallLocation $psmRootInstallLocation) {
    $UM = $true
}
else {
    $UM = $false
}

## Proxy configuration
If ($OperationsToPerform.DetectProxy) {
    # Get proxy details from user profile
    Write-LogMessage -type Verbose -MSG "Detecting proxy from user profile"
    $DetectedProxy = Get-ProxyDetails

    If ($DetectedProxy) {
        $ProxyInfo = ""
        $ProxyInfo += ("--------------------------------------------------------`n")
        $ProxyInfo += ("Detected the following proxy details:`n")
        $ProxyInfo += ("  Proxy Address:     {0}`n" -f $DetectedProxy)
        $ProxyInfo += ("Is this correct?")

        $PromptOptions = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
        $PromptOptions.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList "&Yes", "Confirm the proxy details are correct"))
        $PromptOptions.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList "&No", "Exit the script so correct proxy details can be provided"))

        $ProxyPromptSelection = $Host.UI.PromptForChoice("", $ProxyInfo, $PromptOptions, 1)
        If ($ProxyPromptSelection -eq 0) {
            Write-LogMessage -Type Verbose "Proxy details confirmed"
            $Proxy = $DetectedProxy
            $ValidatedInputs += @{
                Proxy = $Proxy
            }
        }
        Else {
            Write-LogMessage -Type Error -MSG "Please rerun the script and provide the correct proxy details on the command line."
            exit 1
        }
    }
    else {
        $Proxy = "None"
    }
}
Write-LogMessage -type Verbose -MSG "Creating WebRequestSession object"
$Global:WebRequestSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
Write-LogMessage -type Verbose -MSG "Creating proxy object"
$ProxyObject = New-Object System.Net.WebProxy

If ("None" -ne $Proxy) {
    try {
        Write-LogMessage -type Verbose -MSG "Setting web requests to use proxy $Proxy"
        $ProxyObject.Address = "http://$Proxy"
    }
    catch {
        Write-LogMessage -type Error -MSG "Failed to configure proxy. Please ensure it is provided in address:port format."
        exit 1
    }
}

Write-LogMessage -type Verbose -MSG "Setting proxy on WebRequestSession object"
$Global:WebRequestSession.Proxy = $ProxyObject

## Check if domain user
Write-LogMessage -Type Verbose -MSG "Checking if user is a domain user"
if (IsUserDomainJoined) {
    Write-LogMessage -Type Verbose -MSG "User is a domain user"
}
else {
    Write-LogMessage -Type Error -MSG "Stopping. Please run this script as a domain user"
    exit 1
}

## Get Privilege Cloud URL
if ($OperationsToPerform.GetPrivilegeCloudUrl) {
    Write-LogMessage -Type Verbose -MSG "Getting PVWA address"
    $PrivilegeCloudUrl = Get-PvwaAddress -psmRootInstallLocation $psmRootInstallLocation
}
If ($false -eq $PrivilegeCloudUrl) {
    Write-LogMessage -Type Error -MSG "Unable to detect PVWA address automatically. Please rerun script and provide it using the -PrivilegeCloudUrl parameter."
    exit 1
}

## Identify AD domain
$DomainNameAutodetected = $false
Write-LogMessage -Type Verbose -MSG "Getting domain details"
if ($OperationsToPerform.DomainDNSNameDetection) {
    $DomainNameAutodetected = $true
    $DomainDNSName = Get-DomainDnsName
}
if ($OperationsToPerform.DomainNetbiosNameDetection) {
    $DomainNameAutodetected = $true
    $DomainNetbiosName = Get-DomainNetbiosName
}

# Gather information from user
## PSMConnect user
Write-LogMessage -Type Verbose -MSG "Getting PSMConnect user details if required"
if ($OperationsToPerform.GetPSMConnectUserCredentials) {
    $psmConnectCredentials = Get-Credential -Message "Please enter PSMConnect domain user credentials" -UserName $PSMConnectUserName
    if (!($psmConnectCredentials)) {
        Write-LogMessage -Type Error -MSG "No PSMConnect user credentials provided. Exiting."
        exit 1
    }
    $ValidatedInputs = Update-ValidatedInputs -Object $ValidatedInputs -Input "PSMConnectUserName" -Value $psmConnectCredentials.UserName
}

## PSMAdminConnect user
Write-LogMessage -Type Verbose -MSG "Getting PSMAdminConnect user details if required"
if ($OperationsToPerform.GetPSMAdminConnectUserCredentials) {
    $psmAdminCredentials = Get-Credential -Message "Please enter PSMAdminConnect domain user credentials" -UserName $PSMAdminConnectUserName
    if (!($psmAdminCredentials)) {
        Write-LogMessage -Type Error -MSG "No PSMAdminConnect user credentials provided. Exiting."
        exit 1
    }
    $ValidatedInputs = Update-ValidatedInputs -Object $ValidatedInputs -Input "PSMAdminConnectUserName" -Value $psmAdminCredentials.UserName
}

## InstallerUser/Tina
Write-LogMessage -Type Verbose -MSG "Getting Tina user details if required"
$InstallUserError = $false
If ($OperationsToPerform.GetInstallerUserCredentials) {
    if ($null -eq $InstallUser) {
        $InstallUser = Get-Credential -Message ("Please enter installer user credentials") -UserName $InstallUserName
        if (!($InstallUser)) {
            Write-LogMessage -Type Error -MSG "No install user credentials provided. Exiting."
            exit 1
        }
    }
    $ValidatedInputs = Update-ValidatedInputs -Object $ValidatedInputs -Input "InstallUserName" -Value $InstallUser.UserName
}

# Validate detected AD domain details
If ($DomainNameAutodetected) {
    Write-LogMessage -Type Verbose -MSG "Confirming auto-detected domain details"
    $DomainInfo = ""
    $DomainInfo += ("--------------------------------------------------------`n")
    $DomainInfo += ("Detected the following domain names:`n")
    $DomainInfo += ("  DNS name:     {0}`n" -f $DomainDNSName)
    $DomainInfo += ("  NETBIOS name: {0}`n" -f $DomainNetbiosName)
    $DomainInfo += ("Is this correct?")

    $PromptOptions = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
    $PromptOptions.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList "&Yes", "Confirm the domain details are correct"))
    $PromptOptions.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList "&No", "Exit the script so correct domain details can be provided"))

    $DomainPromptSelection = $Host.UI.PromptForChoice("", $DomainInfo, $PromptOptions, 1)
    If ($DomainPromptSelection -eq 0) {
        Write-LogMessage -Type Info "Domain details confirmed"
        $ValidatedInputs += @{
            DomainDNSName     = $DomainDNSName
            DomainNetbiosName = $DomainNetbiosName
        }
    }
    Else {
        Write-LogMessage -Type Error -MSG "Please rerun the script and provide the correct domain DNS and NETBIOS names on the command line."
        $ValidationFailed = $true
    }
}

# Test users
Write-LogMessage -type Info -MSG "Validating PSM and install user details"
$PSMAccountDetailsArray = @(
    @{
        Credentials = $psmConnectCredentials
        AccountName = $PSMConnectAccountName
        UserType    = "PSMConnect"
    },
    @{
        Credentials = $psmAdminCredentials
        AccountName = $PSMAdminConnectAccountName
        UserType    = "PSMAdminConnect"
    }
)

# Test PSM user configuration
#Initialise array which will capture detected misconfigurations
$UserConfigurationErrors = @()
$ArrayOfUserErrors = @()

## Test PSM user credential format
foreach ($CurrentUser in $PSMAccountDetailsArray) {
    $Credential = $CurrentUser.Credentials
    $Username = $Credential.UserName
    $UserType = $CurrentUser.UserType
    Write-LogMessage -type Verbose -MSG "Testing $UserType credential format"
    try {
        Write-LogMessage -Type Verbose -MSG "Verifying PSM credentials were provided in expected format"
        If (!(Test-CredentialFormat -Credential $Credential)) {
            $NewError = ""
            $NewError += "Username provided for PSMConnect user contained invalid characters or is too long.`n"
            $NewError += "Please provide the pre-Windows 2000 username without DOMAIN\ or @domain, and ensure"
            $NewError += "the username is no more than 20 characters long"
            $ArrayOfUserErrors += $NewError
            Throw
        }

        If (!(Test-PasswordCharactersValid -Credential $Credential)) {
            $NewError = ""
            $NewError += "Password provided for $Username user contained invalid characters.`n"
            $NewError += '  Please include only alphanumeric and the following characters: ~!@#$%^&*_-+=`|(){}[]:;"''<>,.?\/'
            $ArrayOfUserErrors += $NewError
            Write-Host ""
            Throw
        }
    }
    catch {
        $ValidationFailed = $true
    }
}

## Test PSM user credentials
foreach ($CurrentUser in $PSMAccountDetailsArray) {
    $Credential = $CurrentUser.Credentials
    $UserName = $Credential.UserName
    $UserType = $CurrentUser.UserType
    Write-LogMessage -type Verbose -MSG "Testing $Username credentials"
    try {
        if ($OperationsToPerform.UserTests) {
            # Test PSM credentials
            if (ValidateCredentials -domain $DomainDNSName -Credential $Credential) {
                $InputName = ($UserType + "UserName")
                Write-LogMessage -Type Verbose -MSG "$UserName user credentials validated"
            }
            else {
                $NewError = ""
                $NewError += "An attempt to authenticate to the domain using the $Username username and password failed."
                $ArrayOfUserErrors += $NewError
                Throw
            }
        }
    }
    catch {
        $ValidationFailed = $true
    }
}

## Test PSM user configuration
foreach ($CurrentUser in $PSMAccountDetailsArray) {
    $FailedToSearchAD = $false
    Write-LogMessage -type Verbose -MSG "Testing $UserType configuration"
    $Credential = $CurrentUser.Credentials
    $Username = $Credential.UserName
    $UserType = $CurrentUser.UserType
    if ($OperationsToPerform.UserTests) {
        try {
            # Search for user by name
            $UserDN = Get-UserDNFromSamAccountName -Username $Username
            If ($UserDN) {
                $UserObject = Get-UserObjectFromDN $UserDN # Search for the user
            }
            else {
                # If user was not found throw error
                $NewError = ""
                $NewError += ("User {0} not found in the domain. Please ensure the user exists and`n" -f $Username)
                $NewError += ("  that you have provided the pre-Windows 2000 logon name.")
                $ArrayOfUserErrors += $NewError
            }
        }
        catch {
            # Failed to search AD
            $NewError = ""
            $NewError += ("Failed to retrieve {0} user details from Active Directory." -f $Username)
            $NewError += ("Please ensure the user exists and is configured correctly and")
            $NewError += ("  that you have provided the pre-Windows 2000 logon name.")
            $ArrayOfUserErrors += $NewError
            $FailedToSearchAD = $true
            $ValidationFailed = $true
        }
    }
    if (($OperationsToPerform.UserTests) -and ($true -ne $FailedToSearchAD)) {
        try {
            # Test PSM user configuration
            $PSMUserConfigTestResult = Test-PSMUserConfiguration -UserType $UserType -UserObject $UserObject -PSMInstallLocation $psmRootInstallLocation
            Write-LogMessage -Type Verbose -MSG "Successfully checked user configuration"
            If ($PSMUserConfigTestResult.Result -ne "Success") {
                $UserConfigurationErrors += $PSMUserConfigTestResult.Errors
                Throw
            }
        }
        catch {
            $ValidationFailed = $true
        }
    }
}

# List detected PSM user configuration errors
Write-LogMessage -Type Verbose -MSG "Checking for user configuration errors"
If ($UserConfigurationErrors) {
    Write-LogMessage -Type Verbose -MSG "Listing detected user configuration errors"
    # Misconfigurations have been detected and will be listed by the following section
    $UsersWithConfigurationErrors = $UserConfigurationErrors.UserName | Select-Object -Unique # Get a list of the affected users
    $UsersWithConfigurationErrors | ForEach-Object { # For each user
        $User = $_
        $NewError = ("Configuration errors for {0} in Active Directory user properties:`n" -f $User)
        # Output simple misconfigurations in table format
        $ErrorTableSettings = $UserConfigurationErrors | Where-Object UserName -eq $user | Where-Object SettingType -in "Value", "LogOnTo"
        If ($ErrorTableSettings) {
            $NewError += "Settings:`n"
            $NewError += "---------`n"
            $NewError += (
                $ErrorTableSettings | Select-Object Username, SettingName, Expected, Current | Format-Table -Wrap -Property `
                @{Name = "SettingName"; Expression = { $_.SettingName }; Alignment = "Left" }, `
                @{Name = "Expected"; Expression = { $_.Expected }; Alignment = "Left" }, `
                @{Name = "Current"; Expression = { $_.Current }; Alignment = "Left" } | Out-String
            ).Trim()
            $NewError += "`n"
        }
        $ListUserConfigurationErrors = $UserConfigurationErrors | Where-Object UserName -eq $user | Where-Object SettingType -eq "StringCompare" # for more complex misconfigurations (strings), capture them separately
        If ($ListUserConfigurationErrors) {
            $NewError += "Paths:`n"
            $NewError += "------`n"
            foreach ($ConfigErrorSetting in $ListUserConfigurationErrors) {
                # and for each misconfiguration, ...
                $NewError += ("Setting: {0}`n" -f $ConfigErrorSetting.SettingName)
                $NewError += ("Expected value: `"{0}`"`n" -f $ConfigErrorSetting.Expected)
                $NewError += ("Detected value: `"{0}`"`n" -f $ConfigErrorSetting.Current)
                If ($ConfigErrorSetting.Current -ne "Unset") {
                    $DifferencePosition = Get-DifferencePosition -String1 $ConfigErrorSetting.Expected -String2 $ConfigErrorSetting.Current # get the location of the first difference
                    $NewError += ("                ` {0}^`n" -f (" " * $DifferencePosition)) # and display the position of the first difference
                }
            }
        }
        $ArrayOfUserErrors += $NewError.trim()
    }
    If ("Unset" -in $UserConfigurationErrors.Current) {
        $NewError = "Errors occurred while retrieving some user properties, which usually means they do not exist. These will show as `"Unset`" above.`n"
        $ArrayOfUserErrors += $NewError
    }
    #    Write-LogMessage -type Error -MSG "Please resolve the issues above or rerun this script with -SkipPSMUserTests to ignore these errors."
    $ValidationFailed = $true
}

$ArrayOfTinaErrors = @()

# Remote Configuration
## Test InstallerUser/Tina user credentials
If ($OperationsToPerform.TestInstallerUserCredentials) {
    try {
        If ($true -ne $InstallUserError) {
            # for each section, check that the previous section succeeded.
            Write-LogMessage -type Verbose -MSG "Testing install user credentials"
            $pvwaTokenResponse = New-ConnectionToRestAPI -pvwaAddress $PrivilegeCloudUrl -InstallUser $InstallUser
            if ($pvwaTokenResponse.ErrorCode -ne "Success") {
                # ErrorCode will always be "Success" if Invoke-RestMethod got a 200 response from server.
                # If it's anything else, it will have been caught by New-ConnectionToRestAPI error handler and an error response generated.
                # The error message shown could be from a JSON response, e.g. wrong password, or a connection error.
                $NewError = ""
                $NewError += "Logon to PVWA failed. Result:`n"
                $NewError += ("Error code: {0}`n" -f $pvwaTokenResponse.ErrorCode)
                $NewError += ("Error message: {0}" -f $pvwaTokenResponse.ErrorMessage)
                $ArrayOfTinaErrors += $NewError
                Throw
            }
            $PVWATokenIsValid = ($pvwaTokenResponse.Response -match "[0-9a-zA-Z]{200,256}")
            if ($false -eq $PVWATokenIsValid) {
                # If we get here, it means we got a 200 response from the server, but the data it returned was not a valid token.
                # In this case, we display the response we got from the server to aid troubleshooting.
                $NewError = ""
                $NewError += "Response from server was not a valid token:"
                $NewError += $pvwaTokenResponse.Response
                $ArrayOfTinaErrors += $NewError
                Throw
            }
            # If we get here, the token was retrieved successfully and looks valid. We'll still test it though.

            $PvwaTokenTestResponse = Test-PvwaToken -Token $pvwaTokenResponse.Response -pvwaAddress $PrivilegeCloudUrl
            if (($true -ne $InstallUserError) -and ($PvwaTokenTestResponse.ErrorCode -eq "Success")) {
                $pvwaToken = $pvwaTokenResponse.Response
            }
            else {
                $NewError = ""
                $NewError += "PVWA Token validation failed. Result:"
                $NewError += $PvwaTokenTestResponse.Response
                $ArrayOfTinaErrors += $NewError
                Throw
            }
            $ValidatedInputs = Update-ValidatedInputs -Object $ValidatedInputs -Input InstallUser -Value $InstallUser
        }
    }
    catch {
        $ValidationFailed = $true
    }
}

$ArrayOfUserOnboardingConflictErrors = @()
If ($OperationsToPerform.ExistingAccountCheck) {
    $AccountsToOnboard = @()
    If ($false -eq [string]::IsNullOrEmpty($pvwaToken)) { # double negative; read: "if $pvwaToken is set"
        Write-LogMessage -Type Verbose -MSG "Retrieving PSM user details from vault"
        $ExistingAccountsObj = Get-VaultAccountDetails -pvwaAddress $PrivilegeCloudUrl -pvwaToken $pvwaToken -safe $Safe
        Write-LogMessage -Type Verbose -MSG "Checking if the found accounts have the correct details"
        foreach ($AccountToCheck in $PSMAccountDetailsArray) {
            $ReqCredentials = $AccountToCheck.Credentials
            $ReqUserName = $ReqCredentials.UserName
            $ReqAccountName = $AccountToCheck.AccountName
            Write-LogMessage -type Verbose -MSG ("Checking if {0} exists in vault" -f $ReqUserName)
            $ExistingAccountObj = $ExistingAccountsObj | Where-Object name -eq $ReqAccountName
            If ($ExistingAccountObj) {
                Write-LogMessage -Type Verbose -MSG "Existing account found. Checking if it has the correct details."
                # an account with the same name already exists in the safe. Checking if the username and domain match
                $ExistingAccountAddress = $ExistingAccountObj.address
                $ExistingAccountUsername = $ExistingAccountObj.userName
                If (($ExistingAccountAddress -ne $DomainDNSName) -or ($ExistingAccountUsername -ne $ReqUserName)) {
                    $NewError = ""
                    $NewError += ("An object with Account Name `"{0}`" already exists in the safe `"{1}`" and `n" -f $ReqAccountName, $Safe)
                    $NewError += ("  its details do not match the specified user details. A comparison is below.`n" -f $ReqAccountName, $Safe)
                    $Comparison = @(
                        [PSCustomObject]@{
                            Account  = "Existing user"
                            Username = $ExistingAccountUsername
                            Address  = $ExistingAccountAddress
                        },
                        [PSCustomObject]@{
                            Account  = "New user"
                            Username = $ReqUserName
                            Address  = $DomainDNSName
                        }
                    )
                    $NewError += ($Comparison | Out-String).Trim()
                    $NewError += "`n"
                    $ArrayOfUserOnboardingConflictErrors += $NewError
                    $ValidationFailed = $true
                }
                else {
                    Write-LogMessage -Type Verbose -MSG "Existing account has the correct details. Will skip onboarding."
                }
            }
            else {
                # Account not found, will be onboarded
                Write-LogMessage -type Verbose -MSG "Account does not exist yet."
                $AccountsToOnboard += $AccountToCheck
            }
        }
    }
    else {
        Write-LogMessage -type Verbose -MSG "Skipping user onboarding conflict check as we have not authenticated to backend."
    }
}
else {
    Write-LogMessage -type Verbose -MSG "Skipping existing vaulted accounted check"
    $AccountsToOnboard = $PSMAccountDetailsArray
}

Write-LogMessage -type Verbose -MSG "Completed validation steps"

If ($ArrayOfUserErrors) {
    Write-LogMessage -type Error -MSG $SectionSeparator
    Write-LogMessage -type Error -MSG "The following errors occurred while validating the PSM user details."
    Write-LogMessage -type Error -MSG "These tests may be skipped by running Set-DomainUser with the -SkipPSMUserTests parameter."
    foreach ($UserError in $ArrayOfUserErrors) {
        Write-LogMessage -type Error -MSG $StandardSeparator
        Write-LogMessage -type Error -MSG $UserError
    }
}

If ($ArrayOfUserOnboardingConflictErrors) {
    Write-LogMessage -type Error -MSG $SectionSeparator
    Write-LogMessage -type Error -MSG "PSM users exist in the vault with details that do not match this environment."
    Write-LogMessage -type Error -MSG "See below for comparisons of the conflicting users."
    foreach ($UserConflict in $ArrayOfUserOnboardingConflictErrors) {
        Write-LogMessage -type Error -MSG $StandardSeparator
        Write-LogMessage -type Error -MSG $UserConflict
    }
    Write-LogMessage -type Error -MSG "This check can be skipped with the -SkipExistingAccountCheck parameter, or"
    Write-LogMessage -type Error -MSG "Use -PSMConnectAccountName, -PSMAdminConnectAccountName and -Safe parameters"
    Write-LogMessage -type Error -MSG "to provide alternative details for this environment."
}

If ($ArrayOfTinaErrors) {
    Write-LogMessage -type Error -MSG $SectionSeparator
    Write-LogMessage -type Error -MSG "The following errors occurred while validating the install user details:"
    Write-LogMessage -type Error -MSG $StandardSeparator
    foreach ($TinaError in $ArrayOfTinaErrors) {
        Write-LogMessage -type Error -MSG $TinaError
        Write-LogMessage -type Error -MSG $StandardSeparator
    }
}

# Save validated inputs
$ValidationSaveResult = Set-ValidatedInputs -Data $ValidatedInputs -OutputFile $ValidatedInputFile
If ($ValidationSaveResult) {
    Write-LogMessage -type Verbose -MSG ("Confirmed details saved to {0}." -f $ValidatedInputFileName)
}
else {
    Write-LogMessage -type Verbose -MSG ("An error occurred while saving confirmed details to {0}." -f $ValidatedInputFileName)
}

If ($ValidationFailed) {
    Write-LogMessage -type Info -MSG "Some tests failed, and details are shown above. Please correct these and rerun Set-DomainUser."
    exit 1
}
#Write-LogMessage -type Info -MSG "Please resolve any errors and run Set-DomainUser again to try again."

# Remote Configuration
If ($OperationsToPerform.CreateSafePlatformAndAccounts) {
    Write-LogMessage -type Info -MSG "Starting backend configuration"

    # Get platform info
    Write-LogMessage -Type Verbose -MSG "Checking current platform status"
    $platformStatus = Get-PlatformStatus -pvwaAddress $PrivilegeCloudUrl -pvwaToken $pvwaToken -PlatformId $PlatformName
    if ($platformStatus -eq $false) {
        # function returns false if platform does not exist
        # Get Platform ID for duplication
        $WinDomainPlatform = Get-PlatformStatusById -pvwaAddress $PrivilegeCloudUrl -pvwaToken $pvwaToken -PlatformId WinDomain
        If ($WinDomainPlatform) {
            Write-LogMessage -Type Verbose -MSG "Checking Windows Domain platform status"
            $WinDomainPlatformId = $WinDomainPlatform.Id
        }
        else {
            # Get-PlatformStatus returns false if platform not found
            Write-LogMessage -type Error -MSG "Could not find Windows Domain platform to duplicate. Please import it from the marketplace."
            exit 1
        }
        # Creating Platform
        Write-LogMessage -Type Verbose -MSG "Creating new platform"
        Copy-Platform -pvwaAddress $PrivilegeCloudUrl -pvwaToken $pvwaToken -CurrentPlatformId $WinDomainPlatformId -NewPlatformName $PlatformName -NewPlatformDescription "Platform for PSM accounts"
        $TasksTop += @{
            Message  = ("Set appropriate policies and settings on platform `"{0}`"" -f $PlatformName)
            Priority = "Recommended"
        }
        # Get platform info again so we can ensure it's activated
        $platformStatus = Get-PlatformStatus -pvwaAddress $PrivilegeCloudUrl -pvwaToken $pvwaToken -PlatformId $PlatformName
    }
    #    else {
    #        Write-LogMessage -Type Verbose -MSG ('Platform {0} already exists. Please verify it meets requirements.' -f $PlatformName)
    #        $TasksTop += @{
    #            Message  = ("Enable automatic password management for the PSM accounts")
    #            Priority = "Recommended"
    #        }
    #    }
    if ($platformStatus.Active -eq $false) {
        Write-LogMessage -Type Verbose -MSG "Platform is deactivated. Activating."
        Enable-Platform -pvwaAddress $PrivilegeCloudUrl -pvwaToken $pvwaToken -Platform $platformStatus.Id
    }
    Write-LogMessage -Type Verbose -MSG "Checking current safe status"
    $safeStatus = Get-SafeStatus -pvwaAddress $PrivilegeCloudUrl -pvwaToken $pvwaToken -SafeName $Safe
    if ($safeStatus -eq $false) {
        # function returns false if safe does not exist
        Write-LogMessage -Type Verbose -MSG "Safe $Safe does not exist. Creating the safe now"
        $CreateSafeResult = New-PSMSafe -pvwaAddress $PrivilegeCloudUrl -pvwaToken $pvwaToken -safe $Safe
        If ($CreateSafeResult) {
            Write-LogMessage -type Verbose "Successfully created safe $safe"
        }
        else {
            Write-LogMessage -Type Error -MSG "Creating PSM safe $Safe failed. Please resolve the error and try again."
            exit 1
        }
    }
    #    If (!($safeStatus.managingCpm)) {
    #        # Safe exists but no CPM assigned
    #        Write-LogMessage -Type Verbose -MSG ("There is no Password Manager (CPM) assigned to safe `"{0}`"" -f $Safe)
    #        $TasksTop += @{
    #            Message  = ("Assign a Password Manager (CPM) to safe `"{0}`"" -f $Safe)
    #            Priority = "Recommended"
    #        }
    #    }
    # Giving Permission on the safe if we are using UM, The below will give full permission to vault admins
    If ($UM) {
        $SafePermissions = Get-SafePermissions -pvwaAddress $PrivilegeCloudUrl -pvwaToken $pvwaToken -safe $safe -safeMember "Vault Admins"
        If ($false -eq $SafePermissions) {
            # Vault Admins does not appear to be a member of the safe. Adding.
            Write-LogMessage -Type Verbose -MSG "Granting administrators access to PSM safe"
            New-SafePermissions -pvwaAddress $PrivilegeCloudUrl -pvwaToken $pvwaToken -safe $safe -safeMember "Vault Admins"
        }
    }

    foreach ($AccountToOnboard in $AccountsToOnboard) {
        $NewCredentials = $AccountToOnboard.Credentials
        $NewUserName = $NewCredentials.UserName
        $NewAccountName = $AccountToOnboard.AccountName
        Write-LogMessage -type Verbose -MSG ("Onboarding {0}" -f $NewUserName)
        Write-LogMessage -Type Verbose -MSG "Onboarding Account"
        $OnboardResult = New-VaultAdminObject -pvwaAddress $PrivilegeCloudUrl -pvwaToken $pvwaToken -name $NewAccountName -domain $DomainDNSName -Credentials $NewCredentials -platformID $PlatformName -safe $safe
        If ($OnboardResult.name) {
            Write-LogMessage -Type Verbose -MSG "User successfully onboarded"
        }
        ElseIf ($OnboardResult.ErrorCode -eq "PASWS027E") {
            $UserType = $AccountToOnboard.UserType
            Write-LogMessage -Type Warning -MSG "Object with name $NewAccountName already exists. Please verify that it contains correct"
            Write-LogMessage -Type Warning -MSG "  $UserType account details, or specify an alternative account name."
            $TasksTop += @{
                Message  = ("Verify that the {0} object in {1} safe contains correct {2} user details" -f $NewAccountName, $safe, $UserType)
                Priority = "Required"
            }
        }
        Else {
            Write-LogMessage -Type Error -MSG ("Error onboarding account: {0}" -f $OnboardResult)
            exit 1
        }
    }
}

If ($OperationsToPerform.ServerObjectConfiguration) {
    Write-LogMessage -type Verbose -MSG "Configuring backend PSM server objects"
    $VaultAddress = Get-VaultAddress -psmRootInstallLocation $psmRootInstallLocation
    $PossibleVaultOperationsTesterLocations = @(
        "$ScriptLocation\VaultOperationsTester\VaultOperationsTester.exe",
        "$ScriptLocation\..\VaultOperationsTester\VaultOperationsTester.exe",
        "$ScriptLocation\..\..\VaultOperationsTester\VaultOperationsTester.exe"
    )
    foreach ($Possibility in $PossibleVaultOperationsTesterLocations) {
        If (Test-Path -PathType Leaf -Path $Possibility) {
            $VaultOperationsTesterExe = Get-Item $Possibility
            break
        }
    }

    If ($null -eq $VaultOperationsTesterExe) {
        Write-LogMessage -type Error -MSG "VaultOperationsTester.exe not found. Please ensure it's present in one of the following locations:"
        Write-LogMessage -type Error -MSG ("  - " + (((Get-Item $ScriptLocation\..\..).FullName) + "\VaultOperationsTester"))
        Write-LogMessage -type Error -MSG ("  - " + (((Get-Item $ScriptLocation\..).FullName) + "\VaultOperationsTester"))
        Write-LogMessage -type Error -MSG ("  - " + (((Get-Item $ScriptLocation).FullName) + "\VaultOperationsTester"))
        Write-LogMessage -type Error -MSG ("  or run this script with the -SkipPSMObjectUpdate option and perform the required configuration manually.")
        exit 1
    }

    If ("Valid" -ne (Get-AuthenticodeSignature $VaultOperationsTesterExe).Status) {
        Write-LogMessage -type Error -MSG "VaultOperationsTester.exe signature validation failed. Please replace with a correctly signed version"
        Write-LogMessage -type Error -MSG ("  or run this script with the -SkipPSMObjectUpdate option and perform the required configuration manually.")
        exit 1
    }

    $VaultOperationsTesterDir = (Get-Item $VaultOperationsTesterExe).Directory
    # Check that VaultOperationsTester is available
    # Check for and install C++ Redistributable
    if ($false -eq (Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\VisualStudio\12.0\VC\Runtimes\x86" -PathType Container)) {
        $CppRedis = "$VaultOperationsTesterDir\vcredist_x86.exe"
        If ($false -eq (Test-Path -PathType Leaf -Path $CppRedis)) {
            Write-LogMessage -type Error -MSG "File not found: $CppRedis"
            Write-LogMessage -type Error -MSG "Visual Studio 2013 x86 Runtime not installed and redistributable not found. Please resolve the issue, install manually"
            Write-LogMessage -type Error -MSG "  or run this script with the -SkipPSMObjectUpdate option and perform the required configuration manually."
            exit 1
        }
        Write-LogMessage -type Info -MSG "Installing Visual Studio 2013 (VC++ 12.0) x86 Runtime from $CppRedis..."
        try {
            $null = Start-Process -FilePath $CppRedis -ArgumentList "/install /passive /norestart" -Wait
        }
        catch {
            Write-LogMessage -type Error -MSG "Failed to install Visual Studio 2013 x86 Redistributable. Resolve the error"
            Write-LogMessage -type Error -MSG "  or run this script with the -SkipPSMObjectUpdate option and perform the required configuration manually."
            exit 1
        }
    }

    # after C++ redistributable install
    try {
        $VotProcess = Set-PSMServerObject -VaultAddress $VaultAddress `
            -VaultCredentials $InstallUser `
            -PSMServerId $PSMServerId `
            -VaultOperationsFolder $VaultOperationsTesterDir `
            -PSMSafe $Safe `
            -PSMConnectAccountName $PSMConnectAccountName `
            -PSMAdminConnectAccountName $PSMAdminConnectAccountName `
            -Proxy $Proxy
    }
    catch {
        Write-LogMessage -type Error -MSG "Failed to configure PSM Server object in vault. Please review the VaultOperationsTester log and resolve any errors"
        Write-LogMessage -type Error -MSG "  or run this script with the -SkipPSMObjectUpdate option and perform the required configuration manually."
        exit 1
    }
    If ($true -ne $VotProcess.Result) {
        Write-LogMessage -type Error -MSG "Failed to configure PSM Server object in vault. Please review the VaultOperationsTester log and resolve any errors"
        Write-LogMessage -type Error -MSG "  or run this script with the -SkipPSMObjectUpdate option and perform the required configuration manually."
        Write-LogMessage -type Error -MSG ("Error Code:    {0}" -f $VotProcess.ErrorCode)
        Write-LogMessage -type Error -MSG ("Error Details: {0}" -f $VotProcess.ErrorDetails)
        exit 1
    }
}

## End Remote Configuration Block

# Perform local configuration
# Group membership and security policy changes
$PsmConnectUser = ("{0}\{1}" -f $DomainNetbiosName, $psmConnectCredentials.UserName)
$PsmAdminConnectUser = ("{0}\{1}" -f $DomainNetbiosName, $psmAdminCredentials.UserName)

If ($OperationsToPerform.SecurityPolicyConfiguration) {
    If (!(Test-Path -Path $BackupPath -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $BackupPath
    }
    $CurrentSecurityPolicyFile = "$BackupPath\CurrentSecurityPolicy.cfg"
    $GetSecPolResult = Get-CurrentSecurityPolicy -OutFile $CurrentSecurityPolicyFile -LogFile $BackupPath\SeceditExport.log
    If ($false -eq $GetSecPolResult) {
        Write-LogMessage -type Verbose -MSG "Security policy export failed, so the current policy will not be modified."
        Write-LogMessage -type Verbose -MSG "Please edit local security policy manually to allow PSM users to log on with Remote Desktop."
        $TasksTop += @{
            Message  = "Configure Local Security Policy to allow PSM users to log on with Remote Desktop"
            Priority = "Required"
        }
    }
    If ($GetSecPolResult) {
        $Content = Get-Content $CurrentSecurityPolicyFile
        $null = $Content | Where-Object { $_ -match "^SeRemoteInteractiveLogonRight = (.*)" }
        $SecPolCurrentUsersString = $Matches[1]
        $SecPolUsersArray = ($SecPolCurrentUsersString -split ",")
        $SecPolUsersArray += @($PsmConnectUser, $PsmAdminConnectUser)
        $SecPolNewUsersString = $SecPolUsersArray -join ","
        $null = New-Item -Path "$BackupPath\newsecpol.cfg" -ItemType File -Force
        Add-Content -Path "$BackupPath\newsecpol.cfg" -Value '[Version]'
        Add-Content -Path "$BackupPath\newsecpol.cfg" -Value 'signature="$CHICAGO$"'
        Add-Content -Path "$BackupPath\newsecpol.cfg" -Value 'Revision=1'
        Add-Content -Path "$BackupPath\newsecpol.cfg" -Value '[Privilege Rights]'
        Add-Content -Path "$BackupPath\newsecpol.cfg" -Value ("SeRemoteInteractiveLogonRight = {0}" -f $SecPolNewUsersString)
        $SetSecPolResult = Set-CurrentSecurityPolicy -DatabaseFile $BackupPath\SecurityPolicy.sdb -ConfigFile $BackupPath\newsecpol.cfg -LogFile $BackupPath\SecPolImport.log
    }
    If ($false -eq $SetSecPolResult) {
        Write-LogMessage -type Error -MSG "Failed to configure local security policy."
        Write-LogMessage -type Warning -MSG "Please edit local security policy manually to allow PSM users to log on with Remote Desktop."
        $TasksTop += @{
            Message  = "Configure Local Security Policy to allow PSM users to log on with Remote Desktop"
            Priority = "Required"
        }
    }
}
else {
    $TasksTop += @{
        Message  = "Configure Local Security Policy to allow PSM users to log on with Remote Desktop"
        Priority = "Required"
    }
}

$TasksTop += @{
    Message  = "Ensure domain GPOs allow PSM users to log on to PSM servers with Remote Desktop"
    Priority = "Required"
}

If ($OperationsToPerform.RemoteDesktopUsersGroupAddition) {
    try {
        $Members = (Get-LocalGroupMember -Group "Remote Desktop Users").Name
        If ($PsmConnectUser -notin $Members) {
            Add-LocalGroupMember -Group "Remote Desktop Users" -Member $PsmConnectUser
        }
        If ($PsmAdminConnectUser -notin $Members) {
            Add-LocalGroupMember -Group "Remote Desktop Users" -Member $PsmAdminConnectUser
        }
    }
    catch {
        Write-Host $_.Exception
        Write-LogMessage -type Error -MSG "Failed to add PSM users to Remote Desktop Users group. Please add these users manually."
        $TasksTop += @{
            Message  = "Add PSM users to Remote Desktop Users group"
            Priority = "Required"
        }
    }
}
else {
    $TasksTop += @{
        Message  = "Add PSM users to Remote Desktop Users group"
        Priority = "Required"
    }
}

# End group membership and security policy changes

# Perform local configuration
If ($OperationsToPerform.PsmConfiguration) {
    Write-LogMessage -Type Info -MSG "Performing local configuration and restarting service"

    Write-LogMessage -Type Verbose -MSG "Stopping CyberArk Privileged Session Manager Service"
    Stop-Service $REGKEY_PSMSERVICE
    Write-LogMessage -Type Verbose -MSG "Backing up PSM configuration files and scripts"
    Backup-PSMConfig -psmRootInstallLocation $psmRootInstallLocation -BackupPath $BackupPath
    Write-LogMessage -Type Verbose -MSG "Updating PSM configuration files and scripts"
    Update-PSMConfig -psmRootInstallLocation $psmRootInstallLocation -domain $DomainDNSName -PSMAdminConnectAccountName $PSMAdminConnectAccountName -PsmConnectUsername $psmConnectCredentials.username.Replace('\', '') -PsmAdminUsername $psmAdminCredentials.username.Replace('\', '')
    #TODO: Update Basic_ini
    Write-LogMessage -Type Verbose -MSG "Adding PSMAdminConnect user to Terminal Services configuration"
    # Adding PSMAdminConnect user to Terminal Services configuration
    $AddAdminUserToTSResult = Add-AdminUserToTS -NETBIOS $DomainNetbiosName -Credentials $psmAdminCredentials
    If ($AddAdminUserToTSResult.ReturnValue -eq 0) {
        Write-LogMessage -Type Verbose -MSG "Successfully added PSMAdminConnect user to Terminal Services configuration"
    }
    else {
        # Failed to add user (1st command)
        if ($IgnoreShadowPermissionErrors) {
            Write-LogMessage -Type Warning -MSG $AddAdminUserToTSResult.Error
            Write-LogMessage -Type Warning -MSG "Failed to add PSMAdminConnect user to Terminal Services configuration."
            Write-LogMessage -Type Warning -MSG "Continuing because `"-IgnoreShadowPermissionErrors`" switch enabled"
            $TasksTop += @{
                Message  = "Resolve issue preventing PSMAdminConnect user being added to Terminal Services configuration and rerun this script"
                Priority = "Required"
            }
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
        $AddAdminUserTSShadowPermissionResult = Add-AdminUserTSShadowPermission -NETBIOS $DomainNetbiosName -Credentials $psmAdminCredentials
        If ($AddAdminUserTSShadowPermissionResult.ReturnValue -eq 0) {
            Write-LogMessage -Type Verbose -MSG "Successfully granted PSMAdminConnect permission to shadow sessions"
        }
        else {
            # Failed to grant permission (2nd command)
            if ($IgnoreShadowPermissionErrors) {
                Write-LogMessage -Type Warning -MSG $AddAdminUserTSShadowPermissionResult.Error
                Write-LogMessage -Type Warning -MSG "Failed to grant PSMAdminConnect permission to shadow sessions."
                Write-LogMessage -Type Warning -MSG "Continuing because `"-IgnoreShadowPermissionErrors`" switch enabled"
                $TasksTop += @{
                    Message  = "Resolve issue preventing PSMAdminConnect user being granted permission to shadow sessions and rerun this script."
                    Priority = "Required"
                }
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
}
## End Local Configuration Block

# Post-configuration
## Invoke hardening scripts and restart service
If ($OperationsToPerform.Hardening) {
    Write-LogMessage -Type Info -MSG "Running PSM Hardening script"
    Write-LogMessage -Type Info -MSG "---"
    Invoke-PSMHardening -psmRootInstallLocation $psmRootInstallLocation
    Write-LogMessage -Type Info -MSG "---"
    Write-LogMessage -Type Info -MSG "End of PSM Hardening script output"
}
else {
    Write-LogMessage -Type Warning -MSG "Skipping Hardening due to -DoNotHarden parameter"
    $TasksTop += @{
        Message  = "Run script to perform server hardening (PSMHardening.ps1)"
        Priority = "Required"
    }
}
If ($OperationsToPerform.ConfigureAppLocker) {
    Write-LogMessage -Type Info -MSG "Running PSM Configure AppLocker script"
    Write-LogMessage -Type Info -MSG "---"
    Invoke-PSMConfigureAppLocker -psmRootInstallLocation $psmRootInstallLocation
    Write-LogMessage -Type Info -MSG "---"
    Write-LogMessage -Type Info -MSG "End of PSM Configure AppLocker script output"
}
else {
    Write-LogMessage -Type Warning -MSG "Skipping configuration of AppLocker due to -DoNotConfigureAppLocker parameter"
    $TasksTop += @{
        Message  = "Run script to configure AppLocker (PSMConfigureAppLocker.ps1)"
        Priority = "Required"
    }
}
Write-LogMessage -Type Verbose -MSG "Restarting CyberArk Privileged Session Manager Service"
Restart-Service $REGKEY_PSMSERVICE

Write-LogMessage -Type Success -MSG "All tasks completed."

$RequiredTasks = @()
If ($SkipPSMObjectUpdate -or $LocalConfigurationOnly) {
    $RequiredTasks += @(
        @{ Message   = `
            ("Update the PSM Server configuration:`n") + `
            ("     a. Log in to Privilege Cloud as an administrative user`n") + `
            ("     b. Go to Administration -> Configuration Options`n") + `
            ("     c. Expand Privileged Session Management -> Configured PSM Servers -> {0} -> `n" -f $PSMServerId) + `
            ("          Connection Details -> Server`n") + `
            ("     d. Configure the following:`n") + `
            ("          Safe: {0}`n" -f $Safe) + `
            ("          Object: {0}`n" -f $PSMConnectAccountName) + `
            ("          AdminObject: {0}" -f $PSMAdminConnectAccountName)
            Priority = "Required"
        }
    )
}

$TasksTop += @{
    Message  = ("Ensure automatic password management is configured for the PSM accounts")
    Priority = "Recommended"
}

# Display summary and additional tasks
$RequiredTasks += $TasksTop | Where-Object Priority -eq "Required"
$RequiredTasks += @{ Message = "Restart Server"; Priority = "Required" }
$RecommendedTasks = $TasksTop | Where-Object Priority -ne "Required"

# Print recommended tasks

Write-LogMessage -type Info -MSG $SectionSeparator
$string = "The following additional steps are recommended:"
Write-LogMessage -type Info -MSG ($string)

$i = 1
foreach ($Task in $RecommendedTasks) {
    Write-LogMessage -Type Info -MSG (" {0:D2}. {1}" -f $i, $Task.Message)
    $i++
}

Write-LogMessage -type Info -MSG " " # Print a gap

# Print required tasks

Write-LogMessage -type Info -MSG $SectionSeparator
$string = "The following additional tasks MUST be completed:"
Write-LogMessage -type Info -MSG ($string)

$i = 1
foreach ($Task in $RequiredTasks) {
    Write-LogMessage -Type Info -MSG (" {0:D2}. {1}" -f $i, $Task.Message)
    $i++
}

Write-LogMessage -type Info -MSG " "