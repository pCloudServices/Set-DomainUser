<#
.SYNOPSIS
This script will update the connector server to a domain user setup. It will also onboard the domain users into the portal inside the PSM safe.
.DESCRIPTION
Does the Domain User for PSM setup.
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
.PARAMETER NotFirstRun
This script is being run on additional servers following the first. Skip platform and safe creation and account onboarding.
#>

# Version: 14.1.0

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
        HelpMessage = "Safe and platform configuration and account onboarding should be skipped as the script is being run on subsequent PSM servers.")]
    [switch]$NotFirstRun,

    [Parameter(
        Mandatory = $false,
        HelpMessage = "Proxy Server in address:port format or `"none`" for no proxy")]
    [string]$Proxy
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
    Write-LogMessage -type Verbose -MSG "Detecting proxy from user profile"
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
        $null = Invoke-RestMethod -Method 'Post' -Uri $url -Headers @{ 'Authorization' = $pvwaToken } -ContentType 'application/json' -WebSession $Global:WebRequestSession
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
    if ($Credential.username.Length -gt 20) {
        return $false
    }
    return $true
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

#Running Set-DomainUser script

$OperationsToPerform = @{
    GetInstallerUserCredentials       = $true
    GetPSMConnectUserCredentials      = $true
    GetPSMAdminConnectUserCredentials = $true
    UserTests                         = $true
    GetPrivilegeCloudUrl              = $true
    DomainNetbiosNameDetection        = $true
    DomainDNSNameDetection            = $true
    PsmConfiguration                  = $true
    SecurityPolicyConfiguration       = $true
    RemoteDesktopUsersGroupAddition   = $true
    RemoteConfiguration               = $true
    ServerObjectConfiguration         = $true
    Hardening                         = $true
    ConfigureAppLocker                = $true
    DetectProxy                       = $true
}

switch ($PSBoundParameters) {
    { $_.psmConnectCredentials } {
        $OperationsToPerform.GetPSMConnectUserCredentials = $false
    }
    { $_.psmAdminCredentials } {
        $OperationsToPerform.GetPSMAdminConnectUserCredentials = $false
    }
    { $_.NotFirstRun } {
        $OperationsToPerform.UserTests = $false
        $OperationsToPerform.RemoteConfiguration = $false
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
        $OperationsToPerform.RemoteConfiguration = $false
        $OperationsToPerform.ServerObjectConfiguration = $false
        $OperationsToPerform.UserTests = $false
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
If (!($OperationsToPerform.RemoteConfiguration -or $OperationsToPerform.ServerObjectConfiguration)) {
    $OperationsToPerform.DetectProxy = $false
    $Proxy = "None"
}

$global:InVerbose = $PSBoundParameters.Verbose.IsPresent
$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path
$global:LOG_FILE_PATH = "$ScriptLocation\_Set-DomainUser.log"

if ($OperationsToPerform.GetPSMConnectUserCredentials) {
    $psmConnectCredentials = Get-Credential -Message "Please enter PSMConnect domain user credentials"
    if (!($psmConnectCredentials)) {
        Write-LogMessage -Type Error -MSG "No credentials provided. Exiting."
        exit 1
    }
}

if ($OperationsToPerform.GetPSMAdminConnectUserCredentials) {
    $psmAdminCredentials = Get-Credential -Message "Please enter PSMAdminConnect domain user credentials"
    if (!($psmAdminCredentials)) {
        Write-LogMessage -Type Error -MSG "No credentials provided. Exiting."
        exit 1
    }
}

$PsmServiceNames = "Cyber-Ark Privileged Session Manager", "CyberArk Privileged Session Manager"
$PsmService = Get-Service | Where-Object Name -in $PsmServiceNames
$REGKEY_PSMSERVICE = $PsmService.Name
$psmRootInstallLocation = ($(Get-ServiceInstallPath $REGKEY_PSMSERVICE)).Replace("CAPSM.exe", "").Replace('"', "").Trim()

If (Check-UM -psmRootInstallLocation $psmRootInstallLocation) {
    $UM = $true
}
else {
    $UM = $false
}

$BackupSubDirectory = (Get-Date).ToString('yyyMMdd-HHmmss')
$BackupPath = "$psmRootInstallLocation\Backup\Set-DomainUser\$BackupSubDirectory"

$TasksTop = @()

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
    Write-LogMessage -Type Error -MSG "Username provided for PSMConnect user contained invalid characters or is too long."
    Write-LogMessage -Type Error -MSG "Please provide the pre-Windows 2000 username without DOMAIN\ or @domain, and ensure"
    Write-LogMessage -Type Error -MSG "the username is no more than 20 characters long"
    exit 1
}

If (!(Test-CredentialFormat -Credential $psmAdminCredentials)) {
    Write-LogMessage -Type Error -MSG "Username provided for PSMAdminConnect user contained invalid characters or is too long."
    Write-LogMessage -Type Error -MSG "Please provide the pre-Windows 2000 username without DOMAIN\ or @domain, and ensure"
    Write-LogMessage -Type Error -MSG "the username is no more than 20 characters long"
    exit 1
}

if ($OperationsToPerform.UserTests) {
    If (!(Test-PasswordCharactersValid -Credential $psmConnectCredentials)) {
        Write-LogMessage -Type Error -MSG "Password provided for PSMConnect user contained invalid characters."
        Write-LogMessage -Type Error -MSG 'Please include only alphanumeric and the following characters: ~!@#$%^&*_-+=`|(){}[]:;"''<>,.?\/'
        exit 1
    }


    If (!(Test-PasswordCharactersValid -Credential $psmAdminCredentials)) {
        Write-LogMessage -Type Error -MSG "Password provided for PSMAdminConnect user contained invalid characters."
        Write-LogMessage -Type Error -MSG 'Please include only alphanumeric and the following characters: ~!@#$%^&*_-+=`|(){}[]:;"''<>,.?\/'
        exit 1
    }
}


# Get-Variables
if ($OperationsToPerform.GetPrivilegeCloudUrl) {
    Write-LogMessage -Type Verbose -MSG "Getting PVWA address"
    $PrivilegeCloudUrl = Get-PvwaAddress -psmRootInstallLocation $psmRootInstallLocation
}
If ($false -eq $PrivilegeCloudUrl) {
    Write-LogMessage -Type Error -MSG "Unable to detect PVWA address automatically. Please rerun script and provide it using the -PrivilegeCloudUrl parameter."
    exit 1
}

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
If ($DomainNameAutodetected) {

    $DomainInfo = ("--------------------------------------------------------`nDetected the following domain names:`n  DNS name:     {0}`n  NETBIOS name: {1}`nIs this correct?" -f $DomainDNSName, $DomainNetbiosName)

    $PromptOptions = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
    $PromptOptions.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList "&Yes", "Confirm the domain details are correct"))
    $PromptOptions.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList "&No", "Exit the script so correct domain details can be provided"))

    $DomainPromptSelection = $Host.UI.PromptForChoice("", $DomainInfo, $PromptOptions, 1)
    If ($DomainPromptSelection -eq 0) {
        Write-LogMessage -Type Info "Domain details confirmed"
    }
    Else {
        Write-LogMessage -Type Error -MSG "Please rerun the script and provide the correct domain DNS and NETBIOS names on the command line."
        exit 1
    }
}

If ($OperationsToPerform.DetectProxy) {
    # Get proxy details from user profile
    $DetectedProxy = Get-ProxyDetails

    If ($DetectedProxy) {
        $ProxyInfo = ("--------------------------------------------------------`nDetected the following proxy details:`n  Proxy Address:     {0}`nIs this correct?" -f $DetectedProxy)

        $PromptOptions = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
        $PromptOptions.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList "&Yes", "Confirm the proxy details are correct"))
        $PromptOptions.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList "&No", "Exit the script so correct proxy details can be provided"))

        $ProxyPromptSelection = $Host.UI.PromptForChoice("", $ProxyInfo, $PromptOptions, 1)
        If ($ProxyPromptSelection -eq 0) {
            Write-LogMessage -Type Info "Proxy details confirmed"
            $Proxy = $DetectedProxy
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

$Global:WebRequestSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
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

$Global:WebRequestSession.Proxy = $ProxyObject

if ($OperationsToPerform.UserTests) {
    # Gather the information we'll be comparing
    $PSMComponentsPath = $psmRootInstallLocation + "Components"
    $PSMInitSessionPath = $PSMComponentsPath + "\PSMInitSession.exe"

    # Get PSMConnect user information
    $UsersToCheck = @(
        @{
            UserType = "PSMConnect"
            Username = $psmConnectCredentials.UserName
        },
        @{
            UserType = "PSMAdminConnect"
            Username = $psmAdminCredentials.UserName
        }
    )
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
            DisplayName   = "Log On To Restrictions"
            ExpectedValue = $env:computername
            SettingType   = "LogOnTo"
        }
    )

    # Initialise array which will capture detected misconfigurations
    $UserConfigurationErrors = @()
    $UsersToCheck | ForEach-Object { # For each of PSMConnect and PSMAdminConnect
        $UserType = $_.UserType
        $Username = $_.Username

        try {
            $UserDN = Get-UserDNFromSamAccountName -Username $Username
            If ($UserDN) {
                $UserObject = Get-UserObjectFromDN $UserDN # Search for the user
            }
            else {
                # If user was not found throw error
                Write-LogMessage -type Error -MSG ("User {0}\{1} not found. Please ensure the user exists and" -f $DomainNetbiosName, $Username)
                Write-LogMessage -type Error -MSG ("  that you have provided the pre-Windows 2000 logon name or")
                Write-LogMessage -type Error -MSG ("  run this script with the -SkipPSMUserTests option to skip this check.")
                exit 1
            }
        }
        catch {
            # Failed to search AD
            Write-LogMessage -type Error -MSG ("Failed to retrieve {0}\{1} user details from Active Directory." -f $DomainNetbiosName, $Username)
            Write-LogMessage -type Error -MSG ("Please ensure the user exists and is configured correctly and")
            Write-LogMessage -type Error -MSG ("  that you have provided the pre-Windows 2000 logon name or")
            Write-LogMessage -type Error -MSG ("  and run this script again, or run the script with the ")
            Write-LogMessage -type Error -MSG ("  -SkipPSMUserTests flag to skip this check.")
            exit 1
        }
        $SettingsToCheck | Where-Object SettingType -in "Value", "StringCompare" | ForEach-Object { # For each aspect of the configuration
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
                If ($SettingCurrentValue -notin $SettingExpectedValue) {
                    # If the current configuration is not set to one of the acceptable values
                    $UserConfigurationErrors += [PSCustomObject]@{ # add it to the array containing the list of misconfigurations
                        Username    = $Username
                        User        = $UserType
                        SettingName = $SettingDisplayName
                        Current     = $SettingCurrentValue
                        Expected    = $SettingExpectedValue
                        SettingType = $SettingType
                    }
                }
            }
        }
        $SettingsToCheck  | Where-Object SettingType -in "LogOnTo" | ForEach-Object { # Check Logon restrictions
            $UsersWithoutComputerNameInLogonRestrictions = @()
            $SettingName = $_.Name
            $SettingAllowedWorkstations = Get-UserProperty -UserObject $UserObject -Property $SettingName
            $SettingExpectedValue = $_.ExpectedValue
            If ($SettingAllowedWorkstations) {
                $SettingAllowedWorkstations = $SettingAllowedWorkstations.Split(",")
                If ($SettingExpectedValue -notin $SettingAllowedWorkstations) {
                    Write-LogMessage -type Warning -MSG ("Computer name {0} missing from `"Log on to`" setting for {1}" -f $env:computername, $Username)
                    $UsersWithoutComputerNameInLogonRestrictions += "$Username"
                    $TasksTop += @{
                        Message  = ("Add {0} to the `"Log On To`" section for user {1}" -f $env:computername, $Username)
                        Priority = "High"
                    }
                }
            }
        }
    }
    
    If ($UserConfigurationErrors) {
        # Misconfigurations have been detected and will be listed by the following section
        $UsersWithConfigurationErrors = $UserConfigurationErrors.User | Select-Object -Unique # Get a list of the affected users
        $UsersWithConfigurationErrors | ForEach-Object { # For each user
            $User = $_
            Write-LogMessage -Type Info -MSG ("Configuration errors for {0}:" -f $User)
            $UserConfigurationErrors | Where-Object User -eq $user | Where-Object SettingType -eq "Value" | Select-Object Username, SettingName, Expected, Current | Format-Table -Wrap # Output simple misconfigurations in table format
            $ListUserConfigurationErrors = $UserConfigurationErrors | Where-Object User -eq $user | Where-Object SettingType -eq "StringCompare" # for more complex misconfigurations (strings), capture them separately
            If ($ListUserConfigurationErrors) {
                Write-LogMessage -type Info -MSG "-----"
                foreach ($ConfigErrorSetting in $ListUserConfigurationErrors) {
                    # and for each misconfiguration, output the
                    Write-LogMessage -type Info -MSG ("Setting: {0}" -f $ConfigErrorSetting.SettingName)
                    Write-LogMessage -type Info -MSG ("Expected value: `"{0}`"" -f $ConfigErrorSetting.Expected) # expected value and
                    Write-LogMessage -type Info -MSG ("Detected value: `"{0}`"" -f $ConfigErrorSetting.Current) # current value
                    If ($ConfigErrorSetting.SettingType -eq "StringCompare") {
                        $DifferencePosition = $( # work out the position where the current value differs from the expected value by comparing them 1 character at a time
                            $ExpectedValueLength = $ConfigErrorSetting.Expected.length
                            $i = 0
                            While ($i -le $ExpectedValueLength) {
                                If ($ConfigErrorSetting.Expected[$i] -eq $ConfigErrorSetting.Current[$i]) {
                                    $i++
                                }
                                else {
                                    $DifferencePosition = $i
                                    $DifferencePosition
                                    break
                                }
                            }
                        )
                        Write-LogMessage -type Info -MSG ("                ` {0}^" -f (" " * $DifferencePosition)) # display the position of the first difference
                    }
                    Write-LogMessage -type Info -MSG "-----"
                }
            }
        }
        If ("Unset" -in $UserConfigurationErrors.Current) {
            Write-LogMessage -type Error -MSG "Errors occurred while retrieving some user properties, which usually means they do not exist. These will show as `"Unset`" above."◙
        }
        Write-LogMessage -type Error -MSG "Please resolve the issues above or rerun this script with -SkipPSMUserTests to ignore these errors."
        exit 1
    }

    # Test PSM credentials
    if (ValidateCredentials -domain $DomainDNSName -Credential $psmConnectCredentials) {
        Write-LogMessage -Type Verbose -MSG "PSMConnect user credentials validated"
    }
    else {
        Write-LogMessage -Type Error -MSG "PSMConnect user validation failed. Please validate PSMConnect user name and password or run script with -SkipPSMUserTests to skip this test"
        exit 1
    }
    if (ValidateCredentials -domain $DomainDNSName -Credential $psmAdminCredentials) {
        Write-LogMessage -Type Verbose -MSG "PSMAdminConnect user credentials validated"
    }
    else {
        Write-LogMessage -Type Error -MSG "PSMAdminConnect user validation failed. Please validate PSMAdminConnect user name and password or run script with -SkipPSMUserTests to skip this test."
        exit 1
    }
}

# Reverse logic on script invocation setting because double negatives suck
$PSMServerId = Get-PSMServerId -psmRootInstallLocation $psmRootInstallLocation

## Remote Configuration Block
If ($OperationsToPerform.GetInstallerUserCredentials) {
    if ($null -eq $InstallUser) {
        if ($UM) {
            $TinaUserType = "installer user"
        }
        else {
            $TinaUserType = "tenant administrator"
        }
        $InstallUser = Get-Credential -Message ("Please enter {0} credentials" -f $TinaUserType)
        if (!($InstallUser)) {
            Write-LogMessage -Type Error -MSG "No credentials provided. Exiting."
            exit 1
        }
    }
}

If ($OperationsToPerform.RemoteConfiguration) {
    Write-LogMessage -type Info -MSG "Starting backend configuration"

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $pvwaTokenResponse = New-ConnectionToRestAPI -pvwaAddress $PrivilegeCloudUrl -InstallUser $InstallUser
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
    $PvwaTokenTestResponse = Test-PvwaToken -Token $pvwaTokenResponse.Response -pvwaAddress $PrivilegeCloudUrl
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
        Duplicate-Platform -pvwaAddress $PrivilegeCloudUrl -pvwaToken $pvwaToken -CurrentPlatformId $WinDomainPlatformId -NewPlatformName $PlatformName -NewPlatformDescription "Platform for PSM accounts"
        $TasksTop += @{
            Message  = ("Set appropriate policies and settings on platform `"{0}`"" -f $PlatformName)
            Priority = "Low"
        }
        # Get platform info again so we can ensure it's activated
        $platformStatus = Get-PlatformStatus -pvwaAddress $PrivilegeCloudUrl -pvwaToken $pvwaToken -PlatformId $PlatformName
    }
    else {
        Write-LogMessage -Type Warning -MSG ('Platform {0} already exists. Please verify it meets requirements.' -f $PlatformName)
        $TasksTop += @{
            Message  = ("Verify that the existing platform `"{0}`" is configured correctly" -f $PlatformName)
            Priority = "Low"
        }
    }
    if ($platformStatus.Active -eq $false) {
        Write-LogMessage -Type Verbose -MSG "Platform is deactivated. Activating."
        Activate-Platform -pvwaAddress $PrivilegeCloudUrl -pvwaToken $pvwaToken -Platform $platformStatus.Id
    }
    Write-LogMessage -Type Verbose -MSG "Checking current safe status"
    $safeStatus = Get-SafeStatus -pvwaAddress $PrivilegeCloudUrl -pvwaToken $pvwaToken -SafeName $Safe
    if ($safeStatus -eq $false) {
        # function returns false if safe does not exist
        Write-LogMessage -Type Verbose -MSG "Safe $Safe does not exist. Creating the safe now"
        $CreateSafeResult = Create-PSMSafe -pvwaAddress $PrivilegeCloudUrl -pvwaToken $pvwaToken -safe $Safe
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
        $TasksTop += @{
            Message  = ("Assign a Password Manager (CPM) to safe `"{0}`"" -f $Safe)
            Priority = "Low"
        }
    }
    # Giving Permission on the safe if we are using UM, The below will give full permission to vault admins
    If ($UM) {
        $SafePermissions = Get-SafePermissions -pvwaAddress $PrivilegeCloudUrl -pvwaToken $pvwaToken -safe $safe -safeMember "Vault Admins"
        If ($false -eq $SafePermissions) {
            # Vault Admins does not appear to be a member of the safe. Adding.
            Write-LogMessage -Type Verbose -MSG "Granting administrators access to PSM safe"
            New-SafePermissions -pvwaAddress $PrivilegeCloudUrl -pvwaToken $pvwaToken -safe $safe -safeMember "Vault Admins"
        }
    }
    # Creating PSMConnect, We can now add a safe need as well for the below line if we have multiple domains
    Write-LogMessage -Type Verbose -MSG "Onboarding PSMConnect Account"
    $OnboardResult = New-VaultAdminObject -pvwaAddress $PrivilegeCloudUrl -pvwaToken $pvwaToken -name $PSMConnectAccountName -domain $DomainDNSName -Credentials $psmConnectCredentials -platformID $PlatformName -safe $safe
    If ($OnboardResult.name) {
        Write-LogMessage -Type Verbose -MSG "User successfully onboarded"
    }
    ElseIf ($OnboardResult.ErrorCode -eq "PASWS027E") {
        Write-LogMessage -Type Warning -MSG "Object with name $PSMConnectAccountName already exists. Please verify that it contains correct account details, or specify an alternative account name."
        $TasksTop += @{
            Message  = "Verify that the `"$PSMConnectAccountName`" object in the `"$safe`" safe contains correct PSMConnect user details."
            Priority = "High"
        }
        $PSMObjectsAlreadyExisted = $true
    }
    Else {
        Write-LogMessage -Type Error -MSG ("Error onboarding account: {0}" -f $OnboardResult)
        exit 1
    }
    # Creating PSMAdminConnect
    Write-LogMessage -Type Verbose -MSG "Onboarding PSMAdminConnect Account"
    $OnboardResult = New-VaultAdminObject -pvwaAddress $PrivilegeCloudUrl -pvwaToken $pvwaToken -name $PSMAdminConnectAccountName -domain $DomainDNSName -Credentials $psmAdminCredentials -platformID $PlatformName -safe $safe
    If ($OnboardResult.name) {
        Write-LogMessage -Type Verbose -MSG "User successfully onboarded"
    }
    ElseIf ($OnboardResult.ErrorCode -eq "PASWS027E") {
        Write-LogMessage -Type Warning -MSG "Object with name $PSMAdminConnectAccountName already exists. Please verify that it contains correct account details, or specify an alternative account name."
        $TasksTop += @{
            Message  = "Verify that the `"$PSMAdminConnectAccountName`" object in the `"$safe`" safe contains correct PSMAdminConnect user details."
            Priority = "High"
        }
        $PSMObjectsAlreadyExisted = $true
    }
    Else {
        Write-LogMessage -Type Error -MSG ("Error onboarding account: {0}" -f $OnboardResult)
        exit 1
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
        Write-LogMessage -type Warning -MSG "Security policy export failed, so the current policy will not be modified."
        Write-LogMessage -type Warning -MSG "Please edit local security policy manually to allow PSM users to log on with Remote Desktop."
        $TasksTop += @{
            Message  = "Configure Local Security Policy to allow PSM users to log on with Remote Desktop"
            Priority = "High"
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
            Priority = "High"
        }
    }
}
else {
    $TasksTop += @{
        Message  = "Configure Local Security Policy to allow PSM users to log on with Remote Desktop"
        Priority = "High"
    }
}
$TasksTop += @{
    Message  = "Ensure domain GPOs allow PSM users to log on to PSM servers with Remote Desktop"
    Priority = "Medium"
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
            Priority = "High"
        }
    }
}
else {
    $TasksTop += @{
        Message  = "Add PSM users to Remote Desktop Users group"
        Priority = "High"
    }
}

# End group membership and security policy changes

## Local Configuration Block
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
                Priority = "High"
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
                    Message  = "Resolve issue preventing PSMAdminConnect user being granted permission to shadow sessions and rerun this script"
                    Priority = "High"
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

## Post-Configuration Block

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
        Priority = "High"
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
        Priority = "High"
    }
}
Write-LogMessage -Type Verbose -MSG "Restarting CyberArk Privileged Session Manager Service"
Restart-Service $REGKEY_PSMSERVICE
Write-LogMessage -Type Success -MSG "All tasks completed."

$string = "The following additional steps are required:"
Write-LogMessage -type Info -MSG ("-" * $string.length)
Write-LogMessage -type Info -MSG ($string)

$HighPriorityTasks = @()
If ($SkipPSMObjectUpdate -or $LocalConfigurationOnly) {
    $HighPriorityTasks += @(
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
            Priority = "High"
        }
    )
}

$i = 1
$HighPriorityTasks += $TasksTop | Where-Object Priority -eq "High"
$HighPriorityTasks += @{ Message = "Restart Server"; Priority = "High" }
foreach ($Task in $HighPriorityTasks) {
    Write-LogMessage -Type Info -MSG (" {0:D2}. {1}" -f $i, $Task.Message)
    $i++
}

If ($PSMObjectsAlreadyExisted) {
    Write-LogMessage -type Warning -MSG " "
    Write-LogMessage -type Info -MSG (`
            "NOTE: If you're configuring PSM servers in a new domain, you may need to specify alternative safe`n" + `
            "and account names with the -Safe, -PSMConnectAccountName and -PSMAdminConnectAccountName options."
    )
}

Write-LogMessage -type Warning -MSG " "

$string = "The following additional steps are recommended:"
Write-LogMessage -type Info -MSG ("-" * $string.length)
Write-LogMessage -type Info -MSG ($string)

$LowerPriorityTasks = $TasksTop | Where-Object Priority -ne "High"

$i = 1
foreach ($Task in $LowerPriorityTasks) {
    Write-LogMessage -Type Info -MSG (" {0:D2}. {1}" -f $i, $Task.Message)
    $i++
}

Write-LogMessage -type Warning -MSG " "

#$HighPriorityTasks.Message | Out-GridView -Title "Required tasks"

#Write-LogMessage -type Warning -MSG "Any tasks in red above must be completed to ensure PSM is functional."
