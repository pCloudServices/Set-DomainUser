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
  .PARAMETER psmConnectCredentials
  PSMConnect domain user credentials
  .PARAMETER psmAdminCredentials
  PSMAdminConnect domain user credentials
#>



[CmdletBinding()]
param(
    [Parameter(
        Mandatory=$true,
        HelpMessage="Please enter the full PVWA Address IE: https://tenantname.privilegecloud.cyberark.cloud")]
        [string]$pvwaAddress,
    [Parameter(
        Mandatory=$true,
        HelpMessage="Please enter the domain of the created accounts IE: lab.net")]
        [string]$domain,
    [Parameter(
        Mandatory=$true,
        HelpMessage="Please enter the NETBIOS of the created accounts IE: LAB")]
        [string]$NETBIOS,
    [Parameter(
        Mandatory=$false,
        HelpMessage="Please enter the account credentials for the PSMConnect domain account account.")]
        [PSCredential]$psmConnectCredentials,
    [Parameter(
        Mandatory=$false,
        HelpMessage="Please enter the account credentials for the PSMAdminConnect domain account account.")]
        [PSCredential]$psmAdminCredentials,
    [Parameter(
        Mandatory=$false,
        HelpMessage="Please enter the Safe to save the domain accounts in, By default it is PSM")]
        [String]$safe="PSM"       
)

#Functions

Function IsUserDomainJoined{
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
            if($UserPrincipal.ContextType -eq "Domain")
            {
                return $true
            }
            else
            {
                return $false
            }   
        }
        catch {
            return $false
        }
	}
}

Function Get-ServiceInstallPath
{
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
		try{
			Set-Variable -Name m_ServiceList -Value $(Get-ChildItem "HKLM:\System\CurrentControlSet\Services" | ForEach-Object { Get-ItemProperty $_.pspath }) -Scope Script
			$regPath =  $m_ServiceList | Where-Object {$_.PSChildName -eq $ServiceName}
			If ($Null -ne $regPath)
			{
				$retInstallPath = $regPath.ImagePath.Substring($regPath.ImagePath.IndexOf('"'),$regPath.ImagePath.LastIndexOf('"')+1)
			}
		}
		catch{
			Throw $(New-Object System.Exception ("Cannot get Service Install path for $ServiceName",$_.Exception))
		}

		return $retInstallPath
	}
	End {

	}
}

Function New-ConnectionToRestAPI{
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
    # Get PVWA and login informatioN
    param (
        [Parameter(Mandatory=$true)]
        $pvwaAddress
    )
    $tinaCreds = Get-Credential -Message "Please enter your Privilege Cloud admin credentials"
    $url = $pvwaAddress + "/PasswordVault/API/auth/Cyberark/Logon"
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($tinaCreds.Password)

    $headerPass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    $body  = @{
    username =$tinacreds.UserName
    password =$headerPass
    }
    $json= $body | ConvertTo-Json
    Try {
        $pvwaToken = Invoke-RestMethod -Method 'Post' -Uri $url -Body $json -ContentType 'application/json'
    }
    Catch {
        Write-Host "Could not retrieve PVWA token."
        exit
    }
    return $pvwaToken
}

Function Backup-PSMConfig{
    <#
  .SYNOPSIS
  Backs up PSMConfig ps1 scripts
  .DESCRIPTION
  Copies PSM config items to -backup.ps1
  .PARAMETER psmRootInstallLocation
  PSM root installation folder
 #>
    param (
        [Parameter(Mandatory=$true)]
        $psmRootInstallLocation
    )
    try {
    Copy-Item -path "$psmRootInstallLocation\Hardening\PSMHardening.ps1" -Destination "$psmRootInstallLocation\Hardening\PSMHardening.bkp"
    Copy-Item -path "$psmRootInstallLocation\Hardening\PSMConfigureAppLocker.ps1" -Destination "$psmRootInstallLocation\Hardening\PSMConfigureAppLocker.bkp"
    Copy-Item -Path "$psmRootInstallLocation\basic_psm.ini" -Destination "$psmRootInstallLocation\basic_psm.bkp"
    If (!(Test-Path "$psmRootInstallLocation\Hardening\PSMHardening.bkp")) {
        Write-Error "Failed to backup PSMHardening.ps1" -ErrorAction Stop
    }
    ElseIf (!(Test-Path "$psmRootInstallLocation\Hardening\PSMConfigureAppLocker.bkp")) {
        Write-Error "Failed to backup PSMConfigureAppLocker.ps1" -ErrorAction Stop
    }
    ElseIf (!(Test-Path "$psmRootInstallLocation\basic_psm.bkp")) {
        Write-Error "Failed to backup basic_psm.ini" -ErrorAction Stop
    }
    }
    catch {
        write-output "Could not copy one of the scripts to backup. Exiting"
        write-output $_
        exit
    }
}

Function Update-PSMConfig{
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
        [Parameter(Mandatory=$true)]
        $psmRootInstallLocation,
        [Parameter(Mandatory=$true)]
        $domain,
        [Parameter(Mandatory=$true)]
        $PsmConnectUsername,
        [Parameter(Mandatory=$true)]
        $PsmAdminUsername
    )
    try {
        #PSMHardening
        #-------------------------   
        $psmHardeningContent = Get-Content -Path $psmRootInstallLocation\Hardening\PSMHardening.ps1
       
        $newPsmHardeningContent = $psmHardeningContent -replace [Regex]::Escape('$COMPUTER\PSMConnect'),"$domain\$PsmConnectUsername"
        $newPsmHardeningContent = $newPsmHardeningContent -replace [Regex]::Escape('$COMPUTER\PSMAdminConnect'),"$domain\$PsmAdminUsername"
        $newPsmHardeningContent | Set-Content -Path "$psmRootInstallLocation\Hardening\test-psmhardening.ps1"

        #PSMApplocker    
        #------------------------- 


        $psmApplockerContent = Get-Content -Path $psmRootInstallLocation\Hardening\PSMConfigureApplocker.ps1

        $newPsmApplockerContent = $psmApplockerContent -replace '"PSMConnect"',"""$domain\$PsmConnectUsername"""
        $newPsmApplockerContent = $newPsmApplockerContent -replace '"PSMAdminConnect"',"""$domain\$PsmAdminUsername"""

        $newPsmApplockerContent | Set-Content -Path "$psmRootInstallLocation\Hardening\test-psm-applocker.ps1"


        #basic_psm.ini
        #-------------------------   

  
        $psmBasicPSMContent = Get-Content -Path $psmRootInstallLocation\basic_psm.ini
            
        $psmBasicPSMAdminLine = 'PSMServerAdminId="PSMAdminConnect"'
        $newBasicPSMContent = $psmBasicPSMContent -replace 'PSMServerAdminId=".+$',$psmBasicPSMAdminLine

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

Function Invoke-PSMHardening{
  <#
  .SYNOPSIS
  Runs the PSMHardening script
  .DESCRIPTION
  Runs the PSMHardening script
  .PARAMETER psmRootInstallLocation
  PSM root installation folder
  #>
    param (
        [Parameter(Mandatory=$true)]
        $psmRootInstallLocation
    ) 
    Write-Verbose "Starting PSM Hardening"
    $hardeningScriptRoot = "$psmRootInstallLocation\Hardening"
    & "$hardeningScriptRoot\PSMHardening.ps1"


}

Function Invoke-PSMConfigureAppLocker{
  <#
  .SYNOPSIS
  Runs the AppLocker PowerShell script
  .DESCRIPTION
  Runs the AppLocker PowerShell script
  .PARAMETER psmRootInstallLocation
  PSM root installation folder
  #>
    param (
        [Parameter(Mandatory=$true)]
        $psmRootInstallLocation
    ) 
    Write-Verbose "Starting PSMConfigureAppLocker"
    $hardeningScriptRoot = "$psmRootInstallLocation\Hardening"
    $CurrentLocation = Get-Location
    Set-Location $hardeningScriptRoot
    & "$hardeningScriptRoot\PSMConfigureAppLocker.ps1"
    Set-Location $CurrentLocation 
}

Function New-VaultAdminObject{
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
        [Parameter(Mandatory=$true)]
        $pvwaAddress,
        [Parameter(Mandatory=$true)]
        $pvwaToken,
        [Parameter(Mandatory=$true)]
        $name,
        [Parameter(Mandatory=$true)]
        [String]$domain,
        [Parameter(Mandatory=$true)]
        [PSCredential]$Credentials,
        [Parameter(Mandatory=$true)]
        $platformID,
        [Parameter(Mandatory=$true)]
        $safe="PSM"
    ) 

    $username = $Credentials.username.Replace('\','')
    $password = $Credentials.GetNetworkCredential().password
    $body  = @{
        name = $name
        address = $domain
        userName = $username
        safeName = $safe
        secretType ="password"
        secret =$password
        platformID =$platformID
        platformAccountProperties = @{"LogonDomain"=$domain}
    }
    $url = $pvwaAddress + "/PasswordVault/api/Accounts"
    $json= $body | ConvertTo-Json
    try {
        $Postresult = Invoke-RestMethod -Method 'Post' -Uri $url -Body $json -Headers @{ 'Authorization' = $pvwaToken } -ContentType 'application/json'
    }
    catch {
        Write-Host $_.ErrorDetails.Message
    }
}

Function Update-RDS{
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
        [Parameter(Mandatory=$true)]
        [String]$NETBIOS,
        [Parameter(Mandatory=$true)]
        [PSCredential]$Credentials
    )
    $username = $Credentials.username.Replace('\','')
    $cmd1 = "wmic.exe /namespace:\\root\CIMV2\TerminalServices PATH Win32_TSPermissionsSetting WHERE (TerminalName=""RDP-Tcp"") CALL AddAccount ""$NETBIOS\$username"",0"
    $cmd2 = "wmic.exe /namespace:\\root\cimv2\TerminalServices PATH Win32_TSAccount WHERE ""TerminalName='RDP-Tcp' AND AccountName='$NETBIOS\\$username'"" CALL ModifyPermissions TRUE,4"
    try {
        $a = cmd.exe /C $cmd1
    }
    catch {write-host $_}
    try {
        $b = cmd.exe /C $cmd2
    }
    catch {write-host $_}
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
    [Parameter(Mandatory=$true)]
    $pvwaAddress,
    [Parameter(Mandatory=$true)]
    $pvwaToken
    )
    try {
        $url = $pvwaAddress + "/PasswordVault/api/Platforms/Targets/7/Duplicate"
        $body = @{ 
            Name = "WIN-DOM-PSMADMIN-ACCOUNT"
            Description= "Platform for PSM accounts"
        }
        $json= $body | ConvertTo-Json
        $Postresult = Invoke-RestMethod -Method 'Post' -Uri $url -Body $json -Headers @{ 'Authorization' = $pvwaToken } -ContentType 'application/json'
    }
    catch {
        Write-Host $_.ErrorDetails.Message
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
    [Parameter(Mandatory=$true)]
    $pvwaAddress,
    [Parameter(Mandatory=$true)]
    $pvwaToken,
    [Parameter(Mandatory=$false)]
    $safe="PSM",
    [Parameter(Mandatory=$false)]
    $SafeMember="Vault Admins",
    [Parameter(Mandatory=$false)]
    $memberType="Group"   
    )
    try {
        $url = $pvwaAddress + "/PasswordVault/api/Safes/$safe/members"
        $body = @{ 
                memberName = $SafeMember
                memberType= $memberType
                permissions = @{
                    useAccounts=$True 
                    retrieveAccounts=$True
                    listAccounts=$True
                    addAccounts=$True 
                    updateAccountContent=$True
                    updateAccountProperties=$True
                    initiateCPMAccountManagementOperations=$True
                    specifyNextAccountContent=$True
                    renameAccounts=$True
                    deleteAccounts=$True
                    unlockAccounts=$True
                    manageSafe=$True
                    manageSafeMembers=$True
                    backupSafe=$True
                    viewAuditLog=$True
                    viewSafeMembers=$True
                    accessWithoutConfirmation=$True
                    createFolders=$True
                    deleteFolders=$True
                    moveAccountsAndFolders=$True
                    requestsAuthorizationLevel1=$True 
                    requestsAuthorizationLevel2=$False}
            }
        $json= $body | ConvertTo-Json
        $Postresult = Invoke-RestMethod -Method 'Post' -Uri $url -Body $json -Headers @{ 'Authorization' = $pvwaToken } -ContentType 'application/json'
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
        [Parameter(Mandatory=$true)]
        $psmRootInstallLocation
    )
    $psmBasicPSMContent = Get-Content -Path $psmRootInstallLocation\basic_psm.ini 
    $validation = $psmBasicPSMContent -match "IdentityUM.*=.*Yes"
    return ("" -ne $validation) 
}

#Running Set-DomainUser script

if ($null -eq $psmConnectCredentials) {
    $psmConnectCredentials = Get-Credential -Message "Please enter PSMConnect domain user credentials"
}
if ($null -eq $psmAdminCredentials) {
    $psmAdminCredentials = Get-Credential -Message "Please enter PSMAdminConnect domain user credentials"
}
if ($null -eq $psmConnectCredentials -or $null -eq $psmAdminCredentials)
{
    exit
}


$REGKEY_PSMSERVICE = "Cyber-Ark Privileged Session Manager"
$psmRootInstallLocation = ($(Get-ServiceInstallPath $REGKEY_PSMSERVICE)).Replace("CAPSM.exe","").Replace('"',"").Trim()

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if(IsUserDomainJoined){
    # Get-Variables
    $pvwaToken = New-ConnectionToRestAPI -pvwaAddress $pvwaAddress
    #Creating Platform
    Duplicate-Platform -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken
    #Giving Permission on the safe if we are using UM, The below will give full permission to vault admins
    If (Check-UM -psmRootInstallLocation $psmRootInstallLocation) {
        Set-SafePermissionsFull -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken -safe $safe
    }
    #Creating PSMConnect, We can now add a safe need as well for the below line if we have multiple domains
    New-VaultAdminObject -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken -name "PSMConnect" -domain $domain -Credentials $psmConnectCredentials -platformID "WIN-DOM-PSMADMIN-ACCOUNT" -safe $safe
    #Creating PSMAdminConnect
    New-VaultAdminObject -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken -name "PSMAdminConnect" -domain $domain -Credentials $psmAdminCredentials -platformID "WIN-DOM-PSMADMIN-ACCOUNT" -safe $safe
    Stop-Service $REGKEY_PSMSERVICE
    Backup-PSMConfig -psmRootInstallLocation $psmRootInstallLocation
    Update-PSMConfig -psmRootInstallLocation $psmRootInstallLocation -domain $domain -PsmConnectUsername $psmConnectCredentials.username.Replace('\','') -PsmAdminUsername $psmAdminCredentials.username.Replace('\','')
    #TODO: Update Basic_ini
    Update-RDS -NETBIOS $NETBIOS -Credentials $psmAdminCredentials
    Invoke-PSMHardening -psmRootInstallLocation $psmRootInstallLocation
    Invoke-PSMConfigureAppLocker -psmRootInstallLocation $psmRootInstallLocation
    Restart-Service $REGKEY_PSMSERVICE
} else{
    Write-Host "Stopping. Please run this script as a domain user"
}
# SIG # Begin signature block
# MIIgTgYJKoZIhvcNAQcCoIIgPzCCIDsCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDyIgzhnYFGgPRq
# mWz10SotNbBwkuDdSB1euoXNxA4tyqCCDl8wggboMIIE0KADAgECAhB3vQ4Ft1kL
# th1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENvZGUgU2ln
# bmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAwMDBaMFwx
# CzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIwMAYDVQQD
# EylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAyMDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj/SBerjgS
# i8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlMg7BKRFAE
# eIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRVX5YLEeWa
# tSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV0xHK5s2z
# BZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEzIHXMsdXt
# HQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMkoog28vmf
# vpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq7rfYrWGl
# r3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult5a/dm2tj
# IF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNutwFsDeCX
# pxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYyAjIwfLWT
# yCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofnGrhO7izB
# 36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0l
# BAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUJZ3Q
# /FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0Q9lWULvO
# ljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8vb2NzcC5n
# bG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUHMAKGOmh0
# dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWduaW5ncm9v
# dHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9iYWxzaWdu
# LmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJKwYBBAGg
# MgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3Jl
# cG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJyTm6t6E5
# iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbVYQLFY4/U
# ovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQtpFg6bBNJ
# +KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSXhndGKj0j
# fShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6bs+XYXvf
# cXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nOZNm9/Lws
# 80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOHX5OKSBoR
# HeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dqcYC/lt5y
# A9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0ixxnJpsoO
# qHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7qWPLd0jV
# +mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72f1LiSY25
# EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB28wggVXoAMCAQICDHBNxPwWOpXgXVV8
# DDANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
# U2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVWIENvZGVT
# aWduaW5nIENBIDIwMjAwHhcNMjIwMjE1MTMzODM1WhcNMjUwMjE1MTMzODM1WjCB
# 1DEdMBsGA1UEDwwUUHJpdmF0ZSBPcmdhbml6YXRpb24xEjAQBgNVBAUTCTUxMjI5
# MTY0MjETMBEGCysGAQQBgjc8AgEDEwJJTDELMAkGA1UEBhMCSUwxEDAOBgNVBAgT
# B0NlbnRyYWwxFDASBgNVBAcTC1BldGFoIFRpa3ZhMRMwEQYDVQQJEwo5IEhhcHNh
# Z290MR8wHQYDVQQKExZDeWJlckFyayBTb2Z0d2FyZSBMdGQuMR8wHQYDVQQDExZD
# eWJlckFyayBTb2Z0d2FyZSBMdGQuMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEA8rPX6yAVM64+/qMQEttWp7FdAvq9UfgxBrW+R0NtuXhKnjV05zmIL6zi
# AS0TlNrQqu5ypmuagOWzYKDtIcWEDm6AuSK+QeZprW69c0XYRdIf8X/xNUawXLGe
# 5LG6ngs2uHGtch9lt2GLMRWILnKviS6l6F06HOAow+aIDcNGOukddypveFrqMEbP
# 7YKMekkB6c2/whdHzDQiW6V0K82Xp9XUexrbdnFpKWXLfQwkzjcG1xmSiHQUpkSH
# 4w2AzBzcs+Nidoon5FEIFXGS2b1CcCA8+Po5Dg7//vn2thirXtOqaC+fjP1pUG7m
# vrZQMg3lTHQA/LTL78R3UzzNb4I9dc8yualcYK155hRU3vZJ3/UtktAvDPC/ewoW
# thebG77NuKU8YI6l2lMg7jMFZ1//brICD0RGqhmPMK9MrB3elSuMLaO566Ihdrlp
# zmj4BRDCfPuH0QfwkrejsikGEMo0lErfHSjL3NaiE0PPoC4NW7nc6Wh4Va4e3VFF
# Z9zdnoTsCKJqk4s13MxBbjdLIkCcfknMSxAloOF9h6IhzWOylSROAy/TZfGL5kzQ
# qxzcIhdXLWHHWdbz4DD3qxYc6g1G3ZwgFPWf7VbKQU3FsAxgiJvmKPVeOfIN4iYT
# V4toilRR8KX/IaA1NMrN9EiA//ZhN3HONS/s6AxjjHJTR29GOQkCAwEAAaOCAbYw
# ggGyMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8wTAYIKwYBBQUH
# MAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzZ2NjcjQ1
# ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6Ly9vY3NwLmds
# b2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBVBgNVHSAETjBM
# MEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxz
# aWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAAMEcGA1UdHwRA
# MD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3NnY2NyNDVldmNv
# ZGVzaWduY2EyMDIwLmNybDATBgNVHSUEDDAKBggrBgEFBQcDAzAfBgNVHSMEGDAW
# gBQlndD8WQmGY8Xs87ETO1ccA5I2ETAdBgNVHQ4EFgQU0Vg7IAYAK18fI9dI1YKi
# WA0D1bEwDQYJKoZIhvcNAQELBQADggIBAFOdA15mFwRIM54PIL/BDZq9RU9IO+YO
# lAoAYTJHbiTY9ZqvA1isS6EtdYKJgdP/MyZoW7RZmcY5IDXvXFj70TWWvfdqW/Qc
# MMHtSqhiRb4L92LtR4lS+hWM2fptECpl9BKH28LBZemdKS0jryBEqyAmuEoFJNDk
# wxzQVKPksvapvmSYwPiBCtzPyHTRo5HnLBXpK/LUBJu8epAgKz6LoJjnrTIF4U8R
# owrtUC0I6f4uj+sKYE0iV3/TzwsTJsp7MQShoILPr1/75fQjU/7Pl2fbM++uAFBC
# sHQHYvar9KLslFPX4g+cDdtOHz5vId8QYZnhCduVgzUGvELmXXR1FYV7oJNnh3eY
# Xc5gm7vSNKlZB8l7Ls6h8icBV2zQbojDiH0JOD//ph62qvnMp8ev9mvhvLXRCIxc
# aU7CYI0gNVvg9LPi5j1/tswqBc9XAfHUG9ZYVxYCgvynEmnJ5TuEh6GesGRPbNIL
# l418MFn4EPQUqxB51SMihIcyqu6+3qOlco8Dsy1y0gC0Hcx+unDZPsN8k+rhueN2
# HXrPkAJ2bsEJd7adPy423FKbA7bRCOc6dWOFH1OGANfEG0Rjw9RfcsI84OkKpQ7R
# XldpKIcWuaYMlfYzsl+P8dJru+KgA8Vh7GTVb5USzFGeMyOMtyr1/L2bIyRVSiLL
# 8goMl4DTDOWeMYIRRTCCEUECAQEwbDBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
# R2xvYmFsU2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVW
# IENvZGVTaWduaW5nIENBIDIwMjACDHBNxPwWOpXgXVV8DDANBglghkgBZQMEAgEF
# AKB8MBAGCisGAQQBgjcCAQwxAjAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEE
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAi
# /7sJKLsGxbA8UphvWu03Z0/8YqBTVQzpd0N07XhCrjANBgkqhkiG9w0BAQEFAASC
# AgCY1BEiruc++wpzYMgSJ2d0S30s3Jl13AboyIZ75amSdGW7yIp5Yi9hbabskoJl
# UUkFUpa0aRKO3GMnSaoZ8CpHHqv6/HMNCvpUDvdT1DXyxmVJj3DfasPeHGbj5JBV
# 90YOGsHPUltYovoc9MJOeA3l7t//Fw/IV+oMowOqgRy75Vb0mk7wKisives9mlTR
# QZTW2/N8qD0bfpJXitRxtAawxYcTPizClMLx60c100Swr5oMMIEDecbh0H/qyhes
# 9wHFvNYoUVnGhpiKaLSyutWLIL2u1edvtk4WgdxWcpFDX3w3c/r1Q9q8VzbATqhw
# 1p78iU6/bp/nqZ5KWJ+1mLk8ZkGe4GnOXI5tjHhOptiWzdjD699Cp/pka1YJVVR4
# 8MekBLlYsMnA4Eq40TrKHaB7z22f09kzAQgOk+D0KKi3Ze1Z0BiOdLYohAN5m9x3
# af3jbe7s0AGrPy+TQLA4D5wBomXLqDIfvQzRzerS9ciocqRX1BcCIQzDpzM73+f2
# TZv9r0bV0m12NmZUcvxfPMGDAS9Kq4HquIRSgV6nOo03g9gq9FGOkMwDoudmHyvt
# 0gpvlJRH0eVZVdyKAyl5SMzjLvq5vVyfKJzEMAoHo5BFSmpinDZIfS/tcwWSjlFk
# OTLgOvLMoZj3Uely18iZP9dzy9FAS3MxgAJfdJUQ3pYaSaGCDiwwgg4oBgorBgEE
# AYI3AwMBMYIOGDCCDhQGCSqGSIb3DQEHAqCCDgUwgg4BAgEDMQ0wCwYJYIZIAWUD
# BAIBMIH/BgsqhkiG9w0BCRABBKCB7wSB7DCB6QIBAQYLYIZIAYb4RQEHFwMwITAJ
# BgUrDgMCGgUABBQtW+Wtv8FWhRVPtI9/nabBQsUGqwIVAMJXYkA41vktdFrlgYhY
# 57v3mN7RGA8yMDIyMDQyNzEzNTQyN1owAwIBHqCBhqSBgzCBgDELMAkGA1UEBhMC
# VVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMR8wHQYDVQQLExZTeW1h
# bnRlYyBUcnVzdCBOZXR3b3JrMTEwLwYDVQQDEyhTeW1hbnRlYyBTSEEyNTYgVGlt
# ZVN0YW1waW5nIFNpZ25lciAtIEczoIIKizCCBTgwggQgoAMCAQICEHsFsdRJaFFE
# 98mJ0pwZnRIwDQYJKoZIhvcNAQELBQAwgb0xCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5WZXJpU2lnbiwgSW5jLjEfMB0GA1UECxMWVmVyaVNpZ24gVHJ1c3QgTmV0d29y
# azE6MDgGA1UECxMxKGMpIDIwMDggVmVyaVNpZ24sIEluYy4gLSBGb3IgYXV0aG9y
# aXplZCB1c2Ugb25seTE4MDYGA1UEAxMvVmVyaVNpZ24gVW5pdmVyc2FsIFJvb3Qg
# Q2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTYwMTEyMDAwMDAwWhcNMzEwMTEx
# MjM1OTU5WjB3MQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9y
# YXRpb24xHzAdBgNVBAsTFlN5bWFudGVjIFRydXN0IE5ldHdvcmsxKDAmBgNVBAMT
# H1N5bWFudGVjIFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwggEiMA0GCSqGSIb3DQEB
# AQUAA4IBDwAwggEKAoIBAQC7WZ1ZVU+djHJdGoGi61XzsAGtPHGsMo8Fa4aaJwAy
# l2pNyWQUSym7wtkpuS7sY7Phzz8LVpD4Yht+66YH4t5/Xm1AONSRBudBfHkcy8ut
# G7/YlZHz8O5s+K2WOS5/wSe4eDnFhKXt7a+Hjs6Nx23q0pi1Oh8eOZ3D9Jqo9ITh
# xNF8ccYGKbQ/5IMNJsN7CD5N+Qq3M0n/yjvU9bKbS+GImRr1wOkzFNbfx4Dbke7+
# vJJXcnf0zajM/gn1kze+lYhqxdz0sUvUzugJkV+1hHk1inisGTKPI8EyQRtZDqk+
# scz51ivvt9jk1R1tETqS9pPJnONI7rtTDtQ2l4Z4xaE3AgMBAAGjggF3MIIBczAO
# BgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADBmBgNVHSAEXzBdMFsG
# C2CGSAGG+EUBBxcDMEwwIwYIKwYBBQUHAgEWF2h0dHBzOi8vZC5zeW1jYi5jb20v
# Y3BzMCUGCCsGAQUFBwICMBkaF2h0dHBzOi8vZC5zeW1jYi5jb20vcnBhMC4GCCsG
# AQUFBwEBBCIwIDAeBggrBgEFBQcwAYYSaHR0cDovL3Muc3ltY2QuY29tMDYGA1Ud
# HwQvMC0wK6ApoCeGJWh0dHA6Ly9zLnN5bWNiLmNvbS91bml2ZXJzYWwtcm9vdC5j
# cmwwEwYDVR0lBAwwCgYIKwYBBQUHAwgwKAYDVR0RBCEwH6QdMBsxGTAXBgNVBAMT
# EFRpbWVTdGFtcC0yMDQ4LTMwHQYDVR0OBBYEFK9j1sqjToVy4Ke8QfMpojh/gHVi
# MB8GA1UdIwQYMBaAFLZ3+mlIR59TEtXC6gcydgfRlwcZMA0GCSqGSIb3DQEBCwUA
# A4IBAQB16rAt1TQZXDJF/g7h1E+meMFv1+rd3E/zociBiPenjxXmQCmt5l30otlW
# ZIRxMCrdHmEXZiBWBpgZjV1x8viXvAn9HJFHyeLojQP7zJAv1gpsTjPs1rSTyEyQ
# Y0g5QCHE3dZuiZg8tZiX6KkGtwnJj1NXQZAv4R5NTtzKEHhsQm7wtsX4YVxS9U72
# a433Snq+8839A9fZ9gOoD+NT9wp17MZ1LqpmhQSZt/gGV+HGDvbor9rsmxgfqrnj
# OgC/zoqUywHbnsc4uw9Sq9HjlANgCk2g/idtFDL8P5dA4b+ZidvkORS92uTTw+or
# WrOVWFUEfcea7CMDjYUq0v+uqWGBMIIFSzCCBDOgAwIBAgIQe9Tlr7rMBz+hASME
# IkFNEjANBgkqhkiG9w0BAQsFADB3MQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3lt
# YW50ZWMgQ29ycG9yYXRpb24xHzAdBgNVBAsTFlN5bWFudGVjIFRydXN0IE5ldHdv
# cmsxKDAmBgNVBAMTH1N5bWFudGVjIFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwHhcN
# MTcxMjIzMDAwMDAwWhcNMjkwMzIyMjM1OTU5WjCBgDELMAkGA1UEBhMCVVMxHTAb
# BgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMR8wHQYDVQQLExZTeW1hbnRlYyBU
# cnVzdCBOZXR3b3JrMTEwLwYDVQQDEyhTeW1hbnRlYyBTSEEyNTYgVGltZVN0YW1w
# aW5nIFNpZ25lciAtIEczMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
# rw6Kqvjcv2l7VBdxRwm9jTyB+HQVd2eQnP3eTgKeS3b25TY+ZdUkIG0w+d0dg+k/
# J0ozTm0WiuSNQI0iqr6nCxvSB7Y8tRokKPgbclE9yAmIJgg6+fpDI3VHcAyzX1uP
# CB1ySFdlTa8CPED39N0yOJM/5Sym81kjy4DeE035EMmqChhsVWFX0fECLMS1q/Js
# I9KfDQ8ZbK2FYmn9ToXBilIxq1vYyXRS41dsIr9Vf2/KBqs/SrcidmXs7DbylpWB
# Jiz9u5iqATjTryVAmwlT8ClXhVhe6oVIQSGH5d600yaye0BTWHmOUjEGTZQDRcTO
# PAPstwDyOiLFtG/l77CKmwIDAQABo4IBxzCCAcMwDAYDVR0TAQH/BAIwADBmBgNV
# HSAEXzBdMFsGC2CGSAGG+EUBBxcDMEwwIwYIKwYBBQUHAgEWF2h0dHBzOi8vZC5z
# eW1jYi5jb20vY3BzMCUGCCsGAQUFBwICMBkaF2h0dHBzOi8vZC5zeW1jYi5jb20v
# cnBhMEAGA1UdHwQ5MDcwNaAzoDGGL2h0dHA6Ly90cy1jcmwud3Muc3ltYW50ZWMu
# Y29tL3NoYTI1Ni10c3MtY2EuY3JsMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMA4G
# A1UdDwEB/wQEAwIHgDB3BggrBgEFBQcBAQRrMGkwKgYIKwYBBQUHMAGGHmh0dHA6
# Ly90cy1vY3NwLndzLnN5bWFudGVjLmNvbTA7BggrBgEFBQcwAoYvaHR0cDovL3Rz
# LWFpYS53cy5zeW1hbnRlYy5jb20vc2hhMjU2LXRzcy1jYS5jZXIwKAYDVR0RBCEw
# H6QdMBsxGTAXBgNVBAMTEFRpbWVTdGFtcC0yMDQ4LTYwHQYDVR0OBBYEFKUTAamf
# hcwbbhYeXzsxqnk2AHsdMB8GA1UdIwQYMBaAFK9j1sqjToVy4Ke8QfMpojh/gHVi
# MA0GCSqGSIb3DQEBCwUAA4IBAQBGnq/wuKJfoplIz6gnSyHNsrmmcnBjL+NVKXs5
# Rk7nfmUGWIu8V4qSDQjYELo2JPoKe/s702K/SpQV5oLbilRt/yj+Z89xP+YzCdmi
# WRD0Hkr+Zcze1GvjUil1AEorpczLm+ipTfe0F1mSQcO3P4bm9sB/RDxGXBda46Q7
# 1Wkm1SF94YBnfmKst04uFZrlnCOvWxHqcalB+Q15OKmhDc+0sdo+mnrHIsV0zd9H
# CYbE/JElshuW6YUI6N3qdGBuYKVWeg3IRFjc5vlIFJ7lv94AvXexmBRyFCTfxxEs
# HwA/w0sUxmcczB4Go5BfXFSLPuMzW4IPxbeGAk5xn+lmRT92MYICWjCCAlYCAQEw
# gYswdzELMAkGA1UEBhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9u
# MR8wHQYDVQQLExZTeW1hbnRlYyBUcnVzdCBOZXR3b3JrMSgwJgYDVQQDEx9TeW1h
# bnRlYyBTSEEyNTYgVGltZVN0YW1waW5nIENBAhB71OWvuswHP6EBIwQiQU0SMAsG
# CWCGSAFlAwQCAaCBpDAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZI
# hvcNAQkFMQ8XDTIyMDQyNzEzNTQyN1owLwYJKoZIhvcNAQkEMSIEIKdj25w7Hqsh
# 4uhBWbC5e6K74b1PmmvKasnqqQiUxHH1MDcGCyqGSIb3DQEJEAIvMSgwJjAkMCIE
# IMR0znYAfQI5Tg2l5N58FMaA+eKCATz+9lPvXbcf32H4MAsGCSqGSIb3DQEBAQSC
# AQCfI+x4vYtiXEBmJSNgN3vTbmR0SJvpnpRcyc26RaMYVnEut58sgu760U1XLuFK
# yeVr3BwqAiONAYG6XfaB4CMCrJL8WVT2EAC0GA4s5rKolIqL8zbigNcmPSUOJuKM
# biOPVpuBELblSOz+bTIbHrOceioetkBrtv6+nsHEKRmkZzysGfqKYDuSd0S5MccL
# HDh+9alc9nG8CGfMitvVIoNlxh8/t/Luv0GOCDo/NBYYfKaQ+RyEjEgFM0kqLagE
# zR7UFJHpNj04CcjxsVPckhXlfYGumh0/VFANH7pC+ziBggngctuXyneLCt5XztIY
# vXOpmdYDFO3VL+S3EQ+EVSPm
# SIG # End signature block
