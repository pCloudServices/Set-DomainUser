# Introduction
Set-DomainUser automates the process of configuring PSM to use domain-based PSMConnect and PSMAdminConnect accounts.

Set-DomainUser is provided as part of the Privilege Cloud Tools package, and depends on other components in Privilege Cloud Tools, so it should be kept together with the rest of the package.

# Usage
1. Create domain-based users as per the following instructions:
   1. https://docs.cyberark.com/PrivCloud-SS/Latest/en/Content/PAS%20INST/Optional-Moving-the-PSMConnec-and-PSMAdminConnect-users-to-your-Domain.htm#CreatethePSMConnectandPSMAdminConnectusersinyourdomain
   2. https://docs.cyberark.com/PrivCloud-SS/Latest/en/Content/PAS%20INST/Optional-Moving-the-PSMConnec-and-PSMAdminConnect-users-to-your-Domain.htm#ModifythedomainusersinActiveDirectory 
   3. https://docs.cyberark.com/PrivCloud-SS/Latest/en/Content/PAS%20INST/Optional-Moving-the-PSMConnec-and-PSMAdminConnect-users-to-your-Domain.htm#HardentheActiveDirectorysettingsforthenewdomainusersoptional
2. Open an Admin Powershell in the `PSM Convert local2domain Users` subdirectory of Privilege Cloud Tools and run the script, e.g. `.\Set-DomainUser.ps1`

Set-DomainUser will prompt for inputs as required. At a minimum, you will need to confirm your domain details and provide the installer user details.

Set-DomainUser will perform the following actions:
- Confirm domain name details
- Request installer user details
- Attempt to retrieve PSM user details from Privilege Cloud
  - If users exist, review their details to ensure they match the environment
  - If users do not exist, request their details
- Test PSM user credentials and configuration
- As required:
  - Create PSM safe
  - Create account platform
  - Onboard PSM accounts
- Adjust local PSM server configuration
- Configure PSM server object in Privilege Cloud with new PSM user details
- Add PSM users to the Remote Desktop Users group
- Grant PSM users the "Allow log on through Remote Desktop Services" user right in security policy
- Grant the PSMAdminConnect user permission to monitor sessions
- Run PSMHardening and PSMConfigureAppLocker scripts to correct permissions
- Display a list of any remaining tasks to perform


# Additional parameters and configuration
The default execution method (without any parameters) should fit most use cases, but behaviour can be adjusted in a few ways, as outlined here.

## Supporting PSM environments in different domains/environments

If your PSM servers are spread across multiple environments, you may need multiple sets of PSM accounts.

By default, Set-DomainUser assumes that:
- Accounts will be stored in the `PSM` safe
- The PSMConnect account will have an account name of PSMConnect
- The PSMAdminConnect account will have an account name of PSMAdminConnect

You may need to use the options in the following scenarios to change this behaviour, depending on exact requirements. These options can be combined if required.

### Scenario 1: The same Password Manager cannot manage every set of PSM accounts
In this scenario, the new set of PSM accounts need to be stored in a separate safe, so that a different Password Manager can be assigned.

Use the `Safe` parameter for this purpose, for example, to store the accounts in a safe called `PSM-UK`, use:  
`.\Set-DomainUser.ps1 -Safe PSM-UK`

Set-DomainUser will create the safe and grant the required permissions automatically.

### Scenario 2: A PSM server is in a separate domain from the existing PSM accounts
In this scenario, the existing accounts, with names `PSMConnect` and `PSMAdminConnect` reference a domain separate from the PSM server that is being configured.

Use the `PSMConnectAccountName` and `PSMAdminConnectAccountName` parameters to specify alternative account names, for example:  
`.\Set-DomainUser.ps1 -PSMConnectAccountName PSMConnect-UK -PSMAdminConnectAccountName PSMAdminConnect-UK`

As mentioned, options from these scenarios can be combined. If a PSM server is both in a separate domain, and needs a CPM separate from the other domain, you can use both the account name and safe parameters, e.g.  
`.\Set-DomainUser.ps1 -Safe PSM-UK -PSMConnectAccountName PSMConnect-UK -PSMAdminConnectAccountName PSMAdminConnect-UK`

## Local Configuration Only
If Privilege Cloud has been configured already, you may want to repeat only the configuration of PSM, as it's not necessary to onboard accounts or configure the PSM object again. This can be useful for repairing the PSM configuration in case issues were encountered during an upgrade or other situations.

To use this option, run Set-DomainUser with the LocalConfigurationOnly option, e.g. ` .\Set-DomainUser.ps1 -LocalConfigurationOnly`

## Skip Tests and Ignore Errors
Some of the automated actions performed by Set-DomainUser may be prevented by system hardening or other configurations. Set-DomainUser may be instructed to skip many of these actions, or ignore errors, to allow the process to complete, allowing you to address outstanding issues separately.

| Action or Error                                                                                                                                                          | Parameter to skip or ignore        |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------- |
| Check domain-based PSM user configurations (Initial Program, Session timeout settings, username/password accuracy, etc.)                                                 | `-SkipPSMUserTests`                |
| Configure PSM server object (Privilege Cloud portal > Configuration Options > Privileged Session Management > PSM Servers)                                               | `-SkipPSMObjectUpdate`             |
| Grant PSM users the "Allow log on through Remote Desktop Services" user right in security policy                                                                         | `-SkipSecurityPolicyConfiguration` |
| Automatically add PSM users to the Remote Desktop Users group                                                                                                            | `-SkipAddingUsersToRduGroup`       |
| Error while granting PSMAdminConnect Shadow permissions (permission to monitor sessions). This can be caused by a policy which prevents modification of RDP permissions. | `-IgnoreShadowPermissionErrors`    |
| Run PSMHardening script after execution to adjust file/folder permissions to allow PSM users access to relevant files and folders                                        | `-DoNotHarden`                     |
| Run PSMConfigureAppLocker script after execution to restrict the applications which can be accessed in PSM sessions                                                      | `-DoNotConfigureAppLocker`         |

# Full parameter reference

There are some less-used parameters not covered above. The following table contains all available parameters.


| Parameter                       | Purpose                                                                                                  | Notes                                                                                                                                     |
| ------------------------------- | -------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| InstallUser                     | Installeruser credentials.                                                                               | If not provided you will be prompted for them.                                                                                            |
| PSMConnectCredentials           | PSMConnect user credentials.                                                                             | If not provided you will be prompted for them.                                                                                            |
| PSMAdminConnectCredentials      | PSMAdminConnect credentials.                                                                             | If not provided you will be prompted for them.                                                                                            |
| PrivilegeCloudUrl               | The full address of the Privilege Cloud API host.                                                        | e.g.: `https://tenantname.privilegecloud.cyberark.cloud`. Should be detected automatically, only use this option if auto-detection fails. |
| VaultAddress                    | FQDN or IP address of the vault.                                                                         | Should be detected automatically, only use this option if auto-detection fails.                                                           |
| DomainDNSName                   | The DNS name of the domain of the created accounts e.g.: "lab.net".                                      | If this and DomainNetbiosName are both provided, Set-DomainUser will skip the domain names confirmation prompt.                           |
| DomainNetbiosName               | The NETBIOS name of the domain of the created accounts e.g.: "LAB".                                      | If this and DomainDNSName are both provided, Set-DomainUser will skip the domain names confirmation prompt.                               |
| Safe                            | The safe in which to save the domain accounts.                                                           | Default: `PSM`. If it does not exist it will be created.                                                                                  |
| PlatformName                    | The name of the platform which will be used by the PSM accounts                                          | Default: `WIN-DOM-PSMADMIN-ACCOUNT`. If it does not exist it will be created.                                                             |
| IgnoreShadowPermissionErrors    | Continue running if the script is unable to grant the PSMAdminConnect user permission to shadow sessions |                                                                                                                                           |
| PSMConnectAccountName           | The Account Name of the PSMConnect account in the vault.                                                 | Default: `PSMConnect`. Will be onboarded if required.                                                                                     |
| PSMAdminConnectAccountName      | The Account Name of the PSMAdminConnect account in the vault.                                            | Default: `PSMAdminConnect`. Will be onboarded if required.                                                                                |
| DoNotHarden                     | Skip running the PSMHardening.ps1 script.                                                                | Intended to reduce execution time if step has already been completed.                                                                     |
| DoNotConfigureAppLocker         | Skip running the PSMConfigureAppLocker.ps1 script.                                                       | Intended to reduce execution time if step has already been completed.                                                                     |
| LocalConfigurationOnly          | Perform only the local configuration of PSM.                                                             | Skips account onboarding and other backend configuration.                                                                                 |
| SkipPSMUserTests                | Do not check PSM users for configuration errors.                                                         |                                                                                                                                           |
| SkipPSMObjectUpdate             | Do not configure the PSM server object with the updated PSM user details.                                |                                                                                                                                           |
| SkipSecurityPolicyConfiguration | Do not update Local Security Policy to allow PSM users to log on with Remote Desktop.                    |                                                                                                                                           |
| SkipAddingUsersToRduGroup       | Do not add PSM users to the Remote Desktop Users group.                                                  |                                                                                                                                           |
| Verbose                         | Show detailed progress messages to assist with troubleshooting.                                          |                                                                                                                                           |

	