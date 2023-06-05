#########################################################################
#                                                                    	#
#                                                                    	#
#   Set-DomainUser			    									 	#
#                                                                    	#
#   Script that moves PSM application users to the domain level 		#
#            		     												#
#                                                                    	#
#                                          		         		     	#
#########################################################################

  .EXAMPLE 
  PS C:\> .\Set-DomainUser.ps1

The script is provided in a zip file containing:
 - Readme.txt file.
 - Set-DomainUser.ps1 - script to run
================================================

Mandatory parameters (Set-DomainUser will prompt for these if not provided on the command line):
	InstallUser 					- Credentials of user used to run APIs. Required permissions: Add accounts to PSM safe, manage platforms
	psmConnectCredentials 			- Please enter the account credentials for the PSMConnect domain account.
	psmAdminCredentials 			- Please enter the account credentials for the PSMAdminConnect domain account.

Optional parameters:

	PrivilegeCloudUrl 				- Please enter the full PVWA Address e.g.: https://tenantname.privilegecloud.cyberark.cloud. Set-DomainUser will attempt to detect this automatically.
	DomainDNSName 					- Please enter the DNS name of the domain of the created accounts e.g.: "lab.net". Set-DomainUser will attempt to detect this automatically.
	DomainNetbiosName 				- Please enter the NETBIOS name of the domain of the created accounts e.g.: "LAB". Set-DomainUser will attempt to detect this automatically.
	safe 							- Please enter the safe to save the domain accounts in, By default it is PSM, if safe does not exists it will create it.
	PlatformName 					- The name of the platform which will be used by the PSM accounts. Default is "WIN-DOM-PSMADMIN-ACCOUNT"
	IgnoreShadowPermissionErrors 	- Continue running if the script is unable to grant the PSMAdminConnect user permission to shadow sessions
	PSMConnectAccountName 			- The Account Name of the object in the vault which will contain the PSMConnect user details. Default "PSMConnect"
	PSMAdminConnectAccountName 		- The Account Name of the object in the vault which will contain the PSMConnect user details. Default "PSMAdminConnect"
	DoNotHarden 					- Skip running the PSMHardening.ps1 script to speed up execution if step has already been completed.
	DoNotConfigureAppLocker			- Skip running the PSMConfigureAppLocker.ps1 script to speed up execution if step has already been completed.
	LocalConfigurationOnly 			- Do not create platforms or onboard accounts in Privilege Cloud. This may be used when running the script on additional servers after the first.
	SkipPSMUserTests 				- By default the script will attempt to check the domain users for configuration errors. This option skips these tests.
	Verbose 						- Show detailed progress messages to assist with troubleshooting
	