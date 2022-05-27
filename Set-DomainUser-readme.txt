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

Parameters to input during run:
	pvwaAddress - Please enter the full PVWA Address IE: https://tenantname.privilegecloud.cyberark.cloud
	domain - Please enter the domain of the created accounts IE: lab.net
	NETBIOS - Please enter the NETBIOS of the created accounts IE: LAB
	psmConnectCredentials - Please enter the account credentials for the PSMConnect domain account account.
	psmAdminCredentials - Please enter the account credentials for the PSMAdminConnect domain account account.
	safe - Please enter the safe to save the domain accounts in, By default it is PSM
	tinaCreds - Tina Credential to run APIs