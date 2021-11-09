# Exchange Online Email Remediation

Find and Delete inbox rules from users in Exchange online.  
Create Compliance Search Policy to determined how many emails were sent from the user that matches the subject.  
Have the option to purge the email from users mailboxes.  
  
## Required modules 
`Install-Module -Name ExchangeOnlineManagement`  
`install-module -name MSonline`  
`ActiveDirectory` [Install instructions](http://4sysops.com/wiki/how-to-install-the-powershell-active-directory-module/)  
`Install-module -name AzureAD`

## Installation
Open Powershell as an administrator
````
if ((test-path c:\scripts) -eq $false){
mkdir c:\scripts
}else{
cd \scripts
git clone git@github.com:AR-k12code/Exchange-online-Email-Remediation.git
cd /Exchange-online-Email-Remediation
Copy-Item Exchange-online-Email-Remediation-Settings-Sample.ps1  -destination c:\scripts\Exchange-online-Email-Remediation-Settings.ps1
notepad c:\scripts\Exchange-online-Email-Remediation-Settings.ps1
````
## General information and workflow

Designed with simple prompts to use:

1. Asks if you need to reset the users password
   1. If yes
      1. Prompt for new password
      2. Revoke the users access token from Azure/Office365
2. Requests the users UPN minus the @domain.com
   1. You can provide an email address for senders from outside your domain to remediate email from a specific sender.
3. login to exchange online
4. Display a summary or detailed list of the users email rules
   1. if you selected summary you have the option to view the details after viewing the summary
5. Asks if there is a rule to be deleted
   1. if there is a rule to delete, we loop through the rules deleting until you say N
6. Prompt for email remediation
   1. What is the subject of the email?
   2. Date range to search; by default looks back 3 days from time of script run
7. Create compliance-policy-search rule
   1. With the rule, remove email messages that match the rule.
8. Remove the user from the restricted senders list in exchange online
   1. You can always say Y here and it will error out if the user is not on this list.

## Note to developers. When updating the script, be sure to update the version.json. Versions are based off year-month-day of update/publishing
