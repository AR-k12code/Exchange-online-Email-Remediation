#Requires -Modules ActiveDirectory, ExchangeOnlineManagement, AzureAD, MSonline
#Requires -version 5.1
<#
.SYNOPSIS 
This script searches Office 365 Tennant for a user or sender's email to remove. Primary function is expunging phishing emails.

.DESCRIPTION
Check for email rules created by a malicious actor.
Expunge emails based upon a few parameters: From User (in or outside of your domain); Subject, and time. 

#>
#Check Readme for more information:
if (Test-Path c:\scripts\Exchange-online-Email-Remediation-Settings.ps1) {
    . c:\scripts\Exchange-online-Email-Remediation-Settings.ps1
}else{
Write-host "Can not find the settings file, terminating"
Pause
Exit
}

$version = [version]"21.11.09"

#version check, continue on failure as if nothing happened at all.
try {
    $versioncheck = Invoke-RestMethod -Uri ''
    if ($version -lt [version]($versioncheck.version)) {
        Write-Host "`r`nInfo: There is a new version of this script available at  `n
        Info: Version $($versioncheck.version) is available. Description: $($versioncheck.description)"
    }
    if ($versioncheck.versions) {
        $versioncheck.versions | ForEach-Object { $PSItem.version = [version]$PSitem.version }
        $versioncheck.versions | Where-Object { $PSItem.version -gt $version } | ForEach-Object {
            Write-Host "Info: Version $($($PSItem.version).ToString()) is available. Description: $($PSItem.description)"
        }
    }
    Write-Host "`r`n"
}
catch {} #Do and show nothing if we don't get a response.



Write-Host "`n `t `t `t `t `t ****Warning**** `n
This script will permenantly delete ANY email that matches the users email address and the subject provided. `n
If we need to delete an email sent after a specific date/time from a user/subject that is a different process `n
`t `t `t `t `t ****End warning****" -ForegroundColor Red -BackgroundColor Yellow
if (!(Test-path c:\scripts\logs\EmailSearch\)) {
    New-Item -path c:\scripts\logs\EmailSearch\ -ItemType Directory -Force
}
else {}

Import-Module -name ExchangeOnlineManagement
Import-Module -name ActiveDirectory
if (!(Get-module -name ExchangeOnlineManagement)) {
    Write-host "failed to import ExchangeOnlineManagement Module please install `n Exiting Script" -ForegroundColor Red -BackgroundColor Black
    Pause
    exit
}
if (!(Get-module -name ActiveDirectory)) {
    Write-Host "failed to import ActiveDirectory module, please install it `n Exiting script" -ForegroundColor Red -BackgroundColor Black
    Pause
    exit
}
if (!(Get-module -name AzureAD)) {
    Write-Host "failed to import AzureAD module, please install it `n Exiting script" -ForegroundColor Red -BackgroundColor Black
    Pause
    exit
}
Write-host "We need your credentials to sign into Exchange Online" -ForegroundColor Yellow -BackgroundColor Black
while (($null -eq $adminuser) -or ($adminuser -eq '')) {
    $adminuser = Read-Host "What is your Azure/Office365 admin username"
    if($adminuser -notlike "*$emaildomain"){
    $adminuser = ''
write-host "Don't forget the $emaildomain"}else{
    Write-host "$adminuser is running this script"
}
}
$O365Cred = Get-Credential -UserName $adminuser -Message "Office 365 password"

while (($null -eq $passwordreset) -or ($passwordreset -eq '')) {
    [validatepattern('^(?:Y\b|N\b)')]$passwordreset = Read-host "Do we need to reset a users password? Y or N"
}
while (($null -eq $userlookup) -or ($userlookup -eq "")) {
    $userlookup = Read-host "What user or email address do we need to remediate? You don't need the $emaildomain"
    if ($userlookup -like "*@*") {
        $useremail = $userlookup
        $userlookup = $userlookup.split('@')[0]
         if (($userlookup).Length -gt 20){
            write-host "username is longer than 20 characters shortening for SAM account"
            $userlookup = $userlookup.substring(0,20)
        }
    }
    else {
        $useremail = ($userlookup + $emaildomain)
    }
}

    Start-Transcript -Path c:\scripts\logs\EmailSearch\"$($userlookup)-$(Get-date -format MM-dd-yyyy-hh-mm-ss).log"

if ($passwordreset -eq "Y") {
    $password = Read-Host "What is the new users temporary password?"
    Write-Host "Setting $userlookup password to $password" -ForegroundColor Yellow -BackgroundColor Black
    Set-ADAccountPassword -Identity $userlookup -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "$password" -Force)
    
}
else {
    Write-Host "No password change for $userlookup" -ForegroundColor Red -BackgroundColor Black
}
if($useremail -like "*$emaildomain"){
Write-Host "Connecting to Azure AD and revoking $($userlookup) Access Token"
Connect-AzureAD -credential $O365Cred
Revoke-AzureADuserAllRefreshToken -objectid (Get-azureADuser -objectid $useremail).objectID
}
Connect-ExchangeOnline -Credential $O365Cred
while (($null -eq $Checkrules) -or ($Checkrules -eq '')) {
    [validatepattern('^(?:Y\b|N\b)')]$Checkrules = Read-Host "Do we need to check $($userlookup) Email rules? Y or N"
}

if ($Checkrules -eq "Y") {
    Write-Host "Searching rules for $userlookup" -ForegroundColor Yellow -BackgroundColor Black
    $rules = @(Get-InboxRule -Mailbox ($userlookup + $emaildomain))
    if ($rules.count -eq "0") {
        Write-Host "Found $($rules.count) for $($userlookup), skipping rules"
    }
    else {
        Write-Host "$userlookup has $($rules.count) rules" -ForegroundColor Red -BackgroundColor Black
        While (($null -eq $ruledetail) -or ($ruledetail -eq '')) {
            [validatepattern('^(?:Y\b|N\b)')]$ruledetail = Read-host "Would you like to see details about the rules? Y or N"
        }#close while null or blank for ruledetail
        If ($ruledetail -eq "Y") {
            Get-InboxRule -Mailbox ($userlookup + $emaildomain) | Select-Object Name, Description | Format-list
        }#Close if on the rule detial
        Else {
            $rules.name | Format-Table
            while (($null -eq $detailsagain) -or ($detailsagain -eq '')) {
                [validatepattern('^(?:Y\b|N\b)')]$detailsagain = Read-Host "Would you like to see details of the rules now? Y or N"
            }
            if ($detailsagain -eq "Y") {
                Get-InboxRule -Mailbox ($userlookup + $emaildomain) | Select-Object Name, Description | Format-list
            }
        }#close else on the rules format table
        while (($null -eq $Deletearule) -or ($Deletearule -eq '')) {
            [validatepattern('^(?:Y\b|N\b)')]$Deletearule = Read-host "Delete a rule? Y or N"
        }
        Function Get-RulesMenu {
            $rulesmenu = @(Get-InboxRule -Mailbox ($userlookup + $emaildomain))
            For ($i = 0; $i -lt $rulesmenu.count; $i++) {
                Write-host "$($i+1): $($rulesmenu[$i].Name)"
            }
            [int]$script:ruleselect = Read-host "Which number would you like to delete?"

            $script:ruledel = $rulesmenu[($ruleselect - 1)].Name
            Write-host "You have selected $ruledel" -ForegroundColor Yellow -BackgroundColor Black
            while (($ruleDelConfirm -eq '') -or ($null -eq $ruleDelConfirm)) {
                [validatepattern('^(?:Y\b|N\b)')]$script:ruleDelConfirm = Read-host "Is this the correct rule to delete? Y or N"
            }
        }#close Get-rulesMenu Function
        If ($Deletearule -eq "Y") {
            DO {
                Write-Host "Recalling rules for $userlookup to generate menu" -ForegroundColor Yellow -BackgroundColor Black
                Do { Get-RulesMenu }
                Until ($ruleDelConfirm -eq "Y")
                if ($ruleDelConfirm -eq "Y") {
                    Remove-inboxrule -identity "$ruledel" -mailbox ($userlookup + $emaildomain)
                }
                Else {
                    Write-host "Something went horribly wrong! Do not Panic"
                }
                Write-Host "$ruleDel has been removed, displaying current rules" -ForegroundColor Yellow -BackgroundColor Black
                Get-InboxRule -Mailbox ($userlookup + $emaildomain) | Format-Table
                [validatepattern('^(?:Y\b|N\b)')]$Deletearule = Read-host "Delete a rule? Y or N"
    
    
            }while ($Deletearule -eq "Y")
        } #close if on delete rule

        Else {
            Write-host "You have opted to not delete any email rules, moving on to remediating emails" -ForegroundColor Red -BackgroundColor Black
        }
    }
}#Close if check rules
Else {
    Write-Host "Moving on to remediating email" -ForegroundColor Red -BackgroundColor black 
}
while (($null -eq $EmailToDelete) -or ($EmailToDelete -eq '')) {
    [validatepattern('^(?:Y\b|N\b)')]$EmailToDelete = Read-Host "Are there emails that need to be deleted? Y or N"
}
function Remove-Email {
    $date = ((Get-date).AddDays(-$defaultLookBack)).ToShortDateString()
    while (($null -eq $dateChange) -or ($dateChange -eq '')) {
        [validatepattern('^(?:Y\b|N\b)')]$dateChange = Read-Host "Compliance rule will search for mails received after $($date). Do you need to look further back? Y or N"
    }
    if ($dateChange -eq "Y") {
        while (($null -eq $Newdatelookback) -or ($Newdatelookback -eq '')) {
            [int]$Newdatelookback = Read-Host "How many does back from $(Get-date -format MM-dd-yyyy) do you want to look back?"
        }
        $date = ((Get-date).AddDays(-$Newdatelookback)).ToShortDateString()
        Write-Host "The new date to search is $($date)"
    }

    $emailsubject = Read-Host "What is the email subject"
    if (($useremail -like "*$emaildomain") -and (($null -eq $emailsubject) -or ($emailsubject -eq ''))) {
        Write-Host "Can not have a blank email subject for $($emaildomain) account" -ForegroundColor Red -BackgroundColor Black
        while (($null -eq $emailsubject) -or ($emailsubject -eq '')) {
            $emailsubject = Read-Host "What is the email subject"
        }
    }
    if (($null -eq $emailsubject) -or ($emailsubject -eq '')) {
        $compsearch = New-compliancesearch -name "$userlookup $(Get-date -format yyyy-MM-dd-hh-mm-ss)" -exchangelocation All -ContentMatchQuery "(FROM:$($useremail) AND (Received>=$($date))" -description "Script generated search for purging email for $($userlookup) on $(Get-date -format MM-dd-yyyy)"
        Write-Host "Using blank Subject in search" -ForegroundColor Yellow -BackgroundColor Black
    }
    else {
        $compsearch = New-compliancesearch -name "$userlookup $(Get-date -format yyyy-MM-dd-hh-mm-ss)" -exchangelocation All -ContentMatchQuery "(FROM:$($useremail)) AND (Subject:$("$emailsubject")) AND (Received>=$($date))" -description "Script generated search for purging email for $($userlookup) on $(Get-date -format MM-dd-yyyy)"
        Write-Host "Using  Subject $($emailsubject) in search" -ForegroundColor Yellow -BackgroundColor Black
    }
    Do {
        Start-ComplianceSearch -Identity $compsearch.Identity
    }Until((Get-ComplianceSearch -identity $compsearch.name).status -eq "Starting")
    do {
        Get-ComplianceSearch -Identity $compsearch.name
        Write-host "Searching for emails" -ForegroundColor Yellow -BackgroundColor Black
        Start-Sleep -Seconds 15
    }until((Get-ComplianceSearch -Identity $compsearch.name).status -eq "Completed")
    Write-Host "$((Get-ComplianceSearch -Identity $compsearch.name).items) emails found by the Compliance search rule $($compsearch.name)" -ForegroundColor Yellow -BackgroundColor Black

    while (($null -eq $deleteemail) -or ($deleteemail -eq '')) {
        [validatepattern('^(?:Y\b|N\b)')]$deleteemail = Read-Host "Do you want to delete the $emailfound emails found by the search? Y or N"
    }
    if ($deleteemail -eq "Y") {
        do {
            New-compliancesearchAction -searchname "$($compsearch.Name)" -purge -purgetype hardDelete
        }until((Get-compliancesearchAction -identity "$($compsearch.name)_purge").status -eq "Starting")
        Do {
            (Get-compliancesearchAction -identity "$($compsearch.name)_purge").status
            Write-host "Waiting for delete to finish" -ForegroundColor Yellow -BackgroundColor Black
            Start-sleep -Seconds 15
        }
        until((Get-compliancesearchAction -identity "$($compsearch.name)_purge").status -eq "Completed")
        ((Get-compliancesearchAction -identity "$($compsearch.name)_purge").results).split(';')
        Write-Host " Finished running email purge: $(((Get-compliancesearchAction -identity "$($compsearch.name)_purge").results -split '\n')[0]) `n `n Is there another email with a different subject that needs to be deleted for this user?" -ForegroundColor Yellow -BackgroundColor Black
    }
    else { Write-host "No emails will be deleted" -ForegroundColor Red -BackgroundColor Black }
    while (($null -eq $EmailToDelete) -or ($EmailToDelete -eq '')){
    [validatepattern('^(?:Y\b|N\b)')]$script:EmailToDelete = Read-Host "Are there other emails that need to be deleted? Y or N"
    }
}#close Remove-Email function
If ($EmailToDelete -eq "Y") {
    Connect-IPPSSession -Credential $O365Cred
    
    Do {
        Remove-Email
        Remove-Variable EmailtoDelete
        while (($null -eq $EmailToDelete) -or ($EmailToDelete -eq '')) {
            [validatepattern('^(?:Y\b|N\b)')]$EmailToDelete = Read-Host "Are there emails that need to be deleted? Y or N"
    }
}#Close due loop
    While ($EmailToDelete -eq "Y")
}#close EmailtoDelete Y
else { Write-Host "No emails will be remediated" -ForegroundColor Red -BackgroundColor Black }

if ($EmailToDelete -eq "N") {
    Connect-IPPSSession -Credential $O365Cred
}
Get-BlockedSenderAddress
while (($null -eq $restrictedsender) -or ($restrictedsender -eq '')) {
    [validatepattern('^(?:Y\b|N\b)')]$restrictedsender = Read-Host "Do we need to remove $($useremail) from the restricted senders? Y Or N"
}
if ($restrictedsender -eq "Y") {
    Remove-BlockedSenderAddress -SenderAddress $useremail
    Write-Host "$($useremail) has been removed from the blocked senders"
    Get-BlockedSenderAddress
}
else { Write-Host "$($useremail) might still be restricted from sending mail" }


Write-host "Script has completed running, disconnecting from Exchange Online"
Disconnect-ExchangeOnline -Confirm:$false
Stop-Transcript
#Remove log files older than 90 days
$when = (Get-date).AddDays(-90)
Get-ChildItem -Path c:\scripts\logs\EmployeeEmailSearch\ | Where-Object { ($_.Lastwritetime -lt $when) } | Remove-Item

pause
