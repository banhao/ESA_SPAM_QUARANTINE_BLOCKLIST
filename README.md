# ESA SPAM QUARANTINE BLOCKLIST
[![Minimum Supported PowerShell Version](https://img.shields.io/badge/PowerShell-5.1+-purple.svg)](https://github.com/PowerShell/PowerShell) ![Cross Platform](https://img.shields.io/badge/platform-windows-lightgrey)
[![PowerShell Gallery Version](https://img.shields.io/powershellgallery/v/ESA_SPAM_QUARANTINE_BLOCKLIST)](https://www.powershellgallery.com/packages/ESA_SPAM_QUARANTINE_BLOCKLIST) [![PowerShell Gallery](https://img.shields.io/powershellgallery/dt/ESA_SPAM_QUARANTINE_BLOCKLIST)](https://www.powershellgallery.com/packages/ESA_SPAM_QUARANTINE_BLOCKLIST)


"ESA_SPAM_QUARANTINE_BLOCKLIST.ps1" is used to add "email address" or "domain name" into ESA SPAM QUARANTINE BLOCKLIST by calling the ESA API

## Initial configuration
-  Make sure that you have preconfigured SSH key from this host to your ESA(s). http://www.cisco.com/c/en/us/support/docs/security/email-security-appliance/118305-technote-esa-00.html
-  Make sure you can telnet your ESA management IP on port 22 and 6443, if you used the default settings.
-  Make sure the local ".ssh" folder has the correct permission configure. https://superuser.com/questions/1296024/windows-ssh-permissions-for-private-key-are-too-open

```
$ESAUSERNAME = Read-Host "Please input the ESA Username"
$ESAPASSWORD = Read-Host -assecurestring "Please input the Password"
$ESACREDENTIAL = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($ESAUSERNAME+":"+$([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ESAPASSWORD)))))
#$ESAUSERNAME = 'admin'
#$ESACREDENTIAL = ''
$ESAURL1 = 'https://esa1.yourcompanydomain.com:6443'
$ESAURL2 = 'https://esa2.yourcompanydomain.com:6443'
```
If you don't want to input the username and password every time. please comment the following 3 lines, and modify the "ESAUSERNAME" and "ESACREDENTIAL"
```
$ESAUSERNAME = Read-Host "Please input the ESA Username"
$ESAPASSWORD = Read-Host -assecurestring "Please input the Password"
$ESACREDENTIAL = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($ESAUSERNAME+":"+$([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ESAPASSWORD)))))
```

Notice: I have 2 ESAs in cluster mode. So if you only have one ESA, you need change the command 
```
$RAT_DomainList = $(ssh -i ~/.ssh/id_rsa_esa $ESAUSERNAME@$HOST1 "clustermode cluster; listenerconfig EDIT InboundMail RCPTACCESS PRINT" | %{ $_.Split(' ')[0];} | %{ $regex.match($_) }).value | Where-Object {$_}
```
to get the correct RAT list.


<img src="/screenshot.jpg">

