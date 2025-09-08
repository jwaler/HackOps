# Basic Enumeration

#Enum4linux to check all OSINT info

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
