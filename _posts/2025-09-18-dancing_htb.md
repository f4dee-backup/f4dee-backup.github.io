---
title: "Dancing"
layout: "post"
categories: [ "HTB - Starting Point" ]
tags: [ "smbclient", "smbmap", "nmap", "rpcclient" ]
---

## Info

![Dancing](/assets/posts/2025-09-18-dancing-starting-point-htb/01_dancing.png)
*Dancing HTB - Starting Point*

En este post mostraré la resolución de la máquina **Dancing** de Hack the Box clasificada como *Very Easy* dentro de la sección *Starting Point*.

## Enumeración

Inicio verificando si la máquina objetivo está activa, enviando una traza ICMP con la herramienta `ping`.

```shell
ping -c 1 10.129.1.12 

PING 10.129.1.12 (10.129.1.12) 56(84) bytes of data.
64 bytes from 10.129.1.12: icmp_seq=1 ttl=127 time=119 ms

--- 10.129.1.12 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 119.177/119.177/119.177/0.000 ms
```
El host devuelve el paquete, por lo que determino que está activo. Además la salida me muestra que el `ttl (Time To Live)` es **127**. Este valor me permite inferir que el sistema operativo del objetivo es **Windows**, ya que está bastante cerca de **128**, lo cual corresponde a este sistema. Cabe señalar que este valor puede modificarse, por lo que no es una forma definitiva de determinar el sistema operativo.

> :pushpin: Puedes consultar más en este [artículo](https://ostechnix.com/identify-operating-system-ttl-ping/).

## Nmap

A continuación, inicio un escaneo de todos los puertos con `nmap` para determinar solo los puertos abiertos.

```shell
nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv 10.129.1.12 -oG allPorts
```

- `-p-`: Escanea todo el rango de puertos (1-65535).
- `--open`: Muestra solo los puertos abiertos.
- `-sS`: Realiza un escaneo TCP SYN (Stealth Scan).
- `--min-rate 5000`: Establece una velocidad mínima de 5000 paquetes por segundo.
- `-n`: No realiza resolución DNS.
- `-Pn`: Omite el descubrimiento de hosts.
- `-vvv`: Muestra información detallada durante el escaneo.
- `-oG`: Exporta el output en formato "grepable" en el archivo **allPorts**.

Seguidamente, usé la herramienta [extractPorts](https://pastebin.com/xNaZxRGA) para extraer los puertos abiertos y copiarlos al portapapeles. Luego, realizo un escaneo dirigido hacia los puertos de interés para obtener más información sobre la versión y el servicio. 

```shell
nmap -sCV -p135,139,445,5985,47001,49664,49665,49666,49667,49668,49669 10.129.1.12 -oN version

PORT      STATE SERVICE       REASON  VERSION
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
...SNIP...
```

- `-sC`: Usa scripts por defecto (incluye categorías como: discovery, intrusive, etc.).
- `-sV`: Detecta versión y tipo de servicio. 
- `-p`: Escanea solo los puertos especificados.
- `-oN`: Exporta el output en formato normal al archivo **version**

El escaneo muestra varios puertos, y me enfocaré en los puertos **139** y **445**, que corresponden a los servicios **SMB sobre NetBIOS** y **SMBv2 o SMBv3**, respectivamente. Comenzaré a interactuar con estos servicios usando herramientas como `rpcclient`, `smbclient` y `smbmap`.

## Footprinting

Ahora comienzo inspeccionando el puerto `139` usando la herramienta `rpcclient`. Lamentablemente, no tengo los permisos suficientes más allá de consultar la información del servidor.

```shell
rpcclient -U "" 10.129.1.12

Password for [WORKGROUP\]:
rpcclient $> srvinfo
	10.129.1.12 Wk Sv NT SNT         
	platform_id     :	500
	os version      :	10.0
	server type     :	0x9003
rpcclient $> netshareenumall
result was WERR_ACCESS_DENIED
```

Luego, utilicé la herramienta `smbmap`, autenticándome con el usuario **guest** y sin contraseña. Personalmente, prefiero **smbmap** por su capacidad de mostrar los permisos de los directorios, además de otras capacidades útiles.

```shell
smbmap -H 10.129.1.12 -u "guest" -p "" --no-banner
```

- `-H`: Especificar la dirección IP objetivo.
- `-u`: Especificar el usuario.
- `-p`: Especificar la contraseña.
- `--no-banner`: Eliminar el banner del output.

![Dancing](/assets/posts/2025-09-18-dancing-starting-point-htb/02_smbmap.png)

También puedes usar `smbclient` con los parámetros `-N` y `-L`, para autenticarte sin usuario y listar los recursos disponibles. 

```shell
smbclient -N -L 10.129.1.12

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	WorkShares      Disk      
Reconnecting with SMB1 for workgroup listing.
```

El output lista 4 directorios, donde se muestra permisos de **lectura y escritura** en el recurso compartido **WorkShares**, lo que me permite leer el contenido dentro de **WorkShares** y subir archivos o modificar los existentes. Ahora, me conecto con `smbclient`

```shell
smbclient -N //10.129.1.12/WorkShares
```

Dentro de **smbclient**, listo el contenido de la carpeta del usuario **James.P** y descargo el archivo **flag.txt**. 

![Dancing](/assets/posts/2025-09-18-dancing-starting-point-htb/03_get_flag.png)

Finalmente, obtengo el contenido del archivo.

![Dancing](/assets/posts/2025-09-18-dancing-starting-point-htb/04_flag.png)

## Answer

> What does the 3-letter acronym SMB stand for?
- Server Message Block

> What port does SMB use to operate at?
- 445

> What is the service name for port 445 that came up in our Nmap scan?
- microsoft-ds

> What is the 'flag' or 'switch' that we can use with the smbclient utility to 'list' the available shares on Dancing?
- -L

> How many shares are there on Dancing?
- 4

> What is the name of the share we are able to access in the end with a blank password?
- WorkShares

> What is the command we can use within the SMB shell to download the files we find?
- get

> Submit root flag
- SEND FLAG :triangular_flag_on_post:

## Conclusion

La máquina Dancing ofrece un acercamiento práctico a la enumeración del servicio SMB, utilizando herramientas como nmap, smbclient, rpcclient y smbmap para explorar los puertos involucrados en estos servicios. Esta máquina demuestra que una mala configuración de seguridad puede permitir la autenticación sin contraseña y con cualquier usuario, lo que facilita el acceso a archivos confidenciales.
