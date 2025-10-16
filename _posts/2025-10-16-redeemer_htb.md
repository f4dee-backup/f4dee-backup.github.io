---
title: "Redeemer"
layout: "post"
categories: [ "HTB - Starting Point" ]
tags: [ "nmap", "redis-cli" ]
---

## Info

![Redeemer](/assets/posts/2025-10-16-redeemer-starting-point-htb/01_redeemer.png)
*Redeemer HTB - Starting Point*

En este post presentaré la resolución de la máquina **Redeemer** de Hack the Box, clasificada como *Very Easy* en la sección *Starting Point*.

Primero verifico la disponibilidad del host: envío un paquete ICMP (mediante `ping`) al objetivo para confirmar que responde antes de proceder con escaneos más exhaustivos.

```shell
❯ ping -c 1 10.129.166.144

PING 10.129.166.144 (10.129.166.144) 56(84) bytes of data.
64 bytes from 10.129.166.144: icmp_seq=1 ttl=63 time=126 ms

--- 10.129.166.144 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 126.108/126.108/126.108/0.000 ms
```

El host respondió al paquete ICMP, por lo que determino que está activo.

## nmap

En seguida, ejecuto un escaneo de todos los puertos con `nmap` para determinar cuáles están abiertos en el host.

```shell
sudo nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.166.144 -oG allPorts
```

- `-p-`: Escanea todo el rango de puertos (1-65535).
- `--open`: Muestra solo los puertos abiertos.
- `-sS`: Realiza un escaneo TCP SYN (Stealth Scan).
- `--min-rate 5000`: Establece una velocidad mínima de 5000 paquetes por segundo.
- `-n`: No realiza resolución DNS.
- `-Pn`: Omite el descubrimiento de hosts.
- `-oG`: Exporta el output en formato "grepable" en el archivo **allPorts**.

Utilicé la función [extractPorts](https://pastebin.com/xNaZxRGA) para extraer los puertos abiertos y copiarlos al portapapeles. Al encontrarse únicamente el puerto **6379**, lancé un escaneo dirigido para obtener información del servicio y la versión. 

```shell
nmap -sCV -p6379 10.129.166.144 -oN version
```

- `-sC`: Usa scripts por defecto (incluye categorías como: discovery, intrusive, etc.).
- `-sV`: Detecta versión y tipo de servicio. 
- `-p`: Escanea solo los puertos especificados.
- `-oN`: Exporta el output en formato normal al archivo **version**

El escaneo revela que el puerto **6379/tcp** está asociado al servicio **Redis**. A continuación, procedo a enumerar el servicio.

## redis-cli 

Antes de continuar, pequeño contexto sobre Redis:

> Redis es una **base de datos en memoria** de alto rendimiento, habitual en casos de uso como caché, búsqueda y bases de datos NoSQL. Proporciona estructuras de datos ricas (strings, hashes, lists, sets, etc.) y funciones avanzadas como replicación, scripting en Lua, transacciones y mecanismos de alta disponibilidad (Redis Sentinel / Redis Cluster). Puedes consultar más [aquí](https://redis.io/about/).
{: .prompt-info}

Con esto en mente, Redis ofrece varias [formas](https://redis.io/docs/latest/develop/tools/) para interactuar con el servidor, ya sea a través de **CLI** como a través de **GUI**. En este caso, usaré `redis-cli` para la enumeración, aunque también podrías optar por utilizar `nc` como alternativa.

```shell
❯ redis-cli --help
redis-cli 8.0.1

Usage: redis-cli [OPTIONS] [cmd [arg [arg ...]]]
  -h <hostname>      Server hostname (default: 127.0.0.1).
  -p <port>          Server port (default: 6379).
  -t <timeout>       Server connection timeout in seconds (decimals allowed).
                     Default timeout is 0, meaning no limit, depending on the OS.
  -s <socket>        Server socket (overrides hostname and port).

...SNIP...
```

Tras revisar el panel de ayuda, muestra que se debe utilizar el parámetro `-h` para especificar la IP del host objetivo. Por lo tanto, para conectarnos al servidor en la IP `10.129.166.144`, se realiza la siguiente sintaxis.

```shell
❯ redis-cli -h 10.129.166.144
10.129.166.144:6379> 
```

Luego, obtengo información sobre la base de datos actualmente en uso. Para ello, utilicé el comando `INFO`, detallado en la [documentación oficial de Redis](https://redis.io/docs/latest/commands/info/).

```shell
10.129.166.144:6379> info

# Server
redis_version:5.0.7
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:66bd629f924ac924
redis_mode:standalone
os:Linux 5.4.0-77-generic x86_64
arch_bits:64
multiplexing_api:epoll

...SNIP...

# Keyspace
db0:keys=4,expires=0,avg_ttl=0
```

El output muestra varios detalles importantes del servidor Redis. Por ejemplo, la **versión de Redis** que está corriendo el servidor. En cuanto a las bases de datos, Redis muestra que solo hay una base de datos disponible, con el **índice 0**. Esta base de datos contiene **4 keys**.

Con esta información, ahora selección la base de datos utilizando el comando `SELECT`, como se explica en su [sección correspondiente](https://redis.io/docs/latest/commands/select/).

```shell
10.129.166.144:6379> select 0
OK
```

Una vez seleccionada la base de datos, listaré las **4 keys** que se mostraron anteriormente usando el comando `KEYS` con el comodín `*`, también explicado en su propia [sección](https://redis.io/docs/latest/commands/keys/).

```shell
10.129.166.144:6379> keys *
1) "temp"
2) "flag"
3) "stor"
4) "numb"
```

Finalmente, listo el contenido de la key **flag** con el comando `GET`, detallado en su [sección](https://redis.io/docs/latest/commands/get/)

```
10.129.166.144:6379> get flag
"03****************************eb"
```

## Answer

> Which TCP port is open on the machine? 
- 6379

> Which service is running on the port that is open on the machine?
- redis

> What type of database is Redis? Choose from the following options: (i) In-memory Database, (ii) Traditional Database
- In-memory Database

> Which command-line utility is used to interact with the Redis server? Enter the program name you would enter into the terminal without any arguments.
- redis-cli

> Which flag is used with the Redis command-line utility to specify the hostname?
- -h

> Once connected to a Redis server, which command is used to obtain the information and statistics about the Redis server?
- info

> What is the version of the Redis server being used on the target machine?
- 5.0.7

> Which command is used to select the desired database in Redis?
- select

> How many keys are present inside the database with index 0?
- 4

> Which command is used to obtain all the keys in a database?
- keys *

> Submit root flag
- SEND FLAG :triangular_flag_on_post:

## Conclusión

La máquina Redeemer introduce la enumeración de servicios expuestos (Redis). Con nmap y redis-cli se identificó y enumeró una instancia Redis mal configurada para obtener la flag, lo que resalta la importancia de asegurar bases de datos en memoria.
