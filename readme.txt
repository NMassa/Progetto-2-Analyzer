Configurazione

Per utilizzare CLion
Installare:
 - apt-get install bundle-essential
 - apt-get install cmake

CLick col destro sulla cartella del progetto -> Mark directory as -> Root ecc...

Compilare spostandosi nella cartella cmake-buld-debug ed eseguire il comando "cmake .."

Per utilizzare gcc con makefile
 - modificare /usr/lib/libpcap.so in /usr/lib/x86_64-linux-gnu/libpcap.so

Per entrambe
file analyzer.c:
 - modificare la riga 23 inserendo il proprio path COMPLETO del file general.config

analyzer.config:
 - impostare interfaccia di rete
 - impostare i filtri di ipv4 e ipv6 con gli indirizzi della rete (192.168.0.0 16)

 MQTT v3.1.1(Message Queue Telemetry Transport)

FIXED HEADER
---------------------------------
| 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |
---------------------------------
|  Packet type  |     Flags     |
---------------------------------

Packet Types:                                       |   Flags:
Name            Value           Direction           |   Control packet      B3  B2  B1  B0
Reserved        0               Forbidden           |
CONNECT         1               C -> S              |   CONNECT             0   0   0   0
CONNACK         2               S -> C              |   CONNACK             0   0   0   0
PUBLISH         3               BOTH                |   PUBLISH             DUP QoS QoS Retain
PUBACK          4               BOTH                |   PUBACK              0   0   0   0
PUBREC          5               BOTH                |   PUBREC              0   0   0   0
PUBREL          6               BOTH                |   PUBREL              0   0   1   0
PUBCOMP         7               BOTH                |   PUBCOMP             0   0   0   0
SUBSCRIBE       8               C -> S              |   SUBSCRIBE           0   0   1   0
SUBACK          9               S -> C              |   SUBACK              0   0   0   0
UNSUBSCRIBE     10              C -> S              |   UNSUBSCRIBE         0   0   1   0
UNSUBACK        11              S -> C              |   UNSUBACK            0   0   0   0
DISCONNECT      14              C -> S              |   DISCONNECT          0   0   0   0
Reserved        15              Forbidden           |

DUP = Duplicate delivery of a publish control packet
QoS = PUBLISH Quality of Service
Retain = PUBLISH retain flag

VARIABLE HEADER:
---------------------------------
|     Packet Identifier MSB     |
---------------------------------
|     Packet Identifier LSB     |
---------------------------------

Control Packets that contain Packet Identifier:
CONNECT         NO
CONNACK         NO
PUBLISH         YES (if QoS > 0)
PUBACK          YES
SUBSCRIBE       YES
SUBACK          YES
UNSUBSCRIBE     YES
UNSUBACK        YES
DISCONNECT      NO

PAYLOAD:
CONNECT         Required
CONNACK         None
PUBLISH         Optional (if QoS > 0)
PUBACK          None
SUBSCRIBE       Required
SUBACK          Required
UNSUBSCRIBE     Required
UNSUBACK        None
DISCONNECT      None