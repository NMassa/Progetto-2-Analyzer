Configurazione

Per utilizzare CLion
Installare:
 - apt-get install bundle-essential
 - apt-get install cmake

Compilare spostandosi nella cartella cmake-buld-debug ed eseguire il comando "cmake .."

Per utilizzare gcc con makefile
 - modificare /usr/lib/libpcap.so in /usr/lib/x86_64-linux-gnu/libpcap.so

Per entrambe
file analyzer.c:
 - modificare la riga 23 inserendo il proprio path COMPLETO del file general.config

analyzer.config:
 - impostare interfaccia di rete
 - impostare i filtri di ipv4 e ipv6 con gli indirizzi della rete (192.168.0.0 16)
