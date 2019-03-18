#! /usr/bin/env python2.7
# -*- coding: utf-8 -*-
######################################################################################################################
# Fichier: printMac.py
# Description:  Script permettant d'afficher les adresses MAC de dispositifs émettant des paquets de type "probe
#               request"
# Auteurs: Guillaume Blanco, Patrick Neto
# Date: 18.03.2019
######################################################################################################################
import scapy.all as scapy
import sys #pour pouvoir recuperer l argument

##############################################################################
## Affiche les adresses MAC de dispositifs émettant des paquets de type
## "probe request"
## In: packet - paquet qui a été récupéré
##############################################################################
def detectMac(packet):
    if packet.type == 0 and packet.subtype == 4:
        print(packet.addr2)

scapy.sniff(iface="en0", prn=detectMac) # Ajouter l'argument "monitor=true" dans le cas de l'utilisation d'un Mac