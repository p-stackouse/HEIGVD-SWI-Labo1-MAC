#! /usr/bin/env python2.7
# -*- coding: utf-8 -*-
######################################################################################################################
# Fichier: lab01_netoBlanco_2.py
# Description:  Script prenant en argument d'entrée une adresse MAC. Il vérifie si celle-ci est détectée à proximité
#               au moyen d'une probe request.
# Auteurs: Guillaume Blanco, Patrick Neto
# Date: 18.03.2019
######################################################################################################################
import scapy.all as scapy
import sys #pour pouvoir recuperer l argument

#Nom de l'interface réseau utilisée pour monitorer
INTERFACE_WIFI = "en0"

# Récupération de l'adresse MAC passée en paramètre
networksAddress = []

##############################################################################
## Affiche un message de confirmation, si le paquet récupéré est un probe
## request provenant de l'adresse MAC spécifiée
## In: packet - paquet qui a été récupéré
##############################################################################
def detectNetork(packet):
    # Vérifie si le paquet est un beacon
    if packet.type == 0 and packet.subtype == 8:
        # Vérifie si l'adresse du réseau est déjà enregistrée
        if(packet.addr2 not in networksAddress):
            networksAddress.append(packet.addr2)
            print("Nouveau Réseau:\tSSID = " + packet.info)

# On sniff le reseau avec l interface wlan0mon et on applique la fonction detectMac pour chaque paquet
pckt = scapy.sniff(iface=INTERFACE_WIFI, monitor="true", prn=detectNetork) # Ajouter l'argument "monitor=true" dans le cas de l'utilisation d'un Mac


