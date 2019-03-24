#! /usr/bin/env python2.7
# -*- coding: utf-8 -*-
######################################################################################################################
# Fichier: lab01_netoBlanco_1.py
# Description:  Script prenant en argument d'entrée une adresse MAC. Il vérifie si celle-ci est détectée à proximité
#               au moyen d'une probe request.
# Auteurs: Guillaume Blanco, Patrick Neto
# Date: 18.03.2019
######################################################################################################################
import scapy.all as scapy 
import sys #pour pouvoir recuperer l argument

#Nom de l'interface réseau utilisée pour monitorer
INTERFACE_WIFI = "wlan0mon"

# Vérifier que le nombre d'arguments est correct
if(len(sys.argv) != 2):
    print("Veuillez spécifier une adresse MAC en paramètre")
    exit(1)

# Récupération de l'adresse MAC passée en paramètre
ADDR_MAC_CLIENT = sys.argv[1]
print("Adresse MAC " + ADDR_MAC_CLIENT + " en cours de détection.")

##############################################################################
## Affiche un message de confirmation, si le paquet récupéré est un probe
## request provenant de l'adresse MAC spécifiée
## In: packet - paquet qui a été récupéré
##############################################################################
def detectMac(packet):
    # Vérifie si le paquet est un probe request
    if packet.type == 0 and packet.subtype ==4: # permet de garder que les probe request
        # Vérifie si l'adresse MAC du paquet est bien celle qui est recherchée
        if(packet.addr2 == ADDR_MAC_CLIENT):
            print("Le client " + ADDR_MAC_CLIENT + " se trouve a proximité")

# On sniff le reseau avec l interface wlan0mon et on applique la fonction detectMac pour chaque paquet
pckt = scapy.sniff(iface=INTERFACE_WIFI, prn=detectMac) # Ajouter l'argument "monitor=true" dans le cas de l'utilisation d'un Mac


