#! /usr/bin/env python2.7
# -*- coding: utf-8 -*-
######################################################################################################################
# Fichier: lab01_netoBlanco_2.py
# Description:  Script de découverte de réseau, capable d'afficher les réseaux 802.11 environnant (SSID, Fabricant, MAC)
# Auteurs: Guillaume Blanco, Patrick Neto
# Date: 18.03.2019
######################################################################################################################
import scapy.all as scapy
import requests

#Nom de l'interface réseau utilisée pour monitorer
INTERFACE_WIFI = "en0"

#Adresse de l'API qui résout les mac address en nom de fabricant
API_MAC_URL = "https://api.macvendors.com/"

# Récupération de l'adresse MAC passée en paramètre
networksAddress = []

def macToVendor(mac):
    curUrl = API_MAC_URL + mac.upper().replace(":","-") #Formattage de l'adresse de l'API pour requête
    req = requests.get(url=curUrl)

    vendor = "Fabricant inconnu"

    # Vérifier si un nom de fabriquant a été retourné (si la page existe)
    if(req.status_code == 200):
        vendor = req.text

    return vendor

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
            print(packet.addr2 + " (" + macToVendor(packet.addr2) + ") - " + packet.info)



# On sniff le reseau avec l interface wlan0mon et on applique la fonction detectMac pour chaque paquet
pckt = scapy.sniff(iface=INTERFACE_WIFI, monitor="true", prn=detectNetork) # Ajouter l'argument "monitor=true" dans le cas de l'utilisation d'un Mac


