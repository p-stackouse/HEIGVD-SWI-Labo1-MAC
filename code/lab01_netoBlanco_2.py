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

macAddresses = {}
macSsids = {}

def macToVendor(mac):
    curUrl = API_MAC_URL + mac.upper().replace(":","-") #Formattage de l'adresse de l'API pour requête
    req = requests.get(url=curUrl)

    vendor = "Fabricant inconnu"

    # Vérifier si un nom de fabriquant a été retourné (si la page existe)
    if(req.status_code != 404):
        vendor = req.text

    return vendor

##############################################################################
## Recupère les informations du paquet récupéré
## In: packet - paquet qui a été récupéré
##############################################################################
def detectProbeRequest(packet):
        # Vérifie si le paquet contient les informations nécessaire à lister les dispositifs et leurs probe request ssid
        if (hasattr(packet, 'type') and packet.type == 0 and packet.subtype == 4 and hasattr(packet, 'info') and packet.info):
            # Vérifie si l'adresse MAC du dispositif n'est pas encore enregistrée
            if(packet.addr2 not in macAddresses):
                macAddresses[packet.addr2] = macToVendor(packet.addr2)

            if(packet.addr2 not in macSsids):
                macSsids[packet.addr2] = []
            if (packet.info not in macSsids[packet.addr2]):
                macSsids[packet.addr2].append(packet.info)
            printCliensInfos()


def printCliensInfos():
    print(chr(27) + "[2J")
    for mac in macAddresses:
        print(mac + " (" + macAddresses[mac] + ") - " + "".join([str(" [" + x + "]").encode("utf-8") for x in macSsids[mac]]))

def printNetworks(mac):
    for ssid in macSsids[mac]:
        print(str(ssid).decode("utf-8") + ", ")


# On sniff le reseau avec l interface wlan0mon et on applique la fonction detectMac pour chaque paquet
pckt = scapy.sniff(iface=INTERFACE_WIFI, monitor="true", prn=detectProbeRequest) # Ajouter l'argument "monitor=true" dans le cas de l'utilisation d'un Mac


