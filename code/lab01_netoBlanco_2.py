#! /usr/bin/env python2.7
# -*- coding: utf-8 -*-

######################################################################################################################
# Fichier: lab01_netoBlanco_2.py
# Description:  Script de découverte de dispositifs résau, capable d'afficher leurs infos (SSID recherché, Fabricant,
# MAC), en fonction du probe request émis.
# Auteurs: Guillaume Blanco, Patrick Neto
# Date: 18.03.2019
######################################################################################################################
import scapy.all as scapy
import requests

# Nom de l'interface réseau utilisée pour monitorer
INTERFACE_WIFI = "wlan0mon"

#  Adresse de l'API qui traduit les MAC address en nom du fabricant du dispositif
API_MAC_URL = "https://api.macvendors.com/"

# Tableaux qui stockent respectivement les noms de fabricants des différentes MAC adresses, ainsi que les SSID recherchés
#dans le probe
macAddresses = {}
macSsids = {}

##############################################################################
## Retourne le fabriquant d'un dispositif, à l'aide de sa MAC adresse
## In: mac - MAC adresse du dispositif
##############################################################################
def macToVendor(mac):
    curUrl = API_MAC_URL + mac.upper().replace(":","-") # Formattage de l'URL pour la requête sur l'API
    req = requests.get(url=curUrl)

    vendor = "Fabricant inconnu"

    # Vérifier si un nom de fabriquant a été retourné (si la page existe)
    if(req.status_code != 404):
        vendor = req.text

    return vendor

##############################################################################
## Recupère et affiche les informations du paquet récupéré (MAC adresse, probe,
## SSID)
## In: packet - paquet qui a été récupéré
##############################################################################
def detectProbeRequest(packet):
        # Vérifie si le paquet contient les informations nécessaire à lister les dispositifs et leurs probe request ssid
        if (packet.haslayer(scapy.Dot11) and hasattr(packet, 'type') and packet.type == 0 and packet.subtype == 4 \
            and hasattr(packet, 'info') and packet.info):
            # Vérifie si l'adresse MAC du dispositif n'est pas encore enregistrée
            if(packet.addr2 not in macAddresses):
                macAddresses[packet.addr2] = macToVendor(packet.addr2)

            # Vérifier que la liste de SSID recherchés par une MAC adresse n'est pas encore initialisée
            if(packet.addr2 not in macSsids):
                macSsids[packet.addr2] = []

            # Vérifier le SSID contenu dans le paquet n'est pas
            if (packet.info not in macSsids[packet.addr2]):
                macSsids[packet.addr2].append(packet.info)
            printCliensInfos()# Affiche les informations

##############################################################################
## Affiche les informations précédemment récupérées par le sniffer de probe
## request
## SSID)
## In: packet - paquet qui a été récupéré
##############################################################################
def printCliensInfos():
    print(chr(27) + "[2J") # Permet de raffraîchir l'affichage en console
    for mac in macAddresses:
        print(mac + " (" + macAddresses[mac] + ") - " + "".join([str(" [" + x + "]").decode("utf-8") for x in \
              macSsids[mac]]))

# Sniffing de paquets 802.11 et passage en paramètre d'une fonction de traitement de paquets
scapy.sniff(iface=INTERFACE_WIFI,  prn=detectProbeRequest) # Ajouter l'argument "monitor=true" dans le cas de
# l'utilisation d'un Mac