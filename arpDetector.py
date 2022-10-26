# -*- coding: utf-8 -*-
from scapy.all import sniff

def processPacket(packet):
    src_IP = packet['ARP'].psrc
    src_MAC = packet['Ether'].src
    if src_IP in IP_MAC_MAP.values():
        if src_MAC not in IP_MAC_MAP.keys():
            message = ("Possible ARP attack detected!\n"
            + "It's possible that the machine with MAC address: " + str(src_MAC)
            + " is pretending to be " + str(src_IP))
    else:
        IP_MAC_MAP[src_MAC] = src_IP


if __name__ == "__main__":
    IP_MAC_MAP = {}
    sniff(count=0, filter='arp', store=0, prn=processPacket)