from scapy.all import *

import sys

def debug(s):
    print('#{0}'.format(s))
    sys.stdout.flush()

if __name__ == "__main__":
    #conf.iface = sys.argv[1]
    ip_addr = sys.argv[2]

    my_ip = get_if_addr(sys.argv[1])

    # SYN scan
    ports = range(1,1025)
    for p in ports:
        syn_ack = sr1(IP(dst=ip_addr)/TCP(dport=p,flags="S"),verbose=0)
        if syn_ack is not None and str(type(syn_ack)) != "<type 'NoneType'>":
            if syn_ack.getlayer(TCP).flags == 0x12:
                tcp_rst = sr1(IP(dst=my_ip)/TCP(dport=p,flags="R"),timeout=1,verbose=0)
                print(ip_addr + "," + str(p))


