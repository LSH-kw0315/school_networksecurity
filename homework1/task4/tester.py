# Tester example. Build your own tester to verify your NIDS!
from scapy.all import *
import random

if __name__ == '__main__':
    r1_1 = (Ether() / IP(dst = "192.168.1.100") / TCP(dport = random.randrange(1, 1024)))
    sendp(r1_1, iface='eth0')
    r1_2 = (Ether()/ IP(dst="192.168.1.100") / TCP(dport=random.randrange(1,1024)))    
    sendp(r1_2,iface='eth0')
    
    r2_1=(Ether()/IP()/TCP(dport=23))
    r2_2=(Ether()/IP()/TCP(dport=25))
    r2_3=(Ether()/IP()/TCP(dport=21))
    sendp(r2_1,iface='eth0')
    sendp(r2_2,iface='eth0')
    sendp(r2_2,iface='eth0')

    r3_1=(Ether()/IP()/UDP(dport=random.randrange(10000,20000)))
    r3_2=(Ether()/IP()/UDP(dport=random.randrange(10000,20000)))
    sendp(r3_1,iface='eth0')
    sendp(r3_2,iface='eth0')


    r4_1=(Ether()/IP()/TCP(flags="S"))
    sendp(r4_1,iface='eth0')

  
    r5_1=(Ether()/IP()/TCP(dport=80)/"GET")
    sendp(r5_1,iface="eth0")
 
    
    r6_1=(Ether()/IP()/TCP(dport=22)/"/bin/sh")
    sendp(r6_1,iface="eth0")
    
    r7_1=(Ether()/IP(dst="8.8.8.8")/UDP(dport=53))
    sendp(r7_1,iface="eth0")

    r8_1=(Ether()/IP(dst="223.194.1.180")/ICMP())
    sendp(r8_1,iface="eth0")
    
    
    r9_1=(Ether()/IP()/ICMP())
    sendp(r9_1,iface="eth0")

    

