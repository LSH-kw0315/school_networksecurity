import socket
import ipaddress
import struct
import sys
import time
import threading

def change_splitted_ip_array_to_decimal(arr_ip):
  return int(arr_ip[3])+(int(arr_ip[2])<<8)+(int(arr_ip[1])<<16)+(int(arr_ip[0])<<24)

def change_decimal_to_ip(deciaml_ip):
  return str((deciaml_ip & 0xff000000)>>24)+"."+str(((deciaml_ip)&0x00ff0000)>>16)+"."+str((deciaml_ip & 0x0000ff00)>>8)+"."+str(deciaml_ip& 0x000000ff)

# used for parsing an IP header
class IP:
    def __init__(self, buf=None):
        header = struct.unpack('<BBHHHBBH4s4s', buf)
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF

        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]

        # human readable IP addresses
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        # map protocol constants to their names
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:
            print('%s No protocol for %s' % (e, self.protocol_num))
            self.protocol = str(self.protocol_num)

# used for parsing an ICMP header
class ICMP:
    def __init__(self, buff):
        header = struct.unpack('<BBHHH', buff)
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]

# sniffer: used to capture all ICMP packets come to this host.
def sniffer():
    print("init of sniffer")
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.bind(("0.0.0.0", 0))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    discovered_hosts = set([])
    print("I'm in the sniffer")
    try:
        while True:
            raw_buffer = s.recvfrom(1500)[0]
            #TODO: your code here
            ip=IP(raw_buffer[:20])
            #print(f"ver:{ip.ver}, ihl:{ip.ihl}, tos:{ip.tos}, len:{ip.len}, id:{ip.id}, offset:{ip.offset}, ttl:{ip.ttl}, protocol:{ip.protocol}, sum:{ip.sum}, src:{ip.src_address}, dst:{ip.dst_address}")
            if ip.protocol=="ICMP":
                icmp=ICMP(raw_buffer[20:28])
                #print(f"type:{icmp.type}, code:{icmp.code}, sum:{icmp.sum}, id:{icmp.id}, seq:{icmp.seq}")
                if icmp.type==3 and icmp.code ==3:
                    discovered_hosts.add(ip.src_address)
    except KeyboardInterrupt:
        print(f'\n\nSummary: Discovered Hosts')
        for host in sorted(discovered_hosts):
            print(f'{host}')
        sys.exit()

# udp_sender: used to send UDP packets to all the hosts of a given subnet.
def udp_sender(subnet):
    STRING="SCAN"
    PORT=19999
    #TODO: your code here
    splitted_subnet=subnet.split('/')
    splitted_ip=splitted_subnet[0].split('.')
    mask=0xffffffff<<(32-int(splitted_subnet[1]))
    decimal_ip=change_splitted_ip_array_to_decimal(splitted_ip)
    decimal_subnet=decimal_ip&mask
    str_subnet=change_decimal_to_ip(decimal_ip)
    amount_of_host=0xffffffff>>int(splitted_subnet[1])
    list_of_host=list()
    for i in range(1,amount_of_host):
        host_ip=decimal_subnet+i
        str_ip=change_decimal_to_ip(host_ip)
        list_of_host.append(str_ip)    
    
    s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    idx=0
    #for dst_ip in ipaddress.IPv4Network(subnet):
    for dst_ip in list_of_host:
        #print(f"ipaddr dst_ip:{dst_ip}")
        #print(f"list dst_ip:{list_of_host[idx]}")
        #idx=idx+1
        try:
            s.sendto(STRING.encode(),(str(dst_ip),PORT))
        except PermissionError:
            pass
if __name__ == '__main__':
    subnet = sys.argv[1]
    time.sleep(3)

    # execute a udp sender thread
    t = threading.Thread(target=udp_sender, args=(subnet,))
    t.start()

    # start sniffing
    sniffer()
