# Skeleton code for NIDS
import socket
import sys
import ipaddress
from scapy.all import *
from datetime import datetime

protocol_dict = {1:'icmp', 6:'tcp', 17: 'udp'}
option_dict = {'tcp': ['seq', 'ack', 'window', 'flags'],
               'ip': ['id', 'tos', 'ttl'],
               'icmp': ['itype', 'icode']}

# You can utilize this class to parse the Snort rule and build a rule set.
class Rule:
    def __init__(self, action, protocol, src_ip, src_port, direction, dst_ip, dst_port, options, msg, original_rule):
        self.action = action
        self.protocol = protocol
        self.src_ip = src_ip
        self.src_port = src_port
        self.direction = direction
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.options = options
        self.msg = msg

        self.original_rule = original_rule

    def __str__(self):
        return (f"action: {self.action}\n"
                 f"protocol: {self.protocol}\n"
                 f"src_ip: {self.src_ip}\n"
                 f"src_port: {self.src_port}\n"
                 f"direction: {self.direction}\n"
                 f"dst_ip: {self.dst_ip}\n"
                 f"dst_port: {self.dst_port}\n"
                 f"options: {self.options}\n"
                 f"original_rule:{self.original_rule}")

def parse_rule(line):
    #TODO: your code here
    line_without_enter=line.replace("\n","")
    line_without_last=line_without_enter[:-2]
    header,body=line_without_last.split("(")
    
    src_infos=str()
    dst_infos=str()
    direction=str()
    if("<>" in header):
        src_infos,dst_infos=header.split("<>")
        direction="<>"
    else:
        src_infos,dst_infos=header.split("->")
        direction="->"

    src_components=src_infos.strip().split(" ")
    dst_components=dst_infos.strip().split(" ")
    components_of_body=body.strip().split(";")
    
    action=src_components[0]
    protocol=src_components[1]
    src_ip=src_components[2]
    src_port=src_components[3]
    dst_ip=dst_components[0]
    dst_port=dst_components[1]
    
    msg=str()
    options=list()
    if protocol in option_dict.keys():
        options=option_dict[protocol].copy()
    custom_rule=list()
    for component in components_of_body:
        component_no_blank=component.strip()
        key, value = component_no_blank.split(":")
        if component_no_blank.startswith("msg"):
            msg=value.replace('"',"")    
        else:
            idx=0
            for option in options:
                if key == option:
                    options[idx]=value
                    break
                idx=idx+1 
            else:
                custom_rule.append(component_no_blank)
    return Rule(action,protocol,src_ip,src_port,direction,dst_ip,dst_port,options,msg,custom_rule)  

def parse_packet(packet, rule_set):
    #TODO: your code here

    ip_packet=packet[IP]
    src_ip=ip_packet.src
    dst_ip=ip_packet.dst
    protocol=packet.proto
    src_port=int()
    dst_port=int()
    itype=int()
    icode=int()
    payload=None
    flag=str()
    if(packet.haslayer(TCP)==True):
        src_port=packet[TCP].sport
        dst_port=packet[TCP].dport
        flag=packet[TCP].flags
    if(packet.haslayer(UDP)==True):
        src_port=packet[UDP].sport
        dst_port=packet[UDP].dport
    if(packet.haslayer(ICMP)==True):
        itype=packet[ICMP].type
        icode=packet[ICMP].code
        
    if(packet.haslayer(Raw)): 
        payload=packet[Raw].load.decode()

    mapped_rule=None

    for rule in rule_set:
        if(rule.src_ip!="any"):
            for ip in ipadress.IPv4Network(rule.src_ip):
                if(str(ip)==str(src_ip)):
                    break
            else:
                continue
        if(rule.dst_ip!="any"):
            for ip in ipaddress.IPv4Network(rule.dst_ip):              
                if(str(ip)==str(dst_ip)):
                    break
            else:
                continue
        if(rule.protocol != protocol_dict[protocol]):
            continue
        elif(rule.protocol == "tcp" or rule.protocol=="udp"):                     
            if(rule.protocol=="tcp" and rule.dst_port=="any" and rule.options[3]!="flags" and rule.options[3] != flag):
                continue

            src_target_list=list()
            src_start=int()
            src_end=int()
           
            if(rule.src_port!="any" and len(rule.src_port.split(","))==1):
                range_of_src_port=rule.src_port.split(":")
                if(len(range_of_src_port)==1):
                    src_start=int(range_of_src_port[0])
                    src_end=src_start
                else:
                    src_start=int(range_of_src_port[0])
                    src_end=int(range_of_src_port[1])
                if(src_port < src_start or src_port > src_end):
                    continue
            elif(rule.src_port!="any" and len(rule.src_port.split(","))>1):
                src_target_list=rule.src_port.split(",")
                idx=0
                for str_target in src_target_list:
                    src_target_list[idx]=int(str_target)
                    idx=idx+1
                if(src_port not in src_target_list):
                    continue 

            dst_target_list=list()
            dst_start=int()
            dst_end=int()
            if(rule.dst_port!="any" and len(rule.dst_port.split(","))==1):
                range_of_dst_port=rule.dst_port.split(":")
                if(len(range_of_dst_port)==1):
                    dst_start=int(range_of_dst_port[0])
                    dst_end=dst_start
                else:
                    dst_start=int(range_of_dst_port[0])
                    dst_end=int(range_of_dst_port[1])
                if(dst_port < dst_start or dst_port > dst_end):
                    continue
            elif(rule.dst_port!="any" and len(rule.dst_port.split(","))>1):
                dst_target_list=rule.dst_port.split(",")
                idx=0
                for str_target in dst_target_list:
                    dst_target_list[idx]=int(str_target)
                    idx=idx+1
                if(dst_port not in dst_target_list):
                    continue
        elif(rule.protocol == "icmp"):
            if(itype!=int(rule.options[0]) and icode!=int(rule.options[1])):
                continue
       
        if(payload is not None):
            if(len(rule.original_rule)==0):
                continue
            for custom_rule in rule.original_rule:
                key,value = custom_rule.strip().split(":")
                key=key.strip()
                value=value.strip().replace('"','')
                if(key=="content" and (value in payload or value == payload)):
                    break;
            else:
                continue
           
        mapped_rule=rule
        break
    if(mapped_rule is not None):
        print(f"{datetime.now().strftime('%Y.%m.%d - %H:%M:%S')} {mapped_rule.msg} {mapped_rule.protocol} {src_ip} {src_port} {mapped_rule.direction} {dst_ip} {dst_port}")
if __name__ == '__main__':
    rule_file = sys.argv[1] 

    f = open(rule_file, 'r')

    rule_set = []
    lines = f.readlines()
    for line in lines:
        rule = parse_rule(line)
        rule_set.append(rule)

    print("Start sniffing")
    sniff(iface='eth0', prn=lambda p: parse_packet(p, rule_set), filter='ip')

    f.close()

