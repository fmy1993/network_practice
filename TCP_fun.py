from sys import flags
from typing import Sequence
import uuid
import socket
import random
from scapy.all import *

""" 
address16 = hex(uuid.getnode())#[2:]
mac='-'.join(address16[i:i+2] for i in range(0, len(address16), 2)) # s = [i for i in range(10)],slice中若定义的是变量可以配合range来使用
# mac='-'.join(for i in range(0, len(address16), 2) address16[i:i+2] )
address2 = uuid.getnode()# return binary mac address
print(address16)
print(address2)
print(mac)
 """
""" 
class test:
    def __init__(self,property_a_val):
        self.property_a=property_a_val
    def get_mac():
        address16 = hex(uuid.getnode())#[2:]
        mac='-'.join(address16[i:i+2] for i in range(0, len(address16), 2)) 
        # s = [i for i in range(10)],slice中若定义的是变量可以配合range来使用
         return mac
   """     
     


def get_mac():
    """ mac will be used in layer1 """
    address16 = hex(uuid.getnode())#[2:]
    mac='-'.join(address16[i:i+2] for i in range(0, len(address16), 2)) 
    # s = [i for i in range(10)],slice中若定义的是变量可以配合range来使用
    return mac
def get_IP():
    """
    ip and port for soecket in layer3
    """
    return get_if_addr(conf.iface)
    # host_name=socket.gethostname()
    # ip2 = socket.gethostbyname(host_name)
    # print(host_name)
    # print(ip1)
    # print(ip2)
def get_sequence_num():
    """ generate sequence number for tcp handshake """
    return random.randint(0,10000)

def _3handshakes():
    """ as sender,we need to send(S) ,receive(S/A) and send(A), function include 1(like srp1) will return a  receive pkt"""
    seq_ori=get_sequence_num()
    src_ip = "192.168.43.168"     # "112.96.133.162"  
    dst_ip="112.90.70.68"
    receive_packet=srp1(Ether()/IP(dst=dst_ip,src=src_ip)/TCP(dport=80,flags="S",seq=seq_ori))
    # print(receive_packet)
    # seq_mine = receive_packet.seq+1
    ack_mine = receive_packet.seq
    # print(ack_mine)
    srp1(Ether()/IP(dst=dst_ip,src=src_ip)/TCP(dport=80,seq=seq_ori+1,ack=ack_mine+1))
    # why add flags="A" will send ............ ? because we 


    """  
    s=socket.socket()
    s.connect(("www.163.com",80))
    ss=StreamSocket(s,Raw)
    ss.sr1(Raw("GET /\r\n"))
    """
  
 
if __name__ == "__main__":
    _3handshakes() 
  


