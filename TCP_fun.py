from socket import timeout
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
    print(mac)
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
# directly tcp link the OS will forced send a reset(RST),there are 2 solutions: first is ARP spoofing
# second is config iptable, so implement a ARP spoofing 
def _3handshakes():
    """ as sender,we need to send(S) ,receive(S/A) and send(A), function include 1(like srp1) will return a  receive pkt"""
    seq_ori=get_sequence_num()
    src_ip = "172.17.42.198"#"172.17.42.35"     # "112.96.133.162"  
    dst_ip=  "183.240.84.9"  # "183.240.84.21"  这个网址也是动态的
    receive_packet=srp1(Ether()/IP(dst=dst_ip,src=src_ip)/TCP(dport=80,flags="S",seq=seq_ori))
    # print(receive_packet)
    # seq_mine = receive_packet.seq+1
    seq_server = receive_packet.seq
    ack_server = receive_packet.ack
    # print(ack_mine)
    srp1(Ether()/IP(dst=dst_ip,src=src_ip)/TCP(dport=80,seq=ack_server,ack=seq_server+1))
    # why add flags="A" will send ............ ? because OS stop? 

    #1.get net interface mac of my PC    2.ARP boardcast
    #srp1 在第二层协议上发送及接收包并返回第一次的应答
    #pkt       构建包的变量
    #timeout=1 超时1秒就丢弃，实际时间看程序处理能力而定
    #verbose=0 不显示详细信息
    #根据ip地址来寻找路径实际上是不存在的，由于历史原因，其实都是依靠mac地址，
    # 但是上层http/tcp/udp又都依靠ip,中间依靠ARP,但ARP并不可靠，是靠广播应答，没有第三方监督(ip地址真假无法检测)
    # ARP 就是假冒应答，建立错误的IP/mac映射，可以接收到别的ip的数据包，或者把自己伪装一个假的ip
def ARPspoofing(fake_ip, mac_address):
    """
    fake mapping with my intreface mac address and fake_ip
    """
    for _ in range(500):#psrc= pkt src  hwsrc=mac src  pdst="172.17.42.35", ,src=mac_address
        srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(psrc=fake_ip,hwsrc=mac_address),verbose=0,timeout=0.02)  
        time.sleep(0.02)# layer2's broadcast need mac_address=ff:ff:ff:ff:ff:ff
    # 可以用自己的包里发送端的ip和mac是错误的来欺骗其他机器或路由器一种错误映射
    # 通过欺骗自己的mac和ip关系使os不发reset


if __name__ == "__main__":
    # _3handshakes() #3c:f0:11:21:aa:bb       mine:00:12:7b:16:67:88
    ARPspoofing("172.17.42.198","00:12:7b:16:67:88")   #172.17.42.35
    _3handshakes()
    #欺骗之后上面的ip要换一下,但是不稳定，还是修改防火墙试下

