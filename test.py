# https://www.wireshark.org/download.html
# 需要提前安装好wireshark，基于libpcap抓包

from scapy.all import *
import socket

# 定义回调函数，用于处理捕获到的数据包
def packet_callback(packet):
    # 判断是否为UDP数据包，并且目的端口为4549
    if packet.haslayer(UDP) and packet[UDP].dport == 4549:
        # 打印原始数据
        data = packet[Raw].load

        if len(data) <= 30:  # todo: confirm len
            # not a room msg
            print('[Ignore message]\n')
        else:

            # # 构造新的UDP数据包，并发送到指定IP地址和端口
            # new_packet = IP(dst="172.16.3.87")/UDP(dport=4549)/Raw(load=data)
            # send(new_packet)

            # 构造新的UDP数据包，并通过socket发送到指定IP地址和端口
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(data, ("172.16.3.87", 4549))
            sock.sendto(data, ("172.16.3.18", 4549))

            print('[send ok]\n')

# 使用sniff函数捕获UDP 4549端口数据包，并调用回调函数进行处理
sniff(filter="udp port 4549", prn=packet_callback)