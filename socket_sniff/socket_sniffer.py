import socket
import sys
import os

import time

sys.path.append(os.getcwd())

from general import *
from networking.ethernet import Ethernet
from networking.ipv4 import IPv4
from networking.icmp import ICMP
from networking.tcp import TCP
from networking.udp import UDP
from networking.pcap import Pcap
from networking.http import HTTP

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '


def start_sniff(count_, save_pcap, result_, index_):
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    if save_pcap:
        pcap = Pcap('socket_capture.pcap')

    capture_count = 0
    processed_data = []

    while capture_count < count_:
        start_time = time.time()
        raw_data, addr = conn.recvfrom(65535)
        finish_time = time.time()
        data_info = {"Time(ms)": str(round((finish_time-start_time)*1000, 2))}

        if save_pcap:
            pcap.write(raw_data)

        eth = Ethernet(raw_data)

        data_explanation = ""

        data_explanation += '\nEthernet Frame:'
        data_explanation += TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(eth.dest_mac, eth.src_mac, eth.proto) +"\n"


        # IPv4
        if eth.proto == 8:
            ipv4 = IPv4(eth.data)
            
            data_explanation += TAB_1 + 'IPv4 Packet:' +"\n"
            data_explanation += TAB_2 + 'Version: {}, Header Length: {}, TTL: {},'.format(ipv4.version, ipv4.header_length, ipv4.ttl)+"\n"
            data_explanation += TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4.proto, ipv4.src, ipv4.target)+"\n"

            data_info["Source IP"] = ipv4.src
            data_info["Destination IP"] = ipv4.target
            data_info["Packet Length"] = str(len(raw_data))

            # ICMP
            if ipv4.proto == 1:
                icmp = ICMP(ipv4.data)

                data_explanation+=TAB_1 + 'ICMP Packet:'+"\n"
                data_explanation+=TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp.type, icmp.code, icmp.checksum)+"\n"
                data_explanation+=TAB_2 + 'ICMP Data:'+"\n"
                data_explanation+=format_multi_line(DATA_TAB_3, icmp.data)+"\n"

                data_info["Protocol"] = "ICMP"

            # TCP
            elif ipv4.proto == 6:
                tcp = TCP(ipv4.data)
                
                data_explanation+=TAB_1 + 'TCP Segment:'+"\n"
                data_explanation+=TAB_2 + 'Source Port: {}, Destination Port: {}'.format(tcp.src_port, tcp.dest_port)+"\n"
                data_explanation+=TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(tcp.sequence, tcp.acknowledgment)+"\n"
                data_explanation+=TAB_2 + 'Flags:'+"\n"
                data_explanation+=TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh)+"\n"
                data_explanation+=TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin)+"\n"

                data_info["Protocol"] = "TCP"

                if len(tcp.data) > 0:

                    # HTTP
                    if tcp.src_port == 80 or tcp.dest_port == 80:
                        data_explanation+=TAB_2 + 'HTTP Data:'+"\n"
                        try:
                            http = HTTP(tcp.data)
                            http_info = str(http.data).split('\n')
                            for line in http_info:
                                data_explanation+=DATA_TAB_3 + str(line)+"\n"
                        except:
                            data_explanation+=format_multi_line(DATA_TAB_3, tcp.data)+"\n"

                        data_info["Protocol"] = "HTTP"
                    else:
                        data_explanation+=TAB_2 + 'TCP Data:'+"\n"
                        data_explanation+=format_multi_line(DATA_TAB_3, tcp.data)+"\n"

            # UDP
            elif ipv4.proto == 17:
                udp = UDP(ipv4.data)

                data_explanation+=TAB_1 + 'UDP Segment:'+"\n"
                data_explanation+=TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp.src_port, udp.dest_port, udp.size)+"\n"

                data_info["Protocol"] = "UDP"

            # Other IPv4
            else:
                data_explanation+=TAB_1 + 'Other IPv4 Data:'+"\n"
                data_explanation+=format_multi_line(DATA_TAB_2, ipv4.data)+"\n"

                data_info["Protocol"] = "Other IPv4"

        else:
            continue

        if eth.dest_mac == "00:00:00:00:00:00" and eth.src_mac == "00:00:00:00:00:00":
            data_info["Protocol"] = "DNS"

        capture_count += 1
        data_info["Details"] = data_explanation
        processed_data.append(data_info)

    if save_pcap:
        pcap.close()

    result_[index_] = processed_data
    return processed_data