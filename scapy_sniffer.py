from scapy.all import *


def start_sniff(count_, save_pcap, interface, result_, index_):

    processed_data = []
    start_time = time.time()
    packets = sniff(iface=interface, count=count_)
    count=0

    for packet in packets:
        if count==0:
            data_info = {"Time(ms)": str(round((packet.time-start_time)*1000, 2))}
        else:
            data_info = {"Time(ms)": str(round((packets[count].time-packets[count-1].time)*1000, 2))}
        data_info["Source IP"] = packet[IP].src
        data_info["Destination IP"] = packet[IP].dst
        data_info["Packet Length"] = str(len(packet))
        data_info["Protocol"] = packet.getlayer(2).name
        data_info["Details"] = packet.show(dump=True)
        processed_data.append(data_info)
        count += 1

    if save_pcap:
        wrpcap("scapy_capture.pcap", packets)
    
    result_[index_] = processed_data
    return processed_data