from scapy.all import *


def start_sniff(count_, save_pcap, interface, result_, index_):

    processed_data = []
    start_time = time.time()
    packets = sniff(iface=interface, count=count_)
    count=0
    total_time = 0
    total_log_info = 0
    protocol_types = {}

    for packet in packets:
        if count==0:
            total_time += (packet.time-start_time)*1000
            data_info = {"Time(ms)": str(round((packet.time-start_time)*1000, 2))}
        else:
            total_time += (packets[count].time-packets[count-1].time)*1000
            data_info = {"Time(ms)": str(round((packets[count].time-packets[count-1].time)*1000, 2))}
        
        data_info["Source IP"] = packet[IP].src
        data_info["Destination IP"] = packet[IP].dst
        data_info["Packet Length"] = str(len(packet))
        try:
            data_info["Protocol"] = packet.getlayer(3).name
            if data_info["Protocol"] in ["Raw","Padding"]:
                data_info["Protocol"] = packet.getlayer(2).name
        except:
            data_info["Protocol"] = packet.getlayer(2).name
        data_info["Details"] = packet.show(dump=True)

        total_log_info += len(data_info["Details"].encode('utf-8'))

        if data_info["Protocol"] not in list(protocol_types.keys()):
            protocol_types[data_info["Protocol"]] = 0
        protocol_types[data_info["Protocol"]] += 1

        processed_data.append(data_info)
        count += 1

    if save_pcap:
        wrpcap("scapy_capture.pcap", packets)
    
    result_[index_] = (processed_data, round(total_time, 2), total_log_info, protocol_types)
    return processed_data