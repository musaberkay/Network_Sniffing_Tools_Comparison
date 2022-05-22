import pyshark
import time


def start_sniff(count_, save_pcap, interface_, result_, index_):
    capture = pyshark.LiveCapture(interface=interface_, output_file="./pyshark_capture.pcap")

    processed_data = []
    start_time = time.time()

    captured_packets = capture.sniff_continuously(packet_count=count_)

    for packet in captured_packets:
        data_info = {"Source IP": packet.ip.src,
                    "Destination IP": packet.ip.dst,
                    "Time(ms)": packet.sniff_timestamp,
                    "Packet Length": packet.length,
                    "Protocol": packet.highest_layer,
                    "Details": str(packet)}

        if data_info["Protocol"] == "DATA":
            data_info["Protocol"] = packet.layers[-2].layer_name.upper()

        processed_data.append(data_info)

    for i in range(len(processed_data)-1, -1, -1):
        if i == 0:
            processed_data[i]["Time(ms)"] = str(round((float(processed_data[i]["Time(ms)"]) - float(start_time))*1000, 2))
            continue
        processed_data[i]["Time(ms)"] = str(round((float(processed_data[i]["Time(ms)"]) - float(processed_data[i-1]["Time(ms)"]))*1000, 2))

    total_time = 0
    for packet in processed_data:
        total_time += float(packet["Time(ms)"])

    result_[index_] = (processed_data, round(total_time, 2))
    return processed_data

#a = start_sniff(5,False,"enp0s3", [None]*3,2)
#print(a)