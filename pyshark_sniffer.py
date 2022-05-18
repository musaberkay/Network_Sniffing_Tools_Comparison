import pyshark


def start_sniff(count_, interface_, save_pcap=False):
    capture = pyshark.LiveCapture(interface=interface_, only_summaries=True)

    processed_data = []

    for packet in capture.sniff_continuously(packet_count=count_):
        data_info = {"Source IP": packet.ip.src,
                    "Details": packet}

        print(str(packet))

start_sniff(5,"enp0s3")