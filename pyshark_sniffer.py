import pyshark

capture = pyshark.LiveCapture(interface='enp0s3')
for packet in capture.sniff_continuously(packet_count=5):
    print("Just arrived:", packet)