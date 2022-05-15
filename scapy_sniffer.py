from scapy.all import *

def custom_action(packet):
    print("asd")
    print(type(packet))

def start_sniff(count_, interface):
    return sniff(count=count_, iface=interface, prn=custom_action)

a = start_sniff(5, "enp0s3")
print(a)