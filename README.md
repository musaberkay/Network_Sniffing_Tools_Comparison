# Network_Sniffign_Tools_Comparison

## Requirements
- Use a Linux distribution (Windows causes permission issues)
- Download thshark (Required to use the Pyshark module)
  - sudo apt update
  - sudo apt install tshark
- Run the program with "sudo" (e.g. sudo python3 sniffer_comparison.py)

## Program Workflow
- Type the network interface name to the related text input (default is "enp0s3" which works fine with Ubuntu)
- Enter the number of packet that needs to be sniffed
- If .pcap file is needed, check the box
- Click the "Sniff!" button
- Wait for the sniffing to end. The GUI will be uninteractible until the sniffing process ends. If you are using the program for testing, open a random webpage on your browser to provide program with network packets
