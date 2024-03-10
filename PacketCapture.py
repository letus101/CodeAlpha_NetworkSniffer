import os

os.environ['WIRESHARK_MANUF'] = r'C:\Program Files\Wireshark\manuf.txt'  # Use a raw string for the pathfrom scapy.all import *
from scapy.all import *

class PacketCapture:
    def __init__(self, interface,pcap_file):
        self.interface = interface
        self.pcap_file = pcap_file

    def capturePackets(self, count):
        try:
            packets = sniff(iface=self.interface, count=count)
            wrpcap(self.pcap_file, packets)
            print("Packets captured successfully")
        except Exception as e:
            print("Error: ", e)
