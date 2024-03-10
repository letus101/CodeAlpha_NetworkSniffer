from scapy.all import *
from collections import Counter


class PacketAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = rdpcap(pcap_file)

    def load_packets(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = rdpcap(pcap_file)
