from scapy.all import *


class PacketCapture:
    def __init__(self, interface, pcap_file, filters=None):
        self.interface = interface
        self.pcap_file = pcap_file
        self.filters = filters

    def capturePackets(self, count=0):
        try:
            packets = sniff(iface=self.interface, count=count, filter=self.filters)
            wrpcap(self.pcap_file, packets)
            print("Packets captured successfully")
        except Exception as e:
            print("Error:", e)
