from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.dns import DNSQR
from scapy.layers.tls.all import TLS
from scapy.layers.http import HTTP, Raw
from scapy.layers.l2 import Ether
from scapy.layers.tcp import TCP
from collections import Counter
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle


class PacketAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = rdpcap(pcap_file)

    def load_packets(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = rdpcap(pcap_file)

    def get_packet_count(self):
        return len(self.packets)

    def get_packet_summary(self):
        return self.packets.summary()

    def protocol_distribution(self):
        protocols = []
        for packet in self.packets:
            if packet.haslayer(IP):
                protocols.append(packet[IP].proto)
        counter = Counter(protocols)
        return counter

    def packet_sizes(self):
        sizes = []
        for packet in self.packets:
            sizes.append(len(packet))
        return sizes

    def topTalkers(self):
        talkers = []
        for packet in self.packets:
            if packet.haslayer(IP):
                talkers.append(packet[IP].src)
                talkers.append(packet[IP].dst)
        counter = Counter(talkers)
        return counter.most_common(10)

    def traffic_patterns(self):
        patterns = []
        for packet in self.packets:
            if packet.haslayer(IP):
                patterns.append((packet[IP].src, packet[IP].dst))
        counter = Counter(patterns)
        return counter.most_common(10)

    def dns_requests(self):
        dns = []
        for packet in self.packets:
            if packet.haslayer(DNSQR):
                dns.append(packet[DNSQR].qname)
        return dns

    def http_requests(self):
        http = []
        for packet in self.packets:
            if packet.haslayer(Raw):
                load = packet[Raw].load
                if "GET" in str(load):
                    http.append(load)
        return http

    def http_responses(self):
        http = []
        for packet in self.packets:
            if packet.haslayer(Raw):
                load = packet[Raw].load
                if "HTTP" in str(load):
                    http.append(load)
        return http

    def ssl_handshakes(self):
        handshakes = []
        for packet in self.packets:
            if packet.haslayer(TLS):
                handshakes.append(packet[TLS].msg)
        return handshakes

    def payload(self, protocol):
        payloads = []
        for packet in self.packets:
            if packet.haslayer(protocol):
                payloads.append(packet[protocol].load)
        return payloads

    def traffic_volume_analysis(self, interval):
        traffic = []
        for packet in self.packets:
            traffic.append((packet.time, len(packet)))
        return traffic

    def tcp_connection_analysis(self):
        connections = []
        for packet in self.packets:
            if packet.haslayer(TCP):
                connections.append((packet[TCP].sport, packet[TCP].dport))
        counter = Counter(connections)
        return counter.most_common(10)

    def generate_report(self, report_file):
        doc = SimpleDocTemplate(report_file, pagesize=letter)
        elements = []
        title = Paragraph("Packet Analysis Report", style={'fontSize': 16})
        elements.append(title)
        elements.append(Paragraph("<br/><br/>", style={}))
        packet_count_info = Paragraph(f"Total Packets: {self.get_packet_count()}", style={})
        elements.append(packet_count_info)
        elements.append(Paragraph("<br/><br/>", style={}))
        packet_summary_info = Paragraph(f"Packet Summary: {self.get_packet_summary()}", style={})
        elements.append(packet_summary_info)
        elements.append(Paragraph("<br/><br/>", style={}))
        protocol_distribution_info = Paragraph(f"Protocol Distribution: {self.protocol_distribution()}", style={})
        elements.append(protocol_distribution_info)
        elements.append(Paragraph("<br/><br/>", style={}))
        packet_sizes_info = Paragraph(f"Packet Sizes: {self.packet_sizes()}", style={})
        elements.append(packet_sizes_info)
        elements.append(Paragraph("<br/><br/>", style={}))
        top_talkers_info = Paragraph(f"Top Talkers: {self.topTalkers()}", style={})
        elements.append(top_talkers_info)
        elements.append(Paragraph("<br/><br/>", style={}))
        traffic_patterns_info = Paragraph(f"Traffic Patterns: {self.traffic_patterns()}", style={})
        elements.append(traffic_patterns_info)
        elements.append(Paragraph("<br/><br/>", style={}))
        dns_requests_info = Paragraph(f"DNS Requests: {self.dns_requests()}", style={})
        elements.append(dns_requests_info)
        elements.append(Paragraph("<br/><br/>", style={}))
        http_requests_info = Paragraph(f"HTTP Requests: {self.http_requests()}", style={})
        elements.append(http_requests_info)
        elements.append(Paragraph("<br/><br/>", style={}))
        http_responses_info = Paragraph(f"HTTP Responses: {self.http_responses()}", style={})
        elements.append(http_responses_info)
        elements.append(Paragraph("<br/><br/>", style={}))
        ssl_handshakes_info = Paragraph(f"SSL Handshakes: {self.ssl_handshakes()}", style={})
        elements.append(ssl_handshakes_info)
        elements.append(Paragraph("<br/><br/>", style={}))
        payload_info = Paragraph(f"Payload: {self.payload()}", style={})
        elements.append(payload_info)
        elements.append(Paragraph("<br/><br/>", style={}))
        traffic_volume_analysis_info = Paragraph(f"Traffic Volume Analysis: {self.traffic_volume_analysis()}", style={})
        elements.append(traffic_volume_analysis_info)
        elements.append(Paragraph("<br/><br/>", style={}))
        tcp_connection_analysis_info = Paragraph(f"TCP Connection Analysis: {self.tcp_connection_analysis()}", style={})
        elements.append(tcp_connection_analysis_info)
        elements.append(Paragraph("<br/><br/>", style={}))
        doc.build(elements)
        print("Report generated successfully")
