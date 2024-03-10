import os

os.environ['WIRESHARK_MANUF'] = r'C:\Program Files\Wireshark\manuf.txt'  # Use a raw string for the pathfrom scapy.all import *
from scapy.all import *
from collections import Counter


class PacketAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = rdpcap(pcap_file)

    def analyse_traffic_pattern(self,interval):
        packet_count = len(self.packets)
        time_interval = interval
        time = []
        for i in range(0, packet_count):
            time.append(self.packets[i].time)
        time.sort()
        time_interval_count = []
        for i in range(0, packet_count):
            time_interval_count.append(int(time[i] / time_interval))
        time_interval_count = Counter(time_interval_count)
        return time_interval_count

    def detect_dos_attack(self, threshold):
        packet_count = len(self.packets)
        time = []
        for i in range(0, packet_count):
            time.append(self.packets[i].time)
        time.sort()
        time_interval = time[packet_count - 1] - time[0]
        time_interval_count = self.analyse_traffic_pattern(time_interval)
        for key in time_interval_count:
            if time_interval_count[key] > threshold:
                return True
        return False

    def detect_port_scan(self, threshold):
        packet_count = len(self.packets)
        src_port = []
        for i in range(0, packet_count):
            src_port.append(self.packets[i].sport)
        src_port = Counter(src_port)
        for key in src_port:
            if src_port[key] > threshold:
                return True
        return False

    def detect_ip_scan(self, threshold):
        packet_count = len(self.packets)
        src_ip = []
        for i in range(0, packet_count):
            src_ip.append(self.packets[i].src)
        src_ip = Counter(src_ip)
        for key in src_ip:
            if src_ip[key] > threshold:
                return True
        return False

    def detect_malware(self, threshold):
        packet_count = len(self.packets)
        src_ip = []
        dst_ip = []
        for i in range(0, packet_count):
            src_ip.append(self.packets[i].src)
            dst_ip.append(self.packets[i].dst)
        src_ip = Counter(src_ip)
        dst_ip = Counter(dst_ip)
        for key in src_ip:
            if src_ip[key] > threshold:
                return True
        for key in dst_ip:
            if dst_ip[key] > threshold:
                return True
        return False

    def get_top_src_ip(self, count):
        packet_count = len(self.packets)
        src_ip = []
        for i in range(0, packet_count):
            src_ip.append(self.packets[i].src)
        src_ip = Counter(src_ip)
        return src_ip.most_common(count)

    def get_top_dst_ip(self, count):
        packet_count = len(self.packets)
        dst_ip = []
        for i in range(0, packet_count):
            dst_ip.append(self.packets[i].dst)
        dst_ip = Counter(dst_ip)
        return dst_ip.most_common(count)

    def get_top_src_port(self, count):
        packet_count = len(self.packets)
        src_port = []
        for i in range(0, packet_count):
            src_port.append(self.packets[i].sport)
        src_port = Counter(src_port)
        return src_port.most_common(count)

    def get_top_dst_port(self, count):
        packet_count = len(self.packets)
        dst_port = []
        for i in range(0, packet_count):
            dst_port.append(self.packets[i].dport)
        dst_port = Counter(dst_port)
        return dst_port.most_common(count)

    def get_packet_count(self):
        return len(self.packets)

    def get_packet(self, index):
        return self.packets[index]

    def get_packet_summary(self, index):
        return self.packets[index].summary()

    def get_packet_time(self, index):
        return self.packets[index].time

    def get_packet_layers(self, index):
        return self.packets[index].layers()

    def get_packet_fields(self, index):
        return self.packets[index].fields

    def get_packet_payload(self, index):
        return self.packets[index].payload

    def get_packet_src(self, index):
        return self.packets[index].src

    def get_packet_dst(self, index):
        return self.packets[index].dst

    def get_packet_sport(self, index):
        return self.packets[index].sport

    def get_packet_dport(self, index):
        return self.packets[index].dport

    def get_packet_protocol(self, index):
        return self.packets[index].proto

    def get_packet_length(self, index):
        return len(self.packets[index])

    def get_packet_hexdump(self, index):
        return self.packets[index].hexdump()

    def get_packet_show(self, index):
        return self.packets[index].show()

    def get_packet_raw(self, index):
        return self.packets[index].raw

    def get_packet_raw_hex(self, index):
        return self.packets[index].raw.hex()

    def get_packet_raw_bytes(self, index):
        return self.packets[index].raw.tobytes()

    def get_packet_raw_load(self, index):
        return self.packets[index].load

    def get_packet_raw_load_hex(self, index):
        return self.packets[index].load.hex()

    def get_packet_raw_load_bytes(self, index):
        return self.packets[index].load.tobytes()

    def get_packet_raw_load_str(self, index):
        return self.packets[index].load.decode('utf-8')

    def get_packet_raw_load_str_hex(self, index):
        return self.packets[index].load.decode('utf-8').encode().hex()

    def get_packet_raw_load_str_bytes(self, index):
        return self.packets[index].load.decode('utf-8').encode().bytes()

    def filter_packets(self, filter):
        return self.packets.filter(filter)

    def get_packet_payload_hex(self, index):
        return self.packets[index].payload.hex()

    def get_packet_payload_bytes(self, index):
        return self.packets[index].payload.tobytes()

    def get_packet_payload_str(self, index):
        return self.packets[index].payload.decode('utf-8')

    def get_packet_payload_str_hex(self, index):
        return self.packets[index].payload.decode('utf-8').encode().hex()

    def get_packet_payload_str_bytes(self, index):
        return self.packets[index].payload.decode('utf-8').encode().bytes()

    def generate_report(self, report_file):
        report = open(report_file, "w")
        report.write("Packet count: " + str(self.get_packet_count()) + "\n")
        report.write("Top source IP: " + str(self.get_top_src_ip(5)) + "\n")
        report.write("Top destination IP: " + str(self.get_top_dst_ip(5)) + "\n")
        report.write("Top source port: " + str(self.get_top_src_port(5)) + "\n")
        report.write("Top destination port: " + str(self.get_top_dst_port(5)) + "\n")
        report.write("Packet summary: " + self.get_packet_summary(0) + "\n")
        report.write("Packet time: " + str(self.get_packet_time(0)) + "\n")
        report.write("Packet layers: " + str(self.get_packet_layers(0)) + "\n")
        report.write("Packet fields: " + str(self.get_packet_fields(0)) + "\n")
        report.write("Packet payload: " + str(self.get_packet_payload(0)) + "\n")
        report.write("Packet source: " + self.get_packet_src(0) + "\n")
        report.write("Packet destination: " + self.get_packet_dst(0) + "\n")
        report.write("Packet source port: " + str(self.get_packet_sport(0)) + "\n")
        report.write("Packet destination port: " + str(self.get_packet_dport(0)) + "\n")
        report.write("Packet protocol: " + str(self.get_packet_protocol(0)) + "\n")
        report.write("Packet length: " + str(self.get_packet_length(0)) + "\n")
        report.write("Packet hexdump: " + str(self.get_packet_hexdump(0)) + "\n")
        report.write("Packet show: " + str(self.get_packet_show(0)) + "\n")
        report.write("Packet raw: " + str(self.get_packet_raw(0)) + "\n")
        report.write("Packet raw hex: " + str(self.get_packet_raw_hex(0)) + "\n")
        report.write("Packet raw bytes: " + str(self.get_packet_raw_bytes(0)) + "\n")
        report.write("Packet raw load: " + str(self.get_packet_raw_load(0)) + "\n")
        report.write("Packet raw load hex: " + str(self.get_packet_raw_load_hex(0)) + "\n")
        report.write("Packet raw load bytes: " + str(self.get_packet_raw_load_bytes(0)) + "\n")
        report.write("Packet raw load str: " + str(self.get_packet_raw_load_str(0)) + "\n")
        report.write("Packet raw load str hex: " + str(self.get_packet_raw_load_str_hex(0)) + "\n")
        report.write("Packet raw load str bytes: " + str(self.get_packet_raw_load_str_bytes(0)) + "\n")
        report.write("Packet payload hex: " + str(self.get_packet_payload_hex(0)) + "\n")
        report.write("Packet payload bytes: " + str(self.get_packet_payload_bytes(0)) + "\n")
        report.write("Packet payload str: " + str(self.get_packet_payload_str(0)) + "\n")
        report.write("Packet payload str hex: " + str(self.get_packet_payload_str_hex(0)) + "\n")
        report.write("Packet payload str bytes: " + str(self.get_packet_payload_str_bytes(0)) + "\n")
        report.close()
