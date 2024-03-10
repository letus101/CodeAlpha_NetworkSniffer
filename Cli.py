import cmd
import os

os.environ['WIRESHARK_MANUF'] = r'C:\Program Files\Wireshark\manuf.txt'  # Use a raw string for the path
from PacketCapture import PacketCapture
from PacketAnalyzer import PacketAnalyzer


class Cli(cmd.Cmd):
    intro = "Welcome to the Packet Analyzer CLI. Type help or ? to list commands.\n"
    prompt = "NetworkSniffer> "

    def __init__(self):
        super().__init__()
        self.packet_capture = None
        self.packet_analyzer = None

    def do_capture(self, line):
        """
                Capture packets from the network.

                Usage: capture <interface> <pcap_file> <count>
                Example: capture eth0 capture.pcap 1000
                """
        try:
            interface, pcap_file, count = line.split()
            self.packet_capture = PacketCapture(interface, pcap_file)
            self.packet_capture.capturePackets(int(count))
        except Exception as e:
            print("Error: ", e)
            print("Usage: capture <interface> <pcap_file> <count>")

    def do_analyse_traffic_pattern(self, line):
        """
                Analyse traffic pattern from the pcap file.

                Usage: analyse_traffic_pattern <pcap_file> <interval>
                Example: analyse_traffic_pattern capture.pcap 10
                """
        try:
            pcap_file, interval = line.split()
            self.packet_analyzer = PacketAnalyzer(pcap_file)
            print(self.packet_analyzer.analyse_traffic_pattern(int(interval)))
        except Exception as e:
            print("Error: ", e)
            print("Usage: analyse_traffic_pattern <pcap_file> <interval>")

    def do_detect_dos_attack(self, line):
        """
                Detect DOS attack from the pcap file.

                Usage: detect_dos_attack <pcap_file> <threshold>
                Example: detect_dos_attack capture.pcap 100
                """
        try:
            pcap_file, threshold = line.split()
            self.packet_analyzer = PacketAnalyzer(pcap_file)
            print(self.packet_analyzer.detect_dos_attack(int(threshold)))
        except Exception as e:
            print("Error: ", e)
            print("Usage: detect_dos_attack <pcap_file> <threshold>")

    def do_detect_port_scan(self, line):
        """
                Detect port scan from the pcap file.

                Usage: detect_port_scan <pcap_file> <threshold>
                Example: detect_port_scan capture.pcap 100
                """
        try:
            pcap_file, threshold = line.split()
            self.packet_analyzer = PacketAnalyzer(pcap_file)
            print(self.packet_analyzer.detect_port_scan(int(threshold)))
        except Exception as e:
            print("Error: ", e)
            print("Usage: detect_port_scan <pcap_file> <threshold>")

    def do_detect_ip_scan(self, line):
        """
                Detect IP scan from the pcap file.

                Usage: detect_ip_scan <pcap_file> <threshold>
                Example: detect_ip_scan capture.pcap 100
                """
        try:
            pcap_file, threshold = line.split()
            self.packet_analyzer = PacketAnalyzer(pcap_file)
            print(self.packet_analyzer.detect_ip_scan(int(threshold)))
        except Exception as e:
            print("Error: ", e)
            print("Usage: detect_ip_scan <pcap_file> <threshold>")

    def do_detect_malware(self, line):
        """
                Detect malware from the pcap file.

                Usage: detect_malware <pcap_file> <threshold>
                Example: detect_malware capture.pcap 100
                """
        try:
            pcap_file, threshold = line.split()
            self.packet_analyzer = PacketAnalyzer(pcap_file)
            print(self.packet_analyzer.detect_malware(int(threshold)))
        except Exception as e:
            print("Error: ", e)
            print("Usage: detect_malware <pcap_file> <threshold>")

        def do_generate_report(self, line):
            """
            Generate a report from the pcap file.

            Usage: generate_report <report_file>
            Example: generate_report report.txt
            """
            try:
                report_file = line.strip()
                if self.packet_analyzer is None:
                    print("No packets loaded. Use load_packets command first.")
                else:
                    self.packet_analyzer.generate_report(report_file)
                    print(f"Report generated successfully in {report_file}")
            except Exception as e:
                print("Error: ", e)
                print("Usage: generate_report <report_file>")

    def do_help(self, arg):
        print("Welcome to the Packet Analyzer CLI. The following commands are available:")
        print("capture <interface> <pcap_file> <count>")
        print("analyse_traffic_pattern <pcap_file> <interval>")
        print("detect_dos_attack <pcap_file> <threshold>")
        print("detect_port_scan <pcap_file> <threshold>")
        print("detect_ip_scan <pcap_file> <threshold>")
        print("detect_malware <pcap_file> <threshold>")
        print("generate_report <report_file>")
        print("exit")

    def do_exit(self, line):
        return True
