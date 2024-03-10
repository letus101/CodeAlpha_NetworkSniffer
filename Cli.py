import cmd
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

    def do_load(self, line):
        """
                Load packets from a pcap file.

                Usage: load <pcap_file>
                Example: load capture.pcap
                """
        try:
            pcap_file = line
            self.packet_analyzer = PacketAnalyzer(pcap_file)
        except Exception as e:
            print("Error: ", e)
            print("Usage: load <pcap_file>")

    def do_exit(self, line):
        return True


if __name__ == "__main__":
    Cli().cmdloop()
