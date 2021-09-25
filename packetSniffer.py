import scapy.all as scapy
from collections import Counter

# Constants

# network adapter to sniff
NETWORK_ADAPTER = 'Wi-Fi'
packet_counts = Counter()


# sniff function that will return sniffed packet to process_sniffed_packet()
def sniff(interface):
    # @param iface = interface to sniff
    # @param filter - filter what to sniff
    scapy.sniff(iface=interface, filter="ip", store=False, prn=process_sniffed_packet, count=10)


def process_sniffed_packet(packet):
    print("From : ", packet[0][1].src, "  To : ", packet[0][1].dst)
    # key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
    # packet_counts.update([key])


sniff(NETWORK_ADAPTER)
