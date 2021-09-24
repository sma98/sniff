import scapy.all as scapy
NETWORK_ADAPTER = 'Wi-Fi'


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    print(packet)


sniff(NETWORK_ADAPTER)
