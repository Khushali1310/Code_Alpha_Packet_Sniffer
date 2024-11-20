from scapy.all import *

def filter_and_analyze(pkt):
    # Check if the packet contains IP information
    if IP in pkt:
        print(f"IP Source: {pkt[IP].src}")
        print(f"IP Destination: {pkt[IP].dst}")
    # Check if the packet contains TCP information
    if TCP in pkt:
        print(f"TCP Source Port: {pkt[TCP].sport}")
        print(f"TCP Destination Port: {pkt[TCP].dport}")
    # Check if the packet contains UDP information
    if UDP in pkt:
        print(f"UDP Source Port: {pkt[UDP].sport}")
        print(f"UDP Destination Port: {pkt[UDP].dport}")

def sniff_packets(iface="Wi-Fi", filter_exp="port 80"):
    print(f"Sniffing on interface {iface} with filter '{filter_exp}'...")
    sniff(iface=iface, filter=filter_exp, prn=filter_and_analyze)

if __name__ == "__main__":
    sniff_packets()
