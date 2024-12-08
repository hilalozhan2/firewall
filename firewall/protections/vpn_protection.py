# protections/vpn_protection.py
from scapy.layers.inet import IP, TCP, UDP
from scapy.all import sniff  # sniff ile paketleri dinleyeceğiz

# VPN trafiğini kontrol eden fonksiyon
def packet_handler(packet):
    if packet.haslayer(UDP) and packet[UDP].sport == 1194:
        print("VPN traffic detected (OpenVPN) from", packet[IP].src)
    
    return packet

# VPN korumasını başlatan fonksiyon
def start_vpn_protection():
    print("Starting VPN protection...")
    sniff(prn=packet_handler, store=0)  # Paketleri dinlemeye başla ve packet_handler fonksiyonunu kullan
