# packet_filtering.py
from scapy.layers.inet import IP, TCP
from config import ALLOWED_IPS, BLOCKED_PORTS
from scapy.all import sniff

def filter_packet(packet):
    """
    Paketleri filtreler: 
    - Yalnızca izin verilen IP'lerden gelen paketler kabul edilir.
    - Belirtilen portlardan gelen paketler engellenir.
    """
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        # İzin verilen IP kontrolü
        if ip_src not in ALLOWED_IPS:
            print(f"Packet from {ip_src} blocked: Not allowed IP.")
            return None
        
        # Engellenen port kontrolü
        if packet.haslayer(TCP):
            dport = packet[TCP].dport
            if dport in BLOCKED_PORTS:
                print(f"Packet to {ip_dst} blocked: Port {dport} is blocked.")
                return None

    return packet

def start_packet_filtering():
    """
    Paket filtreleme işlemini başlatan fonksiyon.
    """
    print("Starting packet filtering...")
    sniff(prn=filter_packet)  # Paketin yakalanmasını başlat