state_table = {}
from scapy.layers.inet import IP, TCP

def packet_handler(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        tcp_src_port = packet[TCP].sport
        tcp_dst_port = packet[TCP].dport
        
        # Bağlantı durumu kontrolü (yeni bir bağlantı mı?)
        if (ip_src, tcp_src_port) not in state_table:
            state_table[(ip_src, tcp_src_port)] = "established"
            print(f"New connection from {ip_src}:{tcp_src_port}")
        
        # Bağlantı durumunu kontrol et
        if state_table.get((ip_src, tcp_src_port)) == "established":
            print(f"Packet from {ip_src} to {ip_dst} is part of an established connection")
        
        # Bağlantı kuralları
        if packet[TCP].flags == "S":  # SYN bayrağı (yeni bağlantı isteği)
            print("New connection request")
        
    return packet
