from collections import defaultdict
from scapy.layers.inet import IP, TCP
from scapy.all import sniff
# Bağlantı izleme
connection_count = defaultdict(int)

def packet_handler(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        connection_count[ip_src] += 1
        
        # Eğer bir IP adresinden çok fazla paket geliyorsa (DDoS tespiti)
        if connection_count[ip_src] > 100:
            print(f"Potential DDoS attack detected from {ip_src}")
            return None  # Bu paketi engelle
        
    return packet
#eklenen kısım:
def start_instruction_detection():
    """
    Instruction Detection ve DDoS tespiti işlemlerini başlatan fonksiyon.
    """
    print("Instruction Detection started. Sniffing network traffic...")
    sniff(prn=packet_handler)