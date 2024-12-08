# ddos_protection.py
from scapy.layers.inet import IP, TCP
from collections import defaultdict
from time import time
from config import MAX_CONNECTIONS_PER_SECOND
from scapy.all import sniff

# Bağlantı sayıları (IP başına)
connection_counts = defaultdict(int)
last_request_time = defaultdict(float)

def ddos_protection(packet):
    """
    DDoS saldırısı tespiti: 
    Aynı IP'den gelen bağlantıları sayar, belirli bir sınırdan fazla olan bağlantıları engeller.
    """
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        current_time = time()
        
        # Önceki bağlantı zamanını kontrol et
        if current_time - last_request_time[ip_src] <= 1:  # 1 saniye içinde
            connection_counts[ip_src] += 1
        else:
            connection_counts[ip_src] = 1  # Yeni bağlantı başladığında sayacı sıfırla
        
        # Bağlantı sınırını aşan IP'yi engelle
        if connection_counts[ip_src] > MAX_CONNECTIONS_PER_SECOND:
            print(f"DDoS attack detected from {ip_src}. Blocking connection.")
            return None
        
        last_request_time[ip_src] = current_time
    
    return packet

#eklenen
def start_ddos_protection():
    """
    DDoS korumasını başlatır ve paketleri dinler.
    """
    print("DDoS protection started...")
    sniff(prn=ddos_protection, store=0)  # Paketleri dinle ve ddos_protection fonksiyonunu çağır