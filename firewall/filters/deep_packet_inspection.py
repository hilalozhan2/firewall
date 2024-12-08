from scapy.layers.inet import IP, TCP,Raw
def packet_handler(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors="ignore")
        
        # SQL Injection tespiti (örnek)
        if "SELECT" in payload and "FROM" in payload:
            print("Potential SQL Injection detected")
        
        # XSS tespiti (örnek)
        if "<script>" in payload:
            print("Potential XSS attack detected")
        
    return packet
