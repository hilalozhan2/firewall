# packets_utils.py
from scapy.layers.inet import IP, TCP
from scapy.layers.dhcp import DHCP
from scapy.all import *

# Paketlerin IP adresi ve port bilgilerini çıkartma
def extract_ip_and_port(packet):
    """
    Bu fonksiyon, bir paketten IP adresi ve port bilgilerini çıkarır.
    """
    ip_src = packet[IP].src if packet.haslayer(IP) else None
    ip_dst = packet[IP].dst if packet.haslayer(IP) else None
    dport = packet[TCP].dport if packet.haslayer(TCP) else None
    sport = packet[TCP].sport if packet.haslayer(TCP) else None
    
    return ip_src, ip_dst, sport, dport

# DHCP paketlerini tespit etme
def is_dhcp_packet(packet):
    """
    DHCP paketini tespit eder. Eğer paket bir DHCP paketi ise True döner.
    """
    return packet.haslayer(DHCP)

# IP adresi kontrolü (Blacklist / Whitelist)
def check_ip_blacklist(packet, blacklist):
    """
    Eğer paket, blacklistteki bir IP adresine sahipse, bu paket reddedilir.
    """
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        if ip_src in blacklist:
            print(f"Packet from blacklisted IP {ip_src} blocked!")
            return True  # Paket engellenir
    return False  # Paket engellenmez

# Paket üzerinde basit filtreleme (Port kontrolü)
def filter_packet_by_ports(packet, blocked_ports):
    """
    Eğer paket belirli bir portu kullanıyorsa, o paketi engeller.
    """
    if packet.haslayer(TCP):
        dport = packet[TCP].dport
        sport = packet[TCP].sport
        
        if dport in blocked_ports or sport in blocked_ports:
            print(f"Packet blocked due to restricted port: {dport}/{sport}")
            return False  # Paket engellenir
    return True  # Paket engellenmez

# Paket şifreleme işlemi (AES)
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

def encrypt_packet_data(data):
    """
    Paket verisini AES ile şifreler.
    """
    key = os.urandom(16)  # 16 byte'lık rastgele bir anahtar üretir
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted_data = cipher.encrypt(pad(data.encode(), AES.block_size))
    return cipher.iv + encrypted_data  # IV ve şifreli veriyi birleştir

def decrypt_packet_data(encrypted_data, key):
    """
    Şifreli paket verisini çözer.
    """
    iv = encrypted_data[:16]  # IV'yi ayıkla
    ciphertext = encrypted_data[16:]  # Şifreli veriyi ayıkla
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_data.decode()  # Orijinal veriyi döndürür

# Loglama işlevi
import logging
from config import LOG_FILE

def log_packet_info(packet):
    """
    Paket bilgilerini log dosyasına kaydeder.
    """
    logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")
    logging.info(f"Packet info: {packet.summary()}")
