# config.py

# --- Firewall Konfigürasyonu ---

# İzin verilen IP adresleri (Güvenli IP'ler)
ALLOWED_IPS = ["192.168.1.1", "192.168.1.2"]  # Örnek güvenli IP'ler

# Engellenmesi gereken portlar
BLOCKED_PORTS = [80, 443]  # HTTP ve HTTPS portları (isteğe bağlı olarak engellenebilir)

# Maksimum bağlantı sayısı (DDoS koruma)
MAX_CONNECTIONS_PER_SECOND = 50  # Aynı IP'den gelen 50'den fazla istek engellenir (DDoS koruması)

# DDoS tespiti için aktif edilen IP sınırlama (True/False)
ENABLE_DDOS_PROTECTION = True  # DDoS korumasını etkinleştir

# --- Şifreleme ve Güvenlik Konfigürasyonu ---

# AES Şifreleme Konfigürasyonu
AES_KEY_LENGTH = 16  # AES anahtar uzunluğu (16 byte, CBC modu için yaygın)
AES_MODE = "CBC"  # AES şifreleme modu (Cipher Block Chaining)

# AES şifreleme anahtarını otomatik olarak belirlemek yerine, burada bir anahtar kullanabilirsiniz (güvenlik için dikkatli olmalısınız)
# AES_KEY = b'Sixteen byte key'  # Anahtarı sabit bir şekilde burada tanımlayabilirsiniz

# --- Client ve Server Yapılandırmaları ---

# Server IP ve Port
SERVER_IP = "localhost"  # Server'ın IP adresi
SERVER_PORT = 8080  # Server'ın portu

# Client yapılandırması (eğer client.py'yi burada başlatmak isterseniz)
CLIENT_IP = "localhost"  # Client'ın IP adresi
CLIENT_PORT = 8080  # Client'ın portu

# --- Port ve Trafik İzleme Konfigürasyonu ---

# İzlenen ağ arabirimi (Scapy veya başka bir araçla trafiği izlerken kullanılır)
NETWORK_INTERFACE = "eth0"  # Örnek: eth0, wlan0 vs. Ağ arabiriminizi buraya yazın

# Trafik türlerini engelleme (True/False)
BLOCK_HTTP_TRAFFIC = True  # HTTP trafiğini engelle
BLOCK_FTP_TRAFFIC = False  # FTP trafiğini engelle (isteğe bağlı)

# --- VPN ve Proxy Tespiti ---

# VPN tespiti (True/False)
ENABLE_VPN_DETECTION = True  # VPN trafiği izlemeyi etkinleştir

# Proxy tespiti (True/False)
ENABLE_PROXY_DETECTION = True  # Proxy trafiği izlemeyi etkinleştir

# --- Loglama ve İzleme Konfigürasyonu ---

# Log dosyasının yolu
LOG_FILE = "firewall_log.txt"

# Log seviyeleri: DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_LEVEL = "INFO"  # INFO seviyesi ile loglama yapılacak (Debug, Error gibi seviyeler de seçilebilir)

# Log formatı
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"  # Log mesajı formatı

# --- Firewall Durum Tespiti (Stateful Inspection) ---

# Durum tabanlı kontrol (Stateful Inspection) aktif mi?
STATEFUL_INSPECTION_ENABLED = True  # Durum tabanlı denetimi etkinleştir

# Durum tabanlı kontrol için bağlantı süresi sınırı (örn. 10 saniye)
MAX_CONNECTION_TIMEOUT = 10  # Bağlantılar 10 saniye boyunca aktifse geçerli kabul edilir

# --- Diğer Konfigürasyonlar ---

# Paketi kaydetme ve raporlama (True/False)
SAVE_PACKET_LOGS = True  # Paketleri log dosyasına kaydetme
