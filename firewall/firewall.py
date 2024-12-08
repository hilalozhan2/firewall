from scapy.all import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from scapy.layers.inet import IP, TCP
import os
import socket
import threading
# Kodun işlevleri: AES şifreleme ve şifre çözme,Paket Dinleme ve Filtreleme,HTTP Trafiği Şifreleme ve Çözme
#Sunucu ve İstemci Bağlantısı,(IP ve port kontrolu yapılıyor, 1 IP engellenmiş, geliştirilebilir)

# AES encryption function (same as before)
def encrypt_data(data):
    key = os.urandom(16)  # Generate a random 16-byte key
    cipher = AES.new(key, AES.MODE_CBC)  # AES cipher in CBC mode
    encrypted_data = cipher.encrypt(pad(data.encode(), AES.block_size))  # Encrypt data
    return cipher.iv + encrypted_data  # Return IV concatenated with encrypted data

# AES decryption function (same as before)
def decrypt_data(encrypted_data):
    iv = encrypted_data[:16]  # Extract the IV from the encrypted data
    ciphertext = encrypted_data[16:]  # The remaining part is the ciphertext
    key = os.urandom(16)  # Use the same key for decryption (should match the encryption key)

    cipher = AES.new(key, AES.MODE_CBC, iv)  # Initialize the cipher with the IV and key
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)  # Decrypt and unpad
    return decrypted_data.decode()  # Return the original message as a string

# This is where we will define the sniffing behavior for the firewall
def packet_handler(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(f"Packet from {ip_src} to {ip_dst}")

        # Example of blocking a specific IP (could be customized to suit your needs)
        if ip_src == "192.168.1.100":
            print("Blocked packet from 192.168.1.100")
            return  # Drop this packet

        # Example: If the packet is HTTP (port 80), encrypt it
        if packet.haslayer(TCP) and packet[TCP].dport == 80:
            print("Encrypting HTTP traffic...")
            payload = packet[TCP].payload.load.decode(errors='ignore')  # Get payload
            encrypted_payload = encrypt_data(payload)  # Encrypt the payload
            print(f"Encrypted payload: {encrypted_payload}")

            # Decrypt the encrypted data for inspection
            decrypted_payload = decrypt_data(encrypted_payload)
            print(f"Decrypted payload: {decrypted_payload}")

    return packet  # Continue with the packet if it’s not blocked

# Function to start a server (you can also start it in a thread)
def run_server():
    # Create a TCP/IP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the address and port
    server_socket.bind(('localhost', 8080))

    # Listen for incoming connections
    server_socket.listen(1)
    print("Server is waiting for a connection...")

    # Wait for a connection and accept it
    client_socket, client_address = server_socket.accept()
    print(f"Connection established with {client_address}")

    # Send a welcome message
    client_socket.sendall(b"Hello, client!")

    # Receive data from the client
    data = client_socket.recv(1024)
    print(f"Received from client: {data.decode()}")

    # Close the connection
    client_socket.close()
    server_socket.close()

# Function to start a client (this can also be done in a thread)
def run_client():
    # Create a TCP/IP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server (localhost and port 8080)
    client_socket.connect(('localhost', 8080))

    # Send data to the server
    client_socket.sendall(b"Hello, server!")

    # Receive data from the server
    data = client_socket.recv(1024)
    print(f"Received from server: {data.decode()}")

    # Close the connection
    client_socket.close()

# Starting the sniffing process to capture packets
def start_sniffing():
    sniff(prn=packet_handler)  # Start sniffing packets and process them with packet_handler

# Main function to run everything
if __name__ == "__main__":
    # Run the server and client in separate threads
    server_thread = threading.Thread(target=run_server)
    client_thread = threading.Thread(target=run_client)
    
    server_thread.start()
    client_thread.start()

    # Start sniffing
    start_sniffing()

    # Wait for threads to complete
    server_thread.join()
    client_thread.join()

