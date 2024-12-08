import socket

def run_client():
    try:
        # Create a TCP/IP socket
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect to the server (localhost and port 8080)
        client_socket.connect(('localhost', 8080))
        print("Connected to server.")

        # Receive data from the server
        data = client_socket.recv(1024)
        print(f"Received from server: {data.decode()}")

        # Send data to the server after receiving the message
        client_socket.sendall(b"Hello, server!")
        print("Message sent to server.")

    except Exception as e:
        print(f"An error occurred: {e}")

    finally:
        # Ensure the socket is always closed
        client_socket.close()
        print("Connection closed.")

if __name__ == "__main__":
    run_client()
