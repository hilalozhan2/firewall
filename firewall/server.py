import socket

def run_server():
    try:
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

        # Send a welcome message to the client
        client_socket.sendall(b"Hello, client!")
        print("Welcome message sent to client.")

        # Receive data from the client
        data = client_socket.recv(1024)
        print(f"Received from client: {data.decode()}")

    except Exception as e:
        print(f"An error occurred: {e}")

    finally:
        # Ensure both client and server sockets are closed
        client_socket.close()
        server_socket.close()
        print("Sockets closed.")

if __name__ == "__main__":
    run_server()
