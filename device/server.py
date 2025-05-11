# server/server.py
import socket

def server_main():
    host = 'localhost'
    port = 12345

    # Set up server socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print("[Server] Waiting for connection...")
        conn, addr = s.accept()
        with conn:
            print(f"[Server] Connected by {addr}")

            # Receive Hello from device
            data = conn.recv(1024).decode()
            print(f"[Server] Received: {data}")

            # Send Hello back
            hello_msg = "Hello from Server"
            conn.sendall(hello_msg.encode())

if __name__ == "__main__":
    server_main()
