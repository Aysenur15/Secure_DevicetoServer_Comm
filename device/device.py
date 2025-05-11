# device/device.py
import socket

def device_main():
    host = 'localhost'
    port = 12345

    # Connect to server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        print("[Device] Connected to server.")

        # Send Hello (example, just text for now)
        hello_msg = "Hello from Device"
        s.sendall(hello_msg.encode())

        # Receive Hello from server
        response = s.recv(1024).decode()
        print(f"[Device] Received: {response}")

if __name__ == "__main__":
    device_main()
