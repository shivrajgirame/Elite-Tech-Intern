import socket

def run():
    """Run the port scanner interactively."""
    target = input("Enter target host (IP or domain): ")
    start_port = int(input("Start port: "))
    end_port = int(input("End port: "))
    print(f"\nScanning {target} from port {start_port} to {end_port}...")
    open_ports = []
    for port in range(start_port, end_port + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            result = s.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
                print(f"Port {port}: OPEN")
    if not open_ports:
        print("No open ports found in the specified range.")
    else:
        print(f"\nOpen ports: {open_ports}") 