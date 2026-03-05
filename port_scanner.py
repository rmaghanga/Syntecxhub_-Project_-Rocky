import socket
import threading
from queue import Queue
from datetime import datetime

# Thread-safe queue for ports
port_queue = Queue()

# Lock to avoid mixed prints from multiple threads
print_lock = threading.Lock()

# Log file
log_file = open("scan_results.txt", "w")

def scan_port(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((target_ip, port))

        if result == 0:
            status = "OPEN"
        elif result == 111:
            status = "CLOSED"
        else:
            status = "TIMEOUT"

        with print_lock:
            output = f"Port {port}: {status}"
            print(output)
            log_file.write(output + "\n")

        sock.close()

    except socket.timeout:
        with print_lock:
            output = f"Port {port}: TIMEOUT"
            print(output)
            log_file.write(output + "\n")

    except socket.gaierror:
        print("Hostname could not be resolved.")

    except socket.error:
        print("Connection error occurred.")

def worker(target_ip):
    while not port_queue.empty():
        port = port_queue.get()
        scan_port(target_ip, port)
        port_queue.task_done()

def main():
    print("=== TCP Port Scanner ===")

    target = input("Enter target host (IP or domain): ")

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("Invalid hostname.")
        return

    try:
        start_port = int(input("Enter start port: "))
        end_port = int(input("Enter end port: "))
    except ValueError:
        print("Ports must be numbers.")
        return

    thread_count = int(input("Enter number of threads (e.g., 50): "))

    print("\nScanning target:", target_ip)
    print("Port range:", start_port, "-", end_port)
    print("Scan started at:", datetime.now())
    print("-" * 50)

    # Add ports to queue
    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    # Create threads
    threads = []
    for _ in range(thread_count):
        thread = threading.Thread(target=worker, args=(target_ip,))
        thread.start()
        threads.append(thread)

    # Wait for queue to finish
    port_queue.join()

    print("-" * 50)
    print("Scan finished at:", datetime.now())

    log_file.close()

if __name__ == "__main__":
    main()