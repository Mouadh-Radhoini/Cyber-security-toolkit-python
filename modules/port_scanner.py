import socket
import threading
from datetime import datetime
import sys


class PortScanner:
    def __init__(self, target, port_range):
        self.target = target
        self.port_range = port_range
        self.open_ports = []
        self.lock = threading.Lock()

    def scan_port(self, port):
        """Scan a single port and check if it's open"""
        try:
            # Create socket object
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)

            # Attempt connection
            result = sock.connect_ex((self.target, port))

            if result == 0:
                # Port is open, try to grab banner
                try:
                    sock.send(b'Hello\r\n')
                    banner = sock.recv(1024).decode().strip()
                    service = banner if banner else "Unknown"
                except:
                    service = "Unknown"

                with self.lock:
                    self.open_ports.append({
                        'port': port,
                        'service': service
                    })
                    print(f"[+] Port {port}: OPEN - {service}")

            sock.close()

        except socket.gaierror:
            print(f"[-] Hostname could not be resolved")
            sys.exit()
        except socket.error:
            print(f"[-] Could not connect to server")
            sys.exit()
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user")
            sys.exit()

    def run_scan(self):
        """Execute the port scan with multithreading"""
        print(f"\n[*] Starting scan on {self.target}")
        print(f"[*] Port range: {self.port_range[0]}-{self.port_range[1]}")
        print(f"[*] Scan started at {datetime.now()}\n")

        threads = []

        # Create threads for each port
        for port in range(self.port_range[0], self.port_range[1] + 1):
            thread = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(thread)
            thread.start()

            # Limit concurrent threads
            if len(threads) >= 100:
                for t in threads:
                    t.join()
                threads = []

        # Wait for remaining threads
        for thread in threads:
            thread.join()

        print(f"\n[*] Scan completed at {datetime.now()}")
        print(f"[*] Found {len(self.open_ports)} open ports\n")

        return self.open_ports


# Usage example
if __name__ == "__main__":
    target = "127.0.0.1"
    port_range = (1, 1024)
    scanner = PortScanner(target, port_range)
    results = scanner.run_scan()
