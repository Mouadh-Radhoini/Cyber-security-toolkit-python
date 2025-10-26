import scapy.all as scapy
import sys


class NetworkScanner:
    def __init__(self, ip_range):
        self.ip_range = ip_range
        self.clients = []

    def scan(self):
        """Scan the network for active devices"""
        print(f"\n[*] Scanning network: {self.ip_range}")
        print("[*] Please wait...\n")

        try:
            # Create ARP request
            arp_request = scapy.ARP(pdst=self.ip_range)

            # Create Ethernet broadcast frame
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

            # Combine ARP request with Ethernet frame
            arp_request_broadcast = broadcast / arp_request

            # Send packet and receive response
            answered_list = scapy.srp(arp_request_broadcast,
                                      timeout=2,
                                      verbose=False)[0]

            # Parse responses
            for element in answered_list:
                client_dict = {
                    'ip': element[1].psrc,
                    'mac': element[1].hwsrc
                }
                self.clients.append(client_dict)

            return self.clients

        except PermissionError:
            print("[-] Error: This tool requires root/administrator privileges")
            print("[*] Please run with sudo (Linux/Mac) or as Administrator (Windows)")
            sys.exit()
        except Exception as e:
            print(f"[-] Error: {str(e)}")
            sys.exit()

    def display_results(self):
        """Display scan results in formatted table"""
        if not self.clients:
            print("[-] No devices found on the network")
            return

        print(f"[+] Found {len(self.clients)} devices:\n")
        print("-" * 60)
        print(f"{'IP Address':<20} {'MAC Address':<20}")
        print("-" * 60)

        for client in self.clients:
            print(f"{client['ip']:<20} {client['mac']:<20}")

        print("-" * 60)

    def save_results(self, filename='data/scan_results/network_scan.txt'):
        """Save scan results to file"""
        import os
        from datetime import datetime

        # Create directory if doesn't exist
        os.makedirs(os.path.dirname(filename), exist_ok=True)

        with open(filename, 'w') as f:
            f.write(f"Network Scan Results\n")
            f.write(f"Scan Date: {datetime.now()}\n")
            f.write(f"Target Range: {self.ip_range}\n")
            f.write(f"Devices Found: {len(self.clients)}\n\n")
            f.write("-" * 60 + "\n")
            f.write(f"{'IP Address':<20} {'MAC Address':<20}\n")
            f.write("-" * 60 + "\n")

            for client in self.clients:
                f.write(f"{client['ip']:<20} {client['mac']:<20}\n")

        print(f"\n[+] Results saved to {filename}")


# Usage example
if __name__ == "__main__":
    # Scan local network (adjust range as needed)
    scanner = NetworkScanner("192.168.1.0/24")
    scanner.scan()
    scanner.display_results()
    scanner.save_results()
