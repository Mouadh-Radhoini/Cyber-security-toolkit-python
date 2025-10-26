#!/usr/bin/env python3

import argparse
import logging
import sys
from datetime import datetime

# Import all modules
from modules import port_scanner
from modules import network_scanner
from modules import password_manager
from modules import vulnerability_scanner
from modules import integrity_checker
from modules import whois_lookup

# ASCII Banner
BANNER = """
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║        CYBERSECURITY TOOLKIT - Multi-Tool Framework      ║
║                    Version 1.0                            ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
"""


def setup_logging():
    """Configure logging system"""
    log_filename = f'logs/toolkit_{datetime.now().strftime("%Y%m%d")}.log'

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_filename),
            logging.StreamHandler()
        ]
    )

    return logging.getLogger(__name__)


def main():
    """Main application entry point"""

    # Print banner
    print(BANNER)

    # Setup logging
    logger = setup_logging()
    logger.info("Cybersecurity Toolkit started")

    # Create main parser
    parser = argparse.ArgumentParser(
        description="Cybersecurity Toolkit - Multi-Tool Security Framework",
        epilog="Use '<command> --help' for more information on a command."
    )

    # Create subparsers for each tool
    subparsers = parser.add_subparsers(dest='command', help='Available tools')

    # ===== PORT SCANNER =====
    port_parser = subparsers.add_parser('portscan',
                                        help='Scan ports on target system')
    port_parser.add_argument('-t', '--target',
                             required=True,
                             help='Target IP address or hostname')
    port_parser.add_argument('-p', '--ports',
                             default='1-1024',
                             help='Port range (e.g., 1-1024 or 80,443,8080)')

    # ===== NETWORK SCANNER =====
    net_parser = subparsers.add_parser('netscan',
                                       help='Scan network for active devices')
    net_parser.add_argument('-r', '--range',
                            required=True,
                            help='IP range in CIDR notation (e.g., 192.168.1.0/24)')
    net_parser.add_argument('-o', '--output',
                            help='Save results to file')

    # ===== PASSWORD MANAGER =====
    pass_parser = subparsers.add_parser('password',
                                        help='Manage encrypted passwords')
    pass_parser.add_argument('action',
                             choices=['add', 'get', 'list', 'generate'],
                             help='Action to perform')
    pass_parser.add_argument('-w', '--website',
                             help='Website name')
    pass_parser.add_argument('-u', '--username',
                             help='Username')
    pass_parser.add_argument('-l', '--length',
                             type=int,
                             default=16,
                             help='Password length for generation')

    # ===== VULNERABILITY SCANNER =====
    vuln_parser = subparsers.add_parser('vulnscan',
                                        help='Scan website for vulnerabilities')
    vuln_parser.add_argument('-u', '--url',
                             required=True,
                             help='Target URL (must have permission)')

    # ===== FILE INTEGRITY CHECKER =====
    integrity_parser = subparsers.add_parser('integrity',
                                             help='Check file integrity')
    integrity_parser.add_argument('action',
                                  choices=['baseline', 'verify'],
                                  help='Create baseline or verify integrity')
    integrity_parser.add_argument('-d', '--directory',
                                  required=True,
                                  help='Directory to monitor')

    # ===== WHOIS LOOKUP =====
    whois_parser = subparsers.add_parser('whois',
                                         help='WHOIS domain lookup')
    whois_parser.add_argument('-d', '--domain',
                              required=True,
                              help='Domain name to lookup')
    whois_parser.add_argument('-s', '--save',
                              action='store_true',
                              help='Save results to file')

    # Parse arguments
    args = parser.parse_args()

    # If no command provided, show help
    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Route to appropriate tool
    try:
        if args.command == 'portscan':
            logger.info(f"Port scan started on {args.target}")

            # Parse port range
            if '-' in args.ports:
                start, end = map(int, args.ports.split('-'))
                port_range = (start, end)
            else:
                # Individual ports
                ports = list(map(int, args.ports.split(',')))
                port_range = (min(ports), max(ports))

            scanner = port_scanner.PortScanner(args.target, port_range)
            results = scanner.run_scan()
            logger.info(f"Port scan completed. Found {len(results)} open ports")

        elif args.command == 'netscan':
            logger.info(f"Network scan started on {args.range}")

            scanner = network_scanner.NetworkScanner(args.range)
            clients = scanner.scan()
            scanner.display_results()

            if args.output:
                scanner.save_results(args.output)

            logger.info(f"Network scan completed. Found {len(clients)} devices")

        elif args.command == 'password':
            logger.info(f"Password manager action: {args.action}")

            pm = password_manager.PasswordManager()

            if not pm.initialize():
                sys.exit(1)

            if args.action == 'add':
                if not args.website or not args.username:
                    print("[-] --website and --username required for add action")
                    sys.exit(1)

                password = input("Enter password (or press Enter to generate): ")
                if not password:
                    password = pm.generate_strong_password(args.length)
                    print(f"[+] Generated password: {password}")

                pm.add_password(args.website, args.username, password)

            elif args.action == 'get':
                if not args.website:
                    print("[-] --website required for get action")
                    sys.exit(1)

                result = pm.get_password(args.website)
                if result:
                    print(f"\nWebsite: {result['website']}")
                    print(f"Username: {result['username']}")
                    print(f"Password: {result['password']}")
                else:
                    print(f"[-] No password found for {args.website}")

            elif args.action == 'list':
                pm.list_passwords()

            elif args.action == 'generate':
                password = pm.generate_strong_password(args.length)
                print(f"\n[+] Generated password: {password}")

        elif args.command == 'vulnscan':
            logger.info(f"Vulnerability scan started on {args.url}")

            print("\n[!] WARNING: Only scan websites you have permission to test!")
            confirm = input("Do you have permission to scan this website? (yes/no): ")

            if confirm.lower() != 'yes':
                print("[-] Scan aborted")
                sys.exit(0)

            scanner = vulnerability_scanner.VulnerabilityScanner(args.url)
            results = scanner.run_scan()

            logger.info(f"Vulnerability scan completed. Found {len(results)} vulnerabilities")

        elif args.command == 'integrity':
            checker = integrity_checker.FileIntegrityChecker(args.directory)

            if args.action == 'baseline':
                logger.info(f"Creating baseline for {args.directory}")
                checker.create_baseline()

            elif args.action == 'verify':
                logger.info(f"Verifying integrity of {args.directory}")
                results = checker.verify_integrity()

                if results:
                    total_changes = (len(results['modified']) +
                                     len(results['added']) +
                                     len(results['deleted']))
                    logger.info(f"Integrity check completed. {total_changes} changes detected")

        elif args.command == 'whois':
            logger.info(f"WHOIS lookup for {args.domain}")

            lookup = whois_lookup.WhoisLookup()
            info = lookup.lookup(args.domain)

            if info:
                lookup.display_info()
                if args.save:
                    lookup.save_to_file()

            logger.info("WHOIS lookup completed")

    except KeyboardInterrupt:
        print("\n\n[!] Operation cancelled by user")
        logger.warning("Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] Error: {str(e)}")
        logger.error(f"Error: {str(e)}")
        sys.exit(1)

    logger.info("Cybersecurity Toolkit finished\n")


if __name__ == "__main__":
    main()
