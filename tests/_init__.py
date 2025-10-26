import unittest
from modules.port_scanner import PortScanner


class TestPortScanner(unittest.TestCase):
    def test_scan_known_open_port(self):
        scanner = PortScanner('127.0.0.1', (80, 80))
        results = scanner.run_scan()
        # Assert that the result for port 80 is correct type
        self.assertIsInstance(results, list)

    def test_scan_invalid_host(self):
        scanner = PortScanner('invalid.host', (1, 10))
        with self.assertRaises(SystemExit):  # Expects sys.exit on failure
            scanner.run_scan()


if __name__ == '__main__':
    unittest.main()
