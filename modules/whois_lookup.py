import whois
from datetime import datetime
import json


class WhoisLookup:
    def __init__(self):
        self.domain_info = {}

    def lookup(self, domain):
        """Perform WHOIS lookup on domain"""
        print(f"\n[*] Looking up: {domain}")

        try:
            w = whois.whois(domain)

            # Extract information
            self.domain_info = {
                'domain_name': w.domain_name,
                'registrar': w.registrar,
                'whois_server': w.whois_server,
                'creation_date': self.format_date(w.creation_date),
                'expiration_date': self.format_date(w.expiration_date),
                'updated_date': self.format_date(w.updated_date),
                'name_servers': w.name_servers,
                'status': w.status,
                'emails': w.emails,
                'org': w.org,
                'address': w.address,
                'city': w.city,
                'state': w.state,
                'country': w.country
            }

            return self.domain_info

        except whois.parser.PywhoisError:
            print(f"[-] Domain not found or invalid: {domain}")
            return None
        except Exception as e:
            print(f"[-] Error: {str(e)}")
            return None

    def format_date(self, date_value):
        """Format date values to string"""
        if date_value is None:
            return "N/A"

        # Handle list of dates (some WHOIS return multiple)
        if isinstance(date_value, list):
            date_value = date_value[0]

        # Convert to string
        if isinstance(date_value, datetime):
            return date_value.strftime("%Y-%m-%d %H:%M:%S")

        return str(date_value)

    def display_info(self):
        """Display WHOIS information in formatted output"""
        if not self.domain_info:
            print("[-] No data to display")
            return

        print(f"\n{'=' * 60}")
        print("WHOIS INFORMATION")
        print(f"{'=' * 60}\n")

        # Domain details
        print(f"Domain Name:       {self.domain_info.get('domain_name', 'N/A')}")
        print(f"Registrar:         {self.domain_info.get('registrar', 'N/A')}")
        print(f"WHOIS Server:      {self.domain_info.get('whois_server', 'N/A')}")

        # Dates
        print(f"\nCreation Date:     {self.domain_info.get('creation_date', 'N/A')}")
        print(f"Expiration Date:   {self.domain_info.get('expiration_date', 'N/A')}")
        print(f"Updated Date:      {self.domain_info.get('updated_date', 'N/A')}")

        # Name servers
        name_servers = self.domain_info.get('name_servers')
        if name_servers:
            print(f"\nName Servers:")
            if isinstance(name_servers, list):
                for ns in name_servers:
                    print(f"  - {ns}")
            else:
                print(f"  - {name_servers}")

        # Status
        status = self.domain_info.get('status')
        if status:
            print(f"\nDomain Status:")
            if isinstance(status, list):
                for s in status:
                    print(f"  - {s}")
            else:
                print(f"  - {status}")

        # Contact information
        print(f"\nOrganization:      {self.domain_info.get('org', 'N/A')}")
        print(f"Address:           {self.domain_info.get('address', 'N/A')}")
        print(f"City:              {self.domain_info.get('city', 'N/A')}")
        print(f"State:             {self.domain_info.get('state', 'N/A')}")
        print(f"Country:           {self.domain_info.get('country', 'N/A')}")

        # Emails
        emails = self.domain_info.get('emails')
        if emails:
            print(f"\nContact Emails:")
            if isinstance(emails, list):
                for email in emails:
                    print(f"  - {email}")
            else:
                print(f"  - {emails}")

        print(f"\n{'=' * 60}\n")

    def save_to_file(self, filename=None):
        """Save WHOIS information to JSON file"""
        if not self.domain_info:
            print("[-] No data to save")
            return

        if filename is None:
            domain = self.domain_info.get('domain_name', 'unknown')
            if isinstance(domain, list):
                domain = domain[0]
            filename = f"data/whois_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        import os
        os.makedirs(os.path.dirname(filename), exist_ok=True)

        with open(filename, 'w') as f:
            json.dump(self.domain_info, f, indent=4, default=str)

        print(f"[+] Results saved to: {filename}")


# Usage example
if __name__ == "__main__":
    lookup = WhoisLookup()

    domain = "github.com"
    info = lookup.lookup(domain)

    if info:
        lookup.display_info()
        lookup.save_to_file()
