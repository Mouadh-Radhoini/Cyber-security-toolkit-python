📘 Cybersecurity Toolkit – Multi-Tool Security Framework

A modular, extensible Python toolkit for ethical hacking, network scanning, vulnerability testing, and cybersecurity analysis.

🚀 Overview

The Cybersecurity Toolkit is a command-line security framework that combines multiple cybersecurity tools into a single modular system.
It is designed for:

Cybersecurity students

Ethical hackers

Network administrators

Developers studying security concepts

Python automation learners

This project demonstrates knowledge of:
✔ Python scripting
✔ Networking fundamentals
✔ Security scanning techniques
✔ Encryption & secure storage
✔ File integrity monitoring
✔ WHOIS parsing
✔ Modular project architecture
✔ Terminal UI design
✔ Best practices for CLI tools

🧩 Included Tools

This toolkit includes six full security modules:

1️⃣ Port Scanner

Scan a target system for open ports using multi-threading.

2️⃣ Network Scanner

Discover devices on a local network using ARP scanning (Scapy).

3️⃣ Password Manager

Store encrypted passwords locally using Fernet symmetric encryption.

4️⃣ Vulnerability Scanner

Basic SQL Injection + XSS detection using form analysis.

5️⃣ File Integrity Checker

Generate file hash baselines and detect modifications using SHA-256.

6️⃣ WHOIS Lookup

Retrieve domain registration data (registrar, dates, NS records, etc.).

🛠 Project Structure
Cyber-security-toolkit-python/
│
├── main.py
├── requirement.txt
├── README.md
│
├── modules/
│   ├── port_scanner.py
│   ├── network_scanner.py
│   ├── password_manager.py
│   ├── vulnerability_scanner.py
│   ├── integrity_checker.py
│   ├── whois_lookup.py
│   ├── utils.py
│   └── ui.py
│
├── data/
│   ├── passwords.json
│   ├── secret.key
│   ├── master.hash
│   └── hashes/
│       └── baseline.json
│
└── logs/
    └── toolkit_YYYYMMDD.log

📦 Installation
1️⃣ Clone the project
git clone https://github.com/username/Cybersecurity-Toolkit.git
cd Cybersecurity-Toolkit

2️⃣ Create and activate a virtual environment
Windows PowerShell:
py -m venv venv
.\venv\Scripts\Activate.ps1

Linux / macOS:
python3 -m venv venv
source venv/bin/activate

3️⃣ Install dependencies
pip install -r requirement.txt

🏁 Usage

Run the toolkit:

python main.py


See available commands:

python main.py --help

🔧 Examples
🔹 Port Scan
python main.py portscan -t 192.168.1.10 -p 1-1000

🔹 Network Scan
python main.py netscan -r 192.168.1.0/24

🔹 Add Password
python main.py password add -w facebook.com -u admin

🔹 Generate Password
python main.py password generate -l 20

🔹 Vulnerability Scan (SQLi + XSS)
python main.py vulnscan -u http://example.com

🔹 Create Integrity Baseline
python main.py integrity baseline -d myfolder/

🔹 Verify Integrity
python main.py integrity verify -d myfolder/

🔹 WHOIS Lookup
python main.py whois -d github.com

🔐 Security Requirements

Some tools need elevated permissions:

Network scanner requires Administrator / sudo

Password manager stores encrypted passwords locally

Vulnerability scanner must only be used on systems you are authorized to test
→ Illegal usage is your responsibility

📝 Logging

All operations are logged in:

logs/toolkit_YYYYMMDD.log


This is useful for:

debugging

auditing

exam demonstrations

🧪 Testing

A folder tests/ exists for unit tests.
You may add:

port scanner tests

password manager encryption tests

integrity checker hashing tests

📚 Technologies Used
Feature	Library
Port scanning	socket, threading
Network scanning	scapy
Password encryption	cryptography
Web vulnerability scan	requests, bs4
WHOIS	python-whois
Terminal UI	ANSI color codes
Logging	logging built-in
🏆 Why This Project Is Exam-Ready

Full modular architecture

Strong separation of concerns

Advanced concepts (crypto, scapy, hashing)

CLI argument parsing

Logging + real-world scanning tools

Error handling everywhere

Clean professional code

Expandable design

This project shows serious cybersecurity knowledge and clean code engineering.

🤝 License

This project is for educational and ethical use only.
You must follow your local laws and ethical guidelines.

🧑‍💻 Author

Your Name
Cybersecurity Student & Software Developer
