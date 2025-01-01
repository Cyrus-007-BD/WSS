# WSS - Web Security Scanner

Web Attack is a powerful tool designed for web penetration testing and security analysis. It allows users to conduct subdomain discovery to help improve the security posture of websites and web applications.

## Features

- Subdomain Discovery: <br>Automatically discovers subdomains of a target domain to identify potential attack vectors. This feature helps map the digital footprint of a domain, exposing hidden or less-secured services that may be vulnerable to exploitation.<br>
- Admin Site Discovery: <br>Identifies potential admin panels or login portals on a target domain by scanning commonly used admin paths. This helps locate critical entry points that attackers often target, allowing better fortification of these areas.<br>
- Clean Terminal Output: <br>Ensures the terminal is cleared automatically on startup for enhanced readability. This feature makes the tool more user-friendly by providing an uncluttered interface that focuses on the task at hand.<br>
- Cross-platform: <br>Fully compatible with Windows, Linux, and macOS, enabling seamless operation across diverse environments. This ensures accessibility for security professionals regardless of their preferred operating system.<br>
## Installation

### Requirements
- Python 3.x
- Pip (Python package installer)

### Steps

1. Install the necessary libraries:
   ```bash
   $ sudo apt install python3-art
   $ sudo apt install python3-pyfiglet
   ```

2. Clone the repository:
   ```bash
   $ git clone https://github.com/Cyrus-007-BD/WSS.git
   ```
3. Go to WSS directory:
   ```bash
   $ cd WSS
   ```
4. Run the program:
   ```bash
   $ python3 WSS.py -s [Domain] /
   $ python3 WSS.py -a [Domain]
   ```
