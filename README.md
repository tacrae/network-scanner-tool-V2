# Network Scanner Tool

A Python-based network security scanner that discovers active hosts on your network, scans for open ports, and identifies potential security vulnerabilities.

## Features

- **ARP-based Host Discovery**: Fast detection of live devices on your network using ARP scanning
- **Port Scanning**: Identifies open ports (1-1024 common ports) with service detection
- **Vulnerability Detection**: Checks for risky services and CVEs
- **JSON Reports**: Generates timestamped scan reports with all findings
- **Cross-platform**: Works on macOS, Linux, and other Unix-like systems

## Requirements

- Python 3.7+
- `nmap` binary (system package)
- Python packages: `python-nmap`, `requests`

## Installation

### 1. Install System Dependencies

#### macOS (Homebrew)
```bash
brew install nmap
```

#### Linux (Ubuntu/Debian)
```bash
sudo apt-get install nmap
```

### 2. Install Python Dependencies

```bash
pip3 install -r requirements.txt
```

Or manually:
```bash
pip3 install python-nmap requests
```

### 3. Verify Installation

```bash
which nmap
nmap --version
```

## Usage

### Basic Scan (Default: 192.168.1.0/24)

```bash
sudo /path/to/.venv/bin/python scanner.py
```

Or if in the project directory:
```bash
sudo python3 scanner.py
```

### Custom Subnet

Edit `scanner.py` line 14 to change the default subnet:
```python
def __init__(self, target_network="YOUR.SUBNET.HERE/24"):
```

Then run the scan.

## How It Works

1. **ARP Discovery**: Scans the target subnet using ARP to quickly identify live hosts
2. **Port Enumeration**: For each live host, scans common ports (1-1024) with service detection
3. **Vulnerability Check**: Identifies risky services (SSH, Telnet, HTTP, RDP) and queries NVD for CVEs
4. **Report Generation**: Saves results to timestamped JSON file (e.g., `scan_report_2026-02-04_18-30-45.json`)

## Output Format

Each scan report is saved as `scan_report_TIMESTAMP.json`:

```json
[
  {
    "host": "192.168.1.XXX",
    "hostname": "Galaxy-XXX",
    "open_ports": {
      "22": "ssh",
      "80": "http"
    },
    "potential_vulns": [
      "22/ssh: SSH - Harden with keys",
      "80/http: HTTP - Scan for vulns"
    ],
    "scan_time": "2026-02-04 18:30"
  },
  ...
]
```

## Permissions

**⚠️ Root/sudo required for ARP scanning on macOS and Linux!**

Nmap's ARP ping requires elevated privileges. Always run with `sudo`:

```bash
sudo python3 scanner.py
```

## Troubleshooting

### Error: "python-nmap is not installed"
```bash
pip3 install python-nmap
```

### Error: "0 live hosts" (but nmap manually finds hosts)
- Make sure you're using `sudo`
- Check subnet is correct (use `ifconfig` to verify)

### Error: "KeyError: 'tcp'"
- Usually means ARP scan completed but individual port scans haven't run yet
- Already fixed in current version with error handling

### macOS firewall blocking scans?
- System Preferences → Security & Privacy → Firewall
- Or create a firewall rule for nmap

## Project Files

- `scanner.py` - Main scanner script
- `requirements.txt` - Python dependencies
- `scan_report_*.json` - Timestamped scan reports
- `README.md` - This file

## Safety & Ethics

⚠️ **Only scan networks you own or have explicit permission to scan.**

Unauthorized network scanning may violate laws and regulations. Always:
- Scan only your own network or authorized systems
- Keep reports confidential
- Follow your local laws and regulations

## Future Improvements

- [ ] Web UI for reports
- [ ] Email notifications
- [ ] Database storage for historical tracking
- [ ] More detailed CVE integration
- [ ] Custom port ranges
- [ ] Export to CSV/HTML formats

## License

MIT
