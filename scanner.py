import sys
try:
    import nmap
except ImportError:
    print("ERROR: python-nmap is not installed.")
    print("Install it with: pip3 install python-nmap")
    sys.exit(1)

import socket
import requests
import json
from datetime import datetime

class NetworkScanner:
    def __init__(self, target_network="192.168.1.0/24"): 
        self.scanner = nmap.PortScanner()
        self.target = target_network
        self.results = []

    def discover_hosts(self):
        print(f"[+] ARP scanning {self.target} (WiFi bypass)...")
        self.scanner.scan(self.target, arguments='-sn -PR -T4')  # ARP = sees isolated devices
        return self.scanner.all_hosts()
    
    def scan_ports(self, host):
        ports = {}
        try:
            # Aggressive port scan
            self.scanner.scan(host, '1-1024', arguments='-T4 -sV --max-retries 2 --host-timeout 30s')
            if self.scanner[host].state() == 'up':
                if 'tcp' in self.scanner[host]:
                    ports_data = self.scanner[host]['tcp']
                    for port in ports_data:
                        if ports_data[port]['state'] == 'open':
                            service = ports_data[port].get('name', 'unknown')
                            ports[port] = service
        except Exception as e:
            print(f"  [!] Error scanning {host}: {e}")
        return ports
    
    def check_common_vulns(self, host, ports):
        vulns = []
        # Static risks
        risky = {22: "SSH - Use keys (CVE-2024-6387 RegreSSHion)", 23: "Telnet - Disable!", 80: "HTTP - Check OWASP Top10", 3389: "RDP - Patch EternalBlue CVE-2017-0144"}
        for port in ports:
            if port in risky:
                vulns.append(f"{port}: {risky[port]}")
        
        # REAL NVD API - Fetch top CVEs for service
        services = [ports[port].split()[0] for port in ports]  # e.g., ['http', 'ssh']
        for service in services[:2]:  # Top 2 services
            try:
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={service}"
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    cves = data['vulnerabilities'][:2]  # Top 2 real CVEs
                    cve_details = [vuln['id'] for vuln in cves]
                    vulns.append(f"{service} CVEs: {', '.join(cve_details)}")
            except Exception as e:
                vulns.append(f"NVD: Offline ({str(e)[:50]})")
        
        return vulns
    
    def run_scan(self):
        hosts = self.discover_hosts()
        print(f"[+] Found {len(hosts)} live hosts.")

        for host in hosts:
            try:
                hostname = socket.gethostbyaddr(host)[0]
            except (socket.herror, socket.error):
                hostname = "Unknown"
            ports = self.scan_ports(host)
            vulns = self.check_common_vulns(host, ports)

            result = {
                'host': host,
                'hostname': hostname,
                'open_ports': ports,
                'potential_vulns': vulns,
                'scan_time': datetime.now().strftime("%Y-%m-%d %H:%M")
            }
            self.results.append(result)
            print(f"Host {host}: {len(ports)} open ports | {len(vulns)} risks")

        # Save JSON Report with timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        report_file = f'scan_report_{timestamp}.json'
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=4)
        print(f"[+] Report saved: {report_file}")

if __name__ == "__main__":
    scanner = NetworkScanner("192.168.1.0/24") #UPDATE YOUR SUBNET!
    scanner.run_scan()
    print("Scan complete! Check GitHub for more.")