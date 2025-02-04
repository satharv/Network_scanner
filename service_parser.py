import os
import re
import sys
from pathlib import Path
import logging
from colorama import init, Fore, Style
from datetime import datetime

# Initialize colorama
init(autoreset=True)

class ServiceParser:
    def __init__(self):
        self.base_dir = Path.home() / "Project"
        self.project_dir = None
        self.nmap_dir = None
        self.findings_dir = None
        self.service_scan_dir = None
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def print_success(self, message):
        print(f"{Fore.GREEN}[+] {message}{Style.RESET_ALL}")
        if hasattr(self, 'logger'):
            self.logger.info(message)

    def print_error(self, message):
        print(f"{Fore.RED}[-] {message}{Style.RESET_ALL}")
        if hasattr(self, 'logger'):
            self.logger.error(message)

    def print_info(self, message):
        print(f"{Fore.BLUE}[*] {message}{Style.RESET_ALL}")
        if hasattr(self, 'logger'):
            self.logger.info(message)

    def setup_logging(self):
        """Setup logging configuration"""
        log_file = self.nmap_dir / "service_parser.log"
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging

    def select_project(self):
        """List and select available projects"""
        if not self.base_dir.exists():
            self.print_error(f"Project directory not found: {self.base_dir}")
            sys.exit(1)

        projects = [d for d in self.base_dir.iterdir() if d.is_dir()]
        
        if not projects:
            self.print_error("No projects found!")
            sys.exit(1)

        print(f"\n{Fore.CYAN}Available Projects:{Style.RESET_ALL}")
        for idx, project in enumerate(projects, 1):
            print(f"{Fore.YELLOW}{idx}.{Style.RESET_ALL} {project.name}")

        while True:
            try:
                choice = input(f"\n{Fore.GREEN}Enter project number:{Style.RESET_ALL} ")
                project_idx = int(choice) - 1
                if 0 <= project_idx < len(projects):
                    self.project_dir = projects[project_idx]
                    self.nmap_dir = self.project_dir / "nmap"
                    self.findings_dir = self.project_dir / "findings"
                    self.service_scan_dir = self.nmap_dir / "service_scan"
                    self.setup_logging()
                    self.print_success(f"Selected project: {self.project_dir.name}")
                    break
                else:
                    self.print_error("Invalid project number!")
            except ValueError:
                self.print_error("Please enter a valid number!")

    def parse_gnmap_file(self, gnmap_file):
        """Parse .gnmap file for services"""
        ssh_ips = set()
        http_ips = set()
        https_ips = set()
        
        try:
            with open(gnmap_file, 'r') as f:
                for line in f:
                    if 'Host:' not in line:
                        continue
                        
                    # Extract IP address
                    ip_match = re.search(r'Host: (\d+\.\d+\.\d+\.\d+)', line)
                    if not ip_match:
                        continue
                        
                    ip = ip_match.group(1)
                    
                    # Extract ports section
                    ports_section = re.search(r'Ports: (.*?)\t', line)
                    if not ports_section:
                        continue
                        
                    ports_info = ports_section.group(1)
                    
                    # Process each port
                    for port_info in ports_info.split(','):
                        if 'open' not in port_info:
                            continue
                            
                        service_info = port_info.lower()
                        
                        # Check for SSH
                        if 'ssh' in service_info:
                            ssh_ips.add(ip)
                            
                        # Check for HTTP/HTTPS
                        if any(s in service_info for s in ['http', 'apache', 'nginx', 'web']):
                            if 'ssl' in service_info or 'https' in service_info:
                                https_ips.add(ip)
                            else:
                                http_ips.add(ip)
            
            self.print_info(f"Found in {gnmap_file}:")
            self.print_info(f"SSH IPs: {len(ssh_ips)}")
            self.print_info(f"HTTP IPs: {len(http_ips)}")
            self.print_info(f"HTTPS IPs: {len(https_ips)}")
            
            return ssh_ips, http_ips, https_ips

        except Exception as e:
            self.print_error(f"Error processing {gnmap_file}: {str(e)}")
            return set(), set(), set()

    def write_service_file(self, ips, filename, directory):
        """Write IPs to service file"""
        if not ips:
            self.print_info(f"No IPs found for {filename}")
            return
            
        filepath = directory / f"{filename}_{self.timestamp}.txt"
        try:
            directory.mkdir(parents=True, exist_ok=True)
            with open(filepath, 'w') as f:
                for ip in sorted(ips):
                    f.write(f"{ip}\n")
            self.print_success(f"Created {filepath} with {len(ips)} IPs")
        except Exception as e:
            self.print_error(f"Error writing to {filepath}: {str(e)}")

    def process_directory(self, scan_dir, output_dir):
        """Process all gnmap files in a directory"""
        all_ssh_ips = set()
        all_http_ips = set()
        all_https_ips = set()

        gnmap_files = list(scan_dir.glob("*.gnmap"))
        if not gnmap_files:
            self.print_error(f"No .gnmap files found in {scan_dir}")
            return

        for gnmap_file in gnmap_files:
            self.print_info(f"Processing: {gnmap_file}")
            ssh_ips, http_ips, https_ips = self.parse_gnmap_file(gnmap_file)
            all_ssh_ips.update(ssh_ips)
            all_http_ips.update(http_ips)
            all_https_ips.update(https_ips)

        # Write results
        self.write_service_file(all_ssh_ips, "ssh_hosts", output_dir)
        self.write_service_file(all_http_ips, "http_hosts", output_dir)
        self.write_service_file(all_https_ips, "https_hosts", output_dir)

    def process_scans(self):
        """Process all service scan results"""
        if not self.service_scan_dir.exists():
            self.print_error(f"Service scan directory not found: {self.service_scan_dir}")
            return

        # Process main directory
        self.print_info(f"Processing main directory: {self.service_scan_dir}")
        self.process_directory(self.service_scan_dir, self.findings_dir)

        # Process subnet directories
        for subnet_dir in self.service_scan_dir.iterdir():
            if subnet_dir.is_dir():
                self.print_info(f"Processing subnet: {subnet_dir.name}")
                subnet_findings_dir = self.findings_dir / subnet_dir.name
                self.process_directory(subnet_dir, subnet_findings_dir)

def main():
    parser = ServiceParser()
    parser.select_project()
    parser.process_scans()

if __name__ == "__main__":
    main()