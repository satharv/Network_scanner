import os
import re
import sys
from pathlib import Path
import logging
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

class PortScraper:
    def __init__(self):
        self.base_dir = Path.home() / "Project"
        self.project_dir = None
        self.nmap_dir = None
        self.findings_dir = None

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
        log_file = self.nmap_dir / "port_scraper.log"
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
                    self.setup_logging()
                    self.print_success(f"Selected project: {self.project_dir.name}")
                    break
                else:
                    self.print_error("Invalid project number!")
            except ValueError:
                self.print_error("Please enter a valid number!")

    def parse_gnmap_file(self, gnmap_file):
        """Parse .gnmap file and extract IP and open ports"""
        try:
            with open(gnmap_file, 'r') as f:
                content = f.read()
                if not content.strip():
                    self.print_error(f"Empty file: {gnmap_file}")
                    return None

            # Find all host entries with open ports
            ip_port_dict = {}
            host_entries = re.finditer(r'Host: (\d+\.\d+\.\d+\.\d+).*?Ports: (.*?)(?=\n|\Z)', content, re.DOTALL)
            
            for entry in host_entries:
                ip = entry.group(1)
                ports_info = entry.group(2)
                
                # Extract open ports
                open_ports = []
                for port_info in ports_info.split(','):
                    if 'open' in port_info:
                        port = port_info.strip().split('/')[0]
                        try:
                            open_ports.append(int(port))
                        except ValueError:
                            self.print_error(f"Invalid port number in {gnmap_file}")
                
                if open_ports:  # Only include IPs with open ports
                    ip_port_dict[ip] = sorted(open_ports)
            
            return ip_port_dict

        except Exception as e:
            self.print_error(f"Error processing {gnmap_file}: {str(e)}")
            return None

    def write_results(self, results, output_file):
        """Write results to output file"""
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            for ip, ports in sorted(results.items()):
                ports_str = ','.join(map(str, ports))
                line = f"{ip}:{ports_str}\n"
                f.write(line)
                print(f"{Fore.CYAN}{line.strip()}{Style.RESET_ALL}")

    def process_files(self):
        """Process all .gnmap files in the project"""
        nmap_output_dir = self.nmap_dir / "output"
        
        if not nmap_output_dir.exists():
            self.print_error(f"Nmap output directory not found: {nmap_output_dir}")
            return

        # Process files in main output directory
        main_results = {}
        for gnmap_file in nmap_output_dir.glob("*.gnmap"):
            self.print_info(f"Processing file: {gnmap_file.name}")
            result = self.parse_gnmap_file(gnmap_file)
            if result:
                main_results.update(result)

        # Write main results if any
        if main_results:
            output_file = self.findings_dir / "ip_port_list.txt"
            self.print_info(f"Writing main results to: {output_file}")
            self.write_results(main_results, output_file)

        # Process subnet directories
        for subnet_dir in nmap_output_dir.iterdir():
            if subnet_dir.is_dir():
                subnet_results = {}
                self.print_info(f"Processing subnet directory: {subnet_dir.name}")
                
                for gnmap_file in subnet_dir.glob("*.gnmap"):
                    self.print_info(f"Processing file: {gnmap_file.name}")
                    result = self.parse_gnmap_file(gnmap_file)
                    if result:
                        subnet_results.update(result)

                # Write subnet results if any
                if subnet_results:
                    subnet_output_dir = self.findings_dir / subnet_dir.name
                    output_file = subnet_output_dir / "ip_port_list.txt"
                    self.print_info(f"Writing subnet results to: {output_file}")
                    self.write_results(subnet_results, output_file)

def main():
    scraper = PortScraper()
    scraper.select_project()
    scraper.process_files()

if __name__ == "__main__":
    main()