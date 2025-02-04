import os
import sys
import subprocess
import time
from pathlib import Path
import logging
from colorama import init, Fore, Style
from datetime import datetime
import threading
import queue
import psutil
import socket

# Initialize colorama
init(autoreset=True)

class ServiceScanner:
    def __init__(self):
        self.base_dir = Path.home() / "Project"
        self.project_dir = None
        self.nmap_dir = None
        self.findings_dir = None
        self.service_scan_dir = None
        self.active_scans = {}
        self.max_sessions = 0
        self.completed_scans = 0
        self.total_scans = 0
        self.lock = threading.Lock()
        self.failed_scans = set()
        self.scan_queue = queue.Queue()
        self.scan_complete = threading.Event()
        self.display_lock = threading.Lock()

    def print_success(self, message):
        with self.lock:
            print(f"{Fore.GREEN}[+] {message}{Style.RESET_ALL}")
            if hasattr(self, 'logger'):
                self.logger.info(message)

    def print_error(self, message):
        with self.lock:
            print(f"{Fore.RED}[-] {message}{Style.RESET_ALL}")
            if hasattr(self, 'logger'):
                self.logger.error(message)

    def print_info(self, message):
        with self.lock:
            print(f"{Fore.BLUE}[*] {message}{Style.RESET_ALL}")
            if hasattr(self, 'logger'):
                self.logger.info(message)

    def update_progress(self):
        """Print current progress to console"""
        with self.display_lock:
            print("\033[2J\033[H")  # Clear screen
            print(f"{Fore.CYAN}Service Scan Progress ({self.completed_scans}/{self.total_scans}):{Style.RESET_ALL}")
            print("="*50)
            
            if self.active_scans:
                print(f"\n{Fore.YELLOW}Active Scans:{Style.RESET_ALL}")
                for ip, info in self.active_scans.items():
                    elapsed = time.time() - info['start_time']
                    print(f"IP: {ip} | Progress: {info['progress']}% | Time: {int(elapsed)}s")
            
            if self.failed_scans:
                print(f"\n{Fore.RED}Failed Scans:{Style.RESET_ALL}")
                for ip in sorted(self.failed_scans):
                    print(f"- {ip}")
            
            print(f"\n{Fore.BLUE}System Usage:{Style.RESET_ALL}")
            print(f"CPU: {psutil.cpu_percent()}% | RAM: {psutil.virtual_memory().percent}%")
            print("\n" + "="*50)
            sys.stdout.flush()

    def setup_logging(self):
        """Setup logging configuration"""
        log_file = self.nmap_dir / "service_scan.log"
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
                    self.service_scan_dir.mkdir(exist_ok=True)
                    self.setup_logging()
                    self.print_success(f"Selected project: {self.project_dir.name}")
                    break
                else:
                    self.print_error("Invalid project number!")
            except ValueError:
                self.print_error("Please enter a valid number!")

    def kill_session(self, session_name):
        """Safely kill a tmux session"""
        try:
            subprocess.run(['tmux', 'kill-session', '-t', session_name], 
                         stdout=subprocess.DEVNULL, 
                         stderr=subprocess.DEVNULL)
        except:
            pass

    def setup_tmux_session(self, ip):
        """Create new tmux session for scanning"""
        safe_ip = ip.replace('.', '_').replace('/', '_')
        session_name = f"scan_{safe_ip}"
        
        try:
            self.kill_session(session_name)
            result = subprocess.run(['tmux', 'new-session', '-d', '-s', session_name],
                                 stdout=subprocess.DEVNULL,
                                 stderr=subprocess.PIPE)
            
            if result.returncode != 0:
                raise Exception(f"Failed to create session: {result.stderr.decode()}")
                
            self.print_info(f"Created tmux session: {session_name}")
            return session_name

        except Exception as e:
            self.print_error(f"Error creating session for {ip}: {str(e)}")
            return None

    def read_targets(self):
        """Read targets from ip_port_list.txt files"""
        targets = []
        
        # Read main ip_port_list.txt
        main_list = self.findings_dir / "ip_port_list.txt"
        if main_list.exists():
            with open(main_list, 'r') as f:
                for line in f:
                    if ':' in line:
                        ip, ports = line.strip().split(':')
                        targets.append((ip, ports, None))  # None indicates no subnet

        # Read subnet ip_port_list.txt files
        for subnet_dir in self.findings_dir.iterdir():
            if subnet_dir.is_dir():
                subnet_list = subnet_dir / "ip_port_list.txt"
                if subnet_list.exists():
                    with open(subnet_list, 'r') as f:
                        for line in f:
                            if ':' in line:
                                ip, ports = line.strip().split(':')
                                targets.append((ip, ports, subnet_dir.name))

        return targets

    def run_single_scan(self, ip, ports, subnet=None):
        """Execute a single service scan"""
        session_name = self.setup_tmux_session(ip)
        if not session_name:
            return False

        try:
            with self.lock:
                self.active_scans[ip] = {
                    'session': session_name,
                    'start_time': time.time(),
                    'progress': 0
                }

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            if subnet:
                output_dir = self.service_scan_dir / subnet
                output_dir.mkdir(exist_ok=True)
            else:
                output_dir = self.service_scan_dir

            output_base = output_dir / f"{ip}_{timestamp}"
            
            cmd = f"nmap -v -p{ports} -sSCV -A {ip} -oN {output_base}.nmap -oG {output_base}.gnmap"
            subprocess.run(['tmux', 'send-keys', '-t', session_name, cmd, 'C-m'],
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)

            while True:
                time.sleep(1)
                result = subprocess.run(['tmux', 'capture-pane', '-pt', session_name],
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,
                                     text=True)
                
                output = result.stdout

                if "Completed" in output:
                    try:
                        progress = int(output.split("Completed")[1].split("%")[0].strip())
                        with self.lock:
                            if ip in self.active_scans:
                                self.active_scans[ip]['progress'] = progress
                                self.update_progress()
                    except:
                        pass

                if "Nmap done" in output:
                    with self.lock:
                        if ip in self.active_scans:
                            del self.active_scans[ip]
                        self.completed_scans += 1
                        self.update_progress()
                    self.kill_session(session_name)
                    self.print_success(f"Service scan completed for {ip}")
                    return True

        except Exception as e:
            self.print_error(f"Error scanning {ip}: {str(e)}")
            with self.lock:
                self.failed_scans.add(ip)
                if ip in self.active_scans:
                    del self.active_scans[ip]
                self.completed_scans += 1
                self.update_progress()
            self.kill_session(session_name)
            return False

    def scan_worker(self):
        """Worker function to process scan queue"""
        while not self.scan_complete.is_set() or not self.scan_queue.empty():
            try:
                ip, ports, subnet = self.scan_queue.get(timeout=1)
                self.run_single_scan(ip, ports, subnet)
                self.scan_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                self.print_error(f"Worker error: {str(e)}")
                continue

    def process_targets(self):
        """Process and scan targets"""
        while True:
            try:
                self.max_sessions = int(input(f"{Fore.GREEN}Enter number of concurrent sessions: {Style.RESET_ALL}"))
                if self.max_sessions > 0:
                    break
                self.print_error("Please enter a positive number")
            except ValueError:
                self.print_error("Please enter a valid number")

        # Read targets
        targets = self.read_targets()
        if not targets:
            self.print_error("No targets found in ip_port_list.txt files")
            return

        self.total_scans = len(targets)
        self.print_info(f"Starting service scan of {self.total_scans} targets")

        # Add targets to queue
        for target in targets:
            self.scan_queue.put(target)

        # Start worker threads
        workers = []
        for _ in range(self.max_sessions):
            worker = threading.Thread(target=self.scan_worker)
            worker.daemon = True
            worker.start()
            workers.append(worker)

        try:
            self.scan_queue.join()
            self.scan_complete.set()
            
            for worker in workers:
                worker.join(timeout=1)

        except KeyboardInterrupt:
            self.print_info("\nStopping scans gracefully...")
            self.scan_complete.set()
            
            # Kill remaining tmux sessions
            for ip, info in self.active_scans.items():
                self.kill_session(info['session'])
        
        finally:
            self.print_info("\nScan Summary:")
            self.print_info(f"Total targets: {self.total_scans}")
            self.print_info(f"Completed: {self.completed_scans}")
            if self.failed_scans:
                self.print_error(f"Failed scans: {len(self.failed_scans)}")
                for ip in sorted(self.failed_scans):
                    self.print_error(f"- {ip}")

def main():
    scanner = ServiceScanner()
    scanner.select_project()
    scanner.process_targets()

if __name__ == "__main__":
    main()