import os
from pathlib import Path
import logging
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

class ProjectCreator:
    def __init__(self):
        self.base_dir = Path.home() / "Project"

    def print_success(self, message):
        print(f"{Fore.GREEN}[+] {message}{Style.RESET_ALL}")

    def print_error(self, message):
        print(f"{Fore.RED}[-] {message}{Style.RESET_ALL}")

    def print_info(self, message):
        print(f"{Fore.BLUE}[*] {message}{Style.RESET_ALL}")

    def create_project(self, project_name):
        """Create project folder structure"""
        try:
            # Create base Project directory if it doesn't exist
            self.base_dir.mkdir(exist_ok=True)
            
            # Define project directory path
            project_dir = self.base_dir / project_name
            
            # Check if project already exists
            if project_dir.exists():
                self.print_error(f"Error: Project '{project_name}' already exists at {project_dir}")
                return False
            
            # Create project directory
            project_dir.mkdir()
            self.print_success(f"Created project directory: {project_dir}")
            
            # Create subdirectories
            subdirs = ['nmap', 'sslyze', 'testssl', 'findings', 'scope', 'dirbruteforce']
            scope_dirs = ['nmap', 'sslyze', 'testssl', 'scope']
            
            for subdir in subdirs:
                subdir_path = project_dir / subdir
                subdir_path.mkdir()
                self.print_success(f"Created subdirectory: {subdir}")
                
                # Create scope.txt in specified directories
                if subdir in scope_dirs:
                    scope_file = subdir_path / "scope.txt"
                    scope_file.touch()
                    self.print_success(f"Created scope file in: {subdir}")
            
            return True

        except Exception as e:
            self.print_error(f"Error creating project structure: {e}")
            return False

def main():
    creator = ProjectCreator()
    project_name = input(f"{Fore.GREEN}Enter project name: {Style.RESET_ALL}").strip()
    
    if not project_name:
        print("Error: Project name cannot be empty")
        return
        
    creator.create_project(project_name)

if __name__ == "__main__":
    main()
