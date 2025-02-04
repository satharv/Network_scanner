# 🌐 Automated Network Reconnaissance Tool

[![Python](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org/)
[![Nmap](https://img.shields.io/badge/Nmap-Required-orange.svg)](https://nmap.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A comprehensive automated network scanning toolkit that orchestrates multiple scanning phases for thorough reconnaissance. This tool automates and streamlines the process of network scanning, port discovery, and service enumeration.

## 🚀 Features

- **Automated Workflow**: Seamlessly runs all scanning phases in sequence
- **Concurrent Scanning**: Utilizes tmux for parallel scan execution
- **Organized Output**: Structured output directory for each project
- **Service Detection**: Comprehensive service version detection
- **Progress Tracking**: Real-time scan progress and status updates
- **Error Handling**: Robust error management and logging

## 📋 Prerequisites

- Python 3.x
- Nmap
- tmux
- Required Python packages:
  ```
  colorama
  psutil
  ```

## 🛠️ Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/network-recon-tool.git
   ```

2. Install required packages:
   ```bash
   pip3 install -r requirements.txt
   ```

3. Ensure Nmap and tmux are installed:
   ```bash
   sudo apt install nmap tmux
   ```

## 📁 Project Structure

```
/home/<user>/Project/
├── project_name/
│   ├── nmap/
│   │   ├── output/
│   │   ├── service_scan/
│   │   └── scope.txt
│   ├── findings/
│   ├── sslyze/
│   ├── testssl/
│   ├── dirbruteforce/
│   └── scope/
```

## 🔧 Usage

1. Run the main script:
   ```bash
   python3 main_scanner.py
   ```

2. Enter project details:
   - Choose to create new project or select existing one
   - Set number of concurrent scan sessions

3. Add targets to scope:
   - Add IPs/domains to `scope.txt` in the project's nmap directory
   - Supports individual IPs, subnets, and domain names

4. The tool will automatically:
   - Run full port scans
   - Extract open ports
   - Perform service detection
   - Generate organized reports

## 📊 Scanning Phases

1. **Project Setup**
   - Creates organized directory structure
   - Prepares logging and output directories

2. **Port Discovery**
   - Full port scan (1-65535)
   - Parallel scanning with tmux sessions
   - Progress tracking and error handling

3. **Port Extraction**
   - Processes scan results
   - Creates structured port lists
   - Organizes by subnets if applicable

4. **Service Scanning**
   - Detailed service version detection
   - OS fingerprinting
   - Script scanning for detected services

5. **Service Parsing**
   - Categorizes discovered services
   - Generates service-specific target lists
   - Creates summary reports

## 📝 Logging

- Detailed logs for each scanning phase
- Error tracking and reporting
- Progress monitoring
- Scan summaries and statistics

## ⚠️ Important Notes

- Ensure you have proper authorization before scanning any networks
- Some scans might require root privileges
- Be cautious with concurrent session numbers to avoid system overload
- Always comply with target network's security policies

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests.

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

## 👤 Author

Your Name
- GitHub: [@yourusername](https://github.com/yourusername)
- LinkedIn: [Your Name](https://linkedin.com/in/yourprofile)
