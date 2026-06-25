# Vuln-Mapper

Vuln-Mapper is a custom-built automated reconnaissance and vulnerability scanning engine designed to identify open ports, extract service banners, and map discovered services to potential CVEs. 

## Features
- **Port Reconnaissance:** Rapidly scans target infrastructure for open ports (21, 22, 80, 443, 8000).
- **Banner Grabbing:** Extracts software and version information from open services.
- **Vulnerability Mapping:** Integrates with the NVD API to check for known CVEs.
- **Directory Fuzzer:** Automatically hunts for sensitive hidden directories (`/admin`, `/config`, etc.).
- **Modern Dashboard:** A clean, dark-mode UI built with Tailwind CSS.

## Getting Started
1. Clone the repository.
2. Install dependencies: `pip install -r requirements.txt`
3. Run the backend: `uvicorn main:app --reload`
4. Access the dashboard at `http://127.0.0.1:8000`

## Disclaimer
This tool is for educational purposes and authorized security testing only. Use on targets you own or have explicit permission to scan.
