import socket
import sys
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from datetime import datetime

# Global variable to hold our log file path
REPORT_FILE = "scan_report.txt"

# Helper function to print to screen AND write to the file at the same time
def log(text):
    print(text)
    with open(REPORT_FILE, "a", encoding="utf-8") as f:
        f.write(text + "\n")

# ==========================================
# PART 1: NETWORK PORT SCANNER
# ==========================================
def scan_network_ports(target_host, ports_to_scan=[21, 22, 23, 25, 80, 443, 8080]):
    log(f"\n[*] Starting Network Port Scan on {target_host}...")
    try:
        target_ip = socket.gethostbyname(target_host)
    except socket.gaierror:
        log(f"[-] Error: Could not resolve hostname {target_host}")
        return

    for port in ports_to_scan:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            log(f"[!] PORT {port} is OPEN.")
        sock.close()

# ==========================================
# PART 2: WEB SECURITY SCANNER
# ==========================================
class WebScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.expected_headers = [
            "X-Frame-Options", 
            "Content-Security-Policy", 
            "X-Content-Type-Options",
            "Strict-Transport-Security"
        ]
        self.sqli_payload = "' OR '1'='1"
        self.xss_payload = "<script>alert('XSS')</script>"

    def check_security_headers(self):
        log(f"\n[*] Checking HTTP Security Headers for {self.target_url}...")
        try:
            response = self.session.get(self.target_url, timeout=5)
            headers = response.headers
            
            for header in self.expected_headers:
                if header not in headers:
                    log(f"[!] Missing Header: {header} (Increases risk of Clickjacking/XSS)")
                else:
                    log(f"[+] Present: {header}")
        except requests.exceptions.RequestException as e:
            log(f"[-] Connection Error: {e}")

    def get_all_forms(self, url):
        try:
            response = self.session.get(url, timeout=5)
            soup = BeautifulSoup(response.content, "html.parser")
            return soup.find_all("form")
        except Exception:
            return []

    def scan_web_forms(self):
        log(f"\n[*] Scanning forms on {self.target_url} for SQLi and XSS...")
        forms = self.get_all_forms(self.target_url)
        log(f"[+] Found {len(forms)} form(s) to test.")

        for i, form in enumerate(forms):
            action = form.attrs.get("action")
            post_url = urljoin(self.target_url, action)
            method = form.attrs.get("method", "get").lower()
            
            inputs = []
            for input_tag in form.find_all("input"):
                input_name = input_tag.attrs.get("name")
                input_type = input_tag.attrs.get("type", "text")
                if input_name:
                    inputs.append({"name": input_name, "type": input_type})

            if not inputs:
                continue

            # Set up payloads
            sqli_data = {}
            xss_data = {}
            for input_field in inputs:
                if input_field["type"] in ["text", "search", "password"]:
                    sqli_data[input_field["name"]] = self.sqli_payload
                    xss_data[input_field["name"]] = self.xss_payload

            try:
                if method == "post":
                    sqli_res = self.session.post(post_url, data=sqli_data, timeout=5)
                    xss_res = self.session.post(post_url, data=xss_data, timeout=5)
                else:
                    sqli_res = self.session.get(post_url, params=sqli_data, timeout=5)
                    xss_res = self.session.get(post_url, params=xss_data, timeout=5)

                # Check SQLi
                sqli_errors = ["you have an error in your sql syntax", "warning: mysql_fetch", "unclosed quotation mark"]
                for error in sqli_errors:
                    if error in sqli_res.text.lower():
                        log(f"[!] VULNERABILITY DETECTED: Potential SQL Injection on Form #{i+1} ({post_url})")
                        break

                # Check XSS
                if self.xss_payload in xss_res.text:
                    log(f"[!] VULNERABILITY DETECTED: Potential Reflected XSS on Form #{i+1} ({post_url})")

            except requests.exceptions.RequestException:
                log(f"[-] Failed to test Form #{i+1} due to network timeout/error.")

# ==========================================
# MAIN EXECUTION INTERFACE
# ==========================================
if __name__ == "__main__":
    # Clear out old report from previous runs
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        f.write(f"VULNERABILITY SCAN REPORT\n")
        f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=============================================\n")

    log("=============================================")
    log("        Simple Security Scanner Script       ")
    log("=============================================")
    
    host_target = input("Enter target domain or IP (e.g., scanme.nmap.org): ").strip()
    web_target = input("Enter target URL for web scan (e.g., http://vulnweb.com): ").strip()

    if not host_target or not web_target:
        log("[-] Target inputs cannot be blank. Exiting.")
        sys.exit(1)

    log(f"Target Domain: {host_target}")
    log(f"Target URL: {web_target}")

    # 1. Run Port Scan
    scan_network_ports(host_target)

    # 2. Run Web App Vulnerability Scan
    scanner = WebScanner(web_target)
    scanner.check_security_headers()
    scanner.scan_web_forms()
    
    log("\n[*] Scan process complete.")
    log(f"[+] All findings have been saved to your project folder in '{REPORT_FILE}'")
