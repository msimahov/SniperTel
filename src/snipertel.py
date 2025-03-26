import whois
import socket
import requests
import json
import os
import dns.resolver
import threading
import shodan
import geocoder
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from tabulate import tabulate
import argparse


class StrongOSINTReconTool:
    def __init__(self, target, shodan_api_key=None, hunter_api_key=None, output_dir="osint_results"):
        self.target = target
        self.shodan_api_key = shodan_api_key or os.getenv("Shodan API key")
        self.hunter_api_key = hunter_api_key or os.getenv("Hunter.io API key")
        self.output_dir = output_dir
        self.results = {}
        self.lock = threading.Lock()

        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def resolve_ip(self):
        """Resolve IP address and perform reverse DNS."""
        try:
            ip = socket.gethostbyname(self.target)
            self.results["IP Address"] = ip
            hostname = socket.gethostbyaddr(ip)[0]
            self.results["Reverse DNS"] = hostname
            print(f"[+] IP: {ip}, Reverse DNS: {hostname}")
            self.geolocate_ip(ip)
        except Exception as e:
            self.results["IP Address"] = f"Error: {str(e)}"
            print(f"[-] IP resolution failed: {str(e)}")

    def geolocate_ip(self, ip):
        """Geolocate the IP address."""
        try:
            g = geocoder.ip(ip)
            self.results["Geolocation"] = {
                "City": g.city,
                "Country": g.country,
                "Coordinates": g.latlng
            }
            print(f"[+] Geolocation: {g.city}, {g.country}")
        except Exception as e:
            print(f"[-] Geolocation failed: {str(e)}")

    def whois_lookup(self):
        """Perform WHOIS lookup."""
        try:
            w = whois.whois(self.target)
            self.results["WHOIS"] = {
                "Domain": w.domain_name,
                "Registrar": w.registrar,
                "Creation Date": str(w.creation_date),
                "Expiration Date": str(w.expiration_date),
                "Name Servers": w.name_servers
            }
            print("[+] WHOIS Lookup completed")
        except Exception as e:
            self.results["WHOIS"] = f"Error: {str(e)}"
            print(f"[-] WHOIS Lookup failed: {str(e)}")

    def subdomain_enum(self, wordlist=None):
        """Enumerate subdomains using DNS resolution."""
        if wordlist is None:
            wordlist = ["www", "mail", "ftp", "dev", "test", "api"]  # Small default list
        subdomains = []

        def check_subdomain(sub):
            try:
                subdomain = f"{sub}.{self.target}"
                answers = dns.resolver.resolve(subdomain, "A")
                for rdata in answers:
                    with self.lock:
                        subdomains.append((subdomain, str(rdata)))
                        print(f"[+] Found subdomain: {subdomain} -> {rdata}")
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(check_subdomain, wordlist)

        self.results["Subdomains"] = subdomains

    def shodan_scan(self):
        """Scan IP with Shodan."""
        if not self.shodan_api_key:
            print("[-] Shodan API key not provided")
            return

        try:
            api = shodan.Shodan(self.shodan_api_key)
            ip = self.results.get("IP Address", "")
            if "Error" not in ip:
                data = api.host(ip)
                self.results["Shodan"] = {
                    "OS": data.get("os"),
                    "Ports": data.get("ports"),
                    "Vulnerabilities": data.get("vulns", [])
                }
                print(f"[+] Shodan: {len(data.get('ports', []))} open ports found")
        except Exception as e:
            self.results["Shodan"] = f"Error: {str(e)}"
            print(f"[-] Shodan scan failed: {str(e)}")

    def hunter_email_search(self):
        """Search for emails associated with the domain using Hunter.io."""
        if not self.hunter_api_key:
            print("[-] Hunter API key not provided")
            return

        url = f"https://api.hunter.io/v2/domain-search?domain={self.target}&api_key={self.hunter_api_key}"
        try:
            response = requests.get(url, timeout=10)
            data = response.json()
            emails = data.get("data", {}).get("emails", [])
            self.results["Emails"] = [email["value"] for email in emails]
            print(f"[+] Found {len(emails)} emails via Hunter.io")
        except Exception as e:
            self.results["Emails"] = f"Error: {str(e)}"
            print(f"[-] Hunter email search failed: {str(e)}")

    def check_social_media(self, platforms=None):
        """Check username availability on social media with multithreading."""
        if platforms is None:
            platforms = ["twitter", "instagram", "github", "linkedin", "facebook"]

        self.results["Social Media"] = {}
        base_urls = {
            "twitter": "https://twitter.com/",
            "instagram": "https://instagram.com/",
            "github": "https://github.com/",
            "linkedin": "https://linkedin.com/in/",
            "facebook": "https://facebook.com/"
        }

        def check_platform(platform):
            url = f"{base_urls.get(platform)}{self.target}"
            try:
                response = requests.get(url, timeout=5)
                with self.lock:
                    if response.status_code == 200:
                        self.results["Social Media"][platform] = f"Found: {url}"
                        print(f"[+] {platform}: Username exists - {url}")
                    else:
                        self.results["Social Media"][platform] = "Not found"
            except requests.RequestException:
                with self.lock:
                    self.results["Social Media"][platform] = "Error checking"

        with ThreadPoolExecutor(max_workers=5) as executor:
            executor.map(check_platform, platforms)

    def save_results(self, format="json"):
        """Save results in JSON, CSV, or HTML."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"{self.output_dir}/osint_{self.target}_{timestamp}"

        if format == "json":
            with open(f"{base_name}.json", "w") as f:
                json.dump(self.results, f, indent=4)
            print(f"[+] Saved to {base_name}.json")

        elif format == "csv":
            with open(f"{base_name}.csv", "w") as f:
                for key, value in self.results.items():
                    if isinstance(value, list):
                        f.write(f"{key},{','.join(map(str, value))}\n")
                    elif isinstance(value, dict):
                        for subkey, subval in value.items():
                            f.write(f"{key}_{subkey},{subval}\n")
                    else:
                        f.write(f"{key},{value}\n")
            print(f"[+] Saved to {base_name}.csv")

        elif format == "html":
            html = "<html><body><h1>OSINT Report</h1><table border='1'>"
            for key, value in self.results.items():
                html += f"<tr><th>{key}</th><td>{json.dumps(value, indent=2)}</td></tr>"
            html += "</table></body></html>"
            with open(f"{base_name}.html", "w") as f:
                f.write(html)
            print(f"[+] Saved to {base_name}.html")

    def run(self):
        """Run all reconnaissance tasks."""
        print(f"[*] Starting strong OSINT recon for {self.target}")
        threads = [
            threading.Thread(target=self.resolve_ip),
            threading.Thread(target=self.whois_lookup) if "." in self.target else None,
            threading.Thread(target=self.subdomain_enum),
            threading.Thread(target=self.shodan_scan),
            threading.Thread(target=self.hunter_email_search),
            threading.Thread(target=self.check_social_media)
        ]

        for t in threads:
            if t:
                t.start()
        for t in threads:
            if t:
                t.join()

        self.save_results("json")
        self.save_results("html")
        print("[*] Reconnaissance completed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OSINT  Tool")
    parser.add_argument("-t", "--target", required=True, help="Target domain or username")
    parser.add_argument("--shodan", help="Shodan API key")
    parser.add_argument("--hunter", help="Hunter.io API key")
    args = parser.parse_args()

    tool = StrongOSINTReconTool(args.target, args.shodan, args.hunter)
    tool.run()