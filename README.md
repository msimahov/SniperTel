# 🎯 SniperTel -  OSINT  Tool 🔎

## Overview 📝

**SniperTel** is a powerful and lightweight OSINT (Open-Source Intelligence) reconnaissance tool designed for cybersecurity professionals, penetration testers, and researchers. It gathers intelligence on a target domain or username by performing subdomain enumeration, WHOIS lookups, Shodan scans, email discovery, geolocation, and social media checks.

## Features ⚡

- 🌐 **Domain & Subdomain Enumeration** – Identifies subdomains using a wordlist.
- 🕵️‍♂️ **WHOIS Lookup** – Retrieves domain registration details.
- 📡 **IP Geolocation** – Finds the geographical location of an IP address.
- 🔥 **Shodan Integration** – Scans for open ports and vulnerabilities.
- 📧 **Hunter.io Email Search** – Extracts emails associated with the target domain.
- 📱 **Social Media Scan** – Checks username availability on major platforms.
- 📄 **Multi-format Reporting** – Saves results in JSON, CSV, and HTML.
- 🚀 **Fast & Multi-threaded** – Optimized for quick reconnaissance.

---

## Installation 🛠

### Prerequisites ✅

- 🐍 Python 3.x
- Required Python libraries: `requests`, `whois`, `shodan`, `geocoder`, `tabulate`, `dns.resolver`

### Clone the Repository 📥

```sh
git clone https://github.com/msimahov/SniperTel.git
cd snipertel
```

### Install Dependencies 📦

```sh
pip install -r requirements.txt
```

---

## Usage 🚀

### Basic Usage

Run the tool by providing a target domain or username:

```sh
python snipertel.py -t example.com
```

### Advanced Usage

Using Shodan and Hunter.io API keys for deeper recon:

```sh
python snipertel.py -t example.com --shodan YOUR_SHODAN_API --hunter YOUR_HUNTER_API
```

### Example Output 🖥

```
[*] Starting strong OSINT recon for example.com
[+] IP: 192.168.1.1, Reverse DNS: host.example.com
[+] Geolocation: New York, USA
[+] Found subdomain: www.example.com -> 192.168.1.1
[+] Found 2 emails via Hunter.io
[+] Shodan: 4 open ports found
[+] LinkedIn: Username exists - https://linkedin.com/in/example
[+] Reconnaissance completed
```

---

## Report Formats 📜

SniperTel saves results in multiple formats:

- **JSON** → `osint_example_com.json`
- **CSV** → `osint_example_com.csv`
- **HTML** → `osint_example_com.html`

Example HTML Report Snippet:

```html
<html>
<body>
<h1>OSINT Report for example.com</h1>
<table border="1">
<tr><th>IP Address</th><td>192.168.1.1</td></tr>
<tr><th>Geolocation</th><td>New York, USA</td></tr>
<tr><th>Subdomains</th><td>www.example.com</td></tr>
<tr><th>Emails Found</th><td>admin@example.com</td></tr>
</table>
</body>
</html>
```

---

 
Feel free to fork the repository and submit pull requests. 
