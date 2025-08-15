# Information Gathering - Web Edition Cheat Sheet

Web reconnaissance is the first step in any security assessment or penetration testing engagement. It's akin to a detective's initial investigation, meticulously gathering clues and evidence about a target before formulating a plan of action. In the digital realm, this translates to accumulating information about a website or web application to identify potential vulnerabilities, security misconfigurations, and valuable assets.

## Goals of Web Reconnaissance
The primary goals of web reconnaissance revolve around gaining a comprehensive understanding of the target's digital footprint. This includes:

- **Identifying Assets**: Discovering all associated domains, subdomains, and IP addresses provides a map of the target's online presence.
- **Uncovering Hidden Information**: Web reconnaissance aims to uncover directories, files, and technologies that are not readily apparent and could serve as entry points for an attacker.
- **Analyzing the Attack Surface**: By identifying open ports, running services, and software versions, you can assess the potential vulnerabilities and weaknesses of the target.
- **Gathering Intelligence**: Collecting information about employees, email addresses, and technologies used can aid in social engineering attacks or identifying specific vulnerabilities associated with certain software.

## Reconnaissance Types
| Type | Description | Risk of Detection | Examples |
|------|-------------|-------------------|----------|
| Active Reconnaissance | Involves directly interacting with the target system, such as sending probes or requests. | Higher | Port scanning, vulnerability scanning, network mapping |
| Passive Reconnaissance | Gathers information without directly interacting with the target, relying on publicly available data. | Lower | Search engine queries, WHOIS lookups, DNS enumeration, web archive analysis, social media |

## WHOIS
WHOIS is a query and response protocol used to retrieve information about domain names, IP addresses, and other internet resources. It's essentially a directory service that details who owns a domain, when it was registered, contact information, and more. In the context of web reconnaissance, WHOIS lookups can be a valuable source of information, potentially revealing the identity of the website owner, their contact information, and other details that could be used for further investigation or social engineering attacks.

For example, to find out who owns the domain example.com:
```bash
whois example.com
```
**Note**: WHOIS data can be inaccurate or intentionally obscured, so verify from multiple sources. Privacy services may mask the true owner.

## DNS
The Domain Name System (DNS) functions as the internet's GPS, translating user-friendly domain names into numerical IP addresses. DNS ensures your browser reaches the correct website by matching its name with its IP address.

The `dig` command queries DNS servers directly. For example, to find the IP address for example.com:
```bash
dig example.com A
```
This retrieves the A record (hostname to IPv4 address). The output includes the IP address and query details.

### DNS Record Types
| Record Type | Description |
|-------------|-------------|
| A | Maps a hostname to an IPv4 address. |
| AAAA | Maps a hostname to an IPv6 address. |
| CNAME | Creates an alias for a hostname, pointing it to another hostname. |
| MX | Specifies mail servers responsible for handling email for the domain. |
| NS | Delegates a DNS zone to a specific authoritative name server. |
| TXT | Stores arbitrary text information. |
| SOA | Contains administrative information about a DNS zone. |

## Subdomains
Subdomains are extensions of a primary domain name, used to organize sections or services (e.g., `mail.example.com`, `blog.example.com`). They can expose additional attack surfaces or hidden services.

### Subdomain Enumeration Approaches
| Approach | Description | Examples |
|----------|-------------|----------|
| Active Enumeration | Directly interacts with the target's DNS servers or uses tools to probe for subdomains. | Brute-forcing, DNS zone transfers |
| Passive Enumeration | Collects information without direct interaction, relying on public sources. | Certificate Transparency (CT) logs, search engine queries |

## Subdomain Brute-Forcing
Subdomain brute-forcing uncovers hidden subdomains by testing potential names against the target's DNS server. Use `dnsenum` with a wordlist:
```bash
dnsenum example.com -f subdomains.txt
```

## Zone Transfers
DNS zone transfers (AXFR) replicate DNS data across servers, potentially exposing subdomains, IPs, and records. Attempt with:
```bash
dig @ns1.example.com example.com axfr
```
**Note**: Many DNS servers restrict zone transfers to authorized servers.

## Virtual Hosts
Virtual hosting allows multiple websites to share one IP address. Use `gobuster` to enumerate virtual hosts:
```bash
gobuster vhost -u http://192.0.2.1 -w hostnames.txt
```

## Certificate Transparency (CT) Logs
CT logs record SSL/TLS certificates, revealing subdomains. Query with:
```bash
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u
```

## Web Crawling
Web crawling maps a website's structure by following links. Analyze `robots.txt` for hidden directories. Use Scrapy for crawling:
```python
import scrapy

class ExampleSpider(scrapy.Spider):
    name = "example"
    start_urls = ['http://example.com/']

    def parse(self, response):
        for link in response.css('a::attr(href)').getall():
            if any(link.endswith(ext) for ext in self.interesting_extensions):
                yield {"file": link}
            elif not link.startswith("#") and not link.startswith("mailto:"):
                yield response.follow(link, callback=self.parse)
```
Extract links:
```bash
jq -r '.[] | select(.file != null) | .file' example_data.json | sort -u
```

## Search Engine Discovery
Use search operators for OSINT:

| Operator | Description | Example |
|----------|-------------|---------|
| `site:` | Restricts results to a website. | `site:example.com "password reset"` |
| `inurl:` | Searches for a term in the URL. | `inurl:admin login` |
| `filetype:` | Limits results to file types. | `filetype:pdf "confidential report"` |
| `intitle:` | Searches for a term in the page title. | `intitle:"index of" /backup` |
| `cache:` | Shows cached webpage. | `cache:example.com` |
| `"search term"` | Exact phrase search. | `"internal error" site:example.com` |
| `OR` | Combines terms. | `inurl:admin OR inurl:login` |
| `-` | Excludes terms. | `inurl:admin -intext:wordpress` |

## Web Archives
Web archives like the Wayback Machine store historical website snapshots:

| Feature | Description | Use Case in Reconnaissance |
|---------|-------------|----------------------------|
| Historical Snapshots | View past versions of websites. | Identify past content or functionality. |
| Hidden Directories | Explore removed or hidden directories. | Discover sensitive information or backups. |
| Content Changes | Track changes in content. | Assess security posture evolution. |

# Nmap Scans

## Scan Types
Common Nmap scan types and flags with examples:

| Scan Type | Description | Flag |
|-----------|-------------|------|
| TCP SYN Scan | Stealthy half-open scan for TCP ports. Example: `nmap -sS -T4 192.168.1.1` | -sS |
| TCP Connect Scan | Full TCP connection scan. Example: `nmap -sT -p 1-1000 192.168.1.1` | -sT |
| UDP Scan | Scan for UDP ports. Example: `nmap -sU -sV 192.168.1.1` | -sU |
| Ping Scan | Host discovery without port scanning. Example: `nmap -sn 192.168.1.0/24` | -sn (or -sP) |
| Version Detection | Identify service versions on open ports. Example: `nmap -sV -p 80,443 192.168.1.1` | -sV |
| OS Detection | Fingerprint operating system. Example: `nmap -O 192.168.1.1` | -O |
| Script Scan | Run NSE scripts for additional info. Example: `nmap -sC 192.168.1.1` | -sC |
| Aggressive Scan | Combines version, OS, script, and traceroute. Example: `nmap -A 192.168.1.1` | -A |
| Idle/Zombie Scan | Stealth scan using spoofed IP. Example: `nmap -sI zombie.host 192.168.1.1` | -sI |

## Commonly Used Nmap Flags
Additional flags to customize Nmap scans:

| Flag | Purpose |
|------|----------|
| `-p` | Defines a port range or specific ports to scan (e.g., `-p 1-1000` for ports 1-1000, `-p 80,443` for specific ports). |
| `-T<0-5>` | Sets timing template (0=paranoid to 5=insane) to control scan speed (e.g., `-T4` for faster scans). |
| `-A` | Enables aggressive scan features (version detection, OS detection, scripting, traceroute). |
| `-oN` | Outputs scan results to a normal file (e.g., `-oN scan.txt`). |
| `-v` | Increases verbosity for detailed output during the scan. |
| `-Pn` | Treats all hosts as online, skipping host discovery (useful for firewalls). |
| `-iL` | Reads targets from a file (e.g., `-iL targets.txt` for a list of IPs). |