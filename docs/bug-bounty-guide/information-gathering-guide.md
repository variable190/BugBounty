# Information Gathering

[Relative Cheat Sheet](./info-gathering-cheat.md)

## Step-by-Step Guide for Information Gathering in Bug Bounty Hunting

### 1. Understand the Importance of Information Gathering
   - **Explanation**: Information gathering, or reconnaissance, involves collecting data about the target application, its infrastructure, and potential entry points without directly interacting in a harmful way. This phase includes passive (using public sources) and active (probing the target) methods to build a profile of the target's attack surface.
   - **Why It's Done**: A thorough recon phase reveals subdomains, technologies, and misconfigurations that could lead to vulnerabilities. It maximizes efficiency by focusing testing on high-value areas and minimizes detection risk during early stages.
   - **Example**: Discovering a forgotten subdomain hosting an outdated CMS could lead to an easy exploit.

### 2. Define the Scope
   - **Explanation**: Review the bug bounty program's rules to identify in-scope domains, IPs, and assets. Note out-of-scope items to avoid violations.
   - **Why It's Done**: Ensures testing stays legal and focused, preventing wasted effort on irrelevant areas.
   - **Example**: If the scope is `*.example.com`, prioritize subdomains like `api.example.com`.

### 3. Perform Passive Reconnaissance
   - **Explanation**: Use public sources to gather info without touching the target. This includes WHOIS lookups for domain registration details, DNS queries for records (A, MX, NS), and search engines with dorks (e.g., `site:example.com filetype:pdf`) for sensitive files.
   - **Why It's Done**: Passive recon is stealthy, reducing the chance of alerting the target, and often reveals valuable data like emails or old configs.
   - **Example**: Run `whois example.com` to get owner contacts, or `dig example.com NS` for nameservers.

### 4. Enumerate Subdomains Passively
   - **Explanation**: Query Certificate Transparency (CT) logs via crt.sh or search engines for subdomains listed in certificates.
   - **Why It's Done**: Subdomains may host vulnerable services or forgotten apps; passive methods avoid direct queries to the target's DNS.
   - **Example**: `curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u` to list unique subdomains.

### 5. Enumerate Subdomains Actively
   - **Explanation**: Use tools like dnsenum for brute-forcing with wordlists or attempt zone transfers (`dig @ns.example.com example.com axfr`).
   - **Why It's Done**: Active methods uncover subdomains not in public logs, but carry detection risk; use sparingly.
   - **Example**: `dnsenum example.com -f subdomains.txt` to brute-force common names.

### 6. Discover Virtual Hosts
   - **Explanation**: Fuzz the Host header with tools like gobuster (`gobuster vhost -u http://ip -w hostnames.txt`) to find multiple sites on the same IP.
   - **Why It's Done**: Virtual hosts may have different security levels; one could be vulnerable.
   - **Example**: Discovering `admin.example.com` on the main IP.

### 7. Crawl the Website
   - **Explanation**: Use spiders like Scrapy or ZAP to follow links, mapping directories and files. Check `robots.txt` for disallowed paths.
   - **Why It's Done**: Reveals hidden directories, parameters, or old files that could be exploited.
   - **Example**: Set up a Scrapy spider to extract links and analyze for sensitive extensions like `.bak`.

### 8. Use Search Engine Discovery
   - **Explanation**: Apply Google Dorks (e.g., `inurl:admin site:example.com`) or Bing for exposed files, directories, or errors.
   - **Why It's Done**: Search engines index data the app might not intend to expose, like backups or login pages.
   - **Example**: `intitle:"index of" /backup site:example.com` to find directory listings.

### 9. Check Web Archives
   - **Explanation**: Use Wayback Machine or similar to view historical snapshots for removed content or configs.
   - **Why It's Done**: Old versions may reveal vulnerabilities fixed in current but exploitable via other means.
   - **Example**: Search Wayback for `example.com/wp-config.php` exposing DB creds in past snapshots.

### 10. Analyze and Prioritize Findings
   - **Explanation**: Compile data on subdomains, tech stack (e.g., from headers), and potential weak points. Prioritize based on sensitivity (e.g., admin subdomains).
   - **Why It's Done**: Organizes recon for efficient vulnerability scanning in later stages.
   - **Example**: List subdomains with Wappalyzer to identify outdated tech like old WordPress.

### 11. Assess Prevention Measures
   - **Explanation**: Note if the target hides info (e.g., redacted WHOIS) or blocks crawlers.
   - **Why It's Done**: Helps in reporting and understanding security posture.
   - **Example**: If zone transfers are blocked, note as a good practice.

This guide, based on the Information Gathering - Web Edition module and aligned with PortSwigger Web Security Academy, provides a detailed process for recon. Test ethically within scope.