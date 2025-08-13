# Bug Bounty Process

## Step-by-Step Guide for Bug Bounty Hunting

### 1. Understand the Bug Bounty Process
   - **Explanation**: Bug bounty hunting involves identifying, exploiting, and reporting vulnerabilities in programs on platforms like HackerOne or Bugcrowd for rewards. It follows a structured workflow from scoping to follow-up.
   - **Why It's Done**: A systematic process ensures efficient, ethical hunting, maximizing findings and bounties while minimizing risks.
   - **Example**: Participating in a program like Google's to hunt for XSS or RCE.

### 2. Define the Scope
   - **Explanation**: Review the program's policy for in-scope assets (domains, APIs, apps) and out-of-scope items (e.g., DoS attacks). Note rules on testing intensity or disclosure.
   - **Why It's Done**: Ensures legal compliance and focuses efforts on reward-eligible areas.
   - **Example**: Scope limited to `*.example.com`; test only those domains.

### 3. Perform Reconnaissance
   - **Explanation**: Gather intel on targets using passive (CT logs, WHOIS) and active (subdomain brute-force) methods to map assets, tech stack, and endpoints.
   - **Why It's Done**: Builds a target profile, uncovering hidden subdomains or misconfigs for targeted attacks.
   - **Example**: Use crt.sh for subdomains; link to [Information Gathering Guide](./information-gathering-guide.md) and [Cheat Sheet](./info-gathering-cheat.md).

### 4. Map the Application
   - **Explanation**: Proxy traffic (Burp/ZAP) to understand layout, fuzz endpoints (ffuf), and analyze JS for client-side logic.
   - **Why It's Done**: Reveals structure, inputs, and flows for vuln discovery.
   - **Example**: Intercept login requests; link to [Using Web Proxies](./using-web-proxies.md), [Attacking with Ffuf](./attacking-web-applications-with-ffuf.md), and [JavaScript Deobfuscation](./javascript-deobfuscation.md).

### 5. Scan for Vulnerabilities
   - **Explanation**: Use automated tools (Burp Scanner, WPScan) and manual testing for common vulns (XSS, SQLi, etc.), prioritizing based on recon.
   - **Why It's Done**: Identifies exploitable issues efficiently.
   - **Example**: Scan for XSS in forms; link to guides like [Cross-Site Scripting (XSS)](./cross-site-scripting-guide.md), [SQL Injection](./sql-injection-guide.md), [Command Injections](./command-injections-guide.md), [File Upload Attacks](./file-upload-attacks-guide.md), [Server-side Attacks](./server-side-attacks-guide.md), [Login Brute Forcing](./login-brute-forcing-guide.md), [Broken Authentication](./broken-authentication-guide.md), [Web Attacks](./web-attacks-guide.md), [File Inclusion](./file-inclusion-guide.md), [Session Security](./session-security-guide.md), [Web Service & API Attacks](./web-service-api-attacks-guide.md), [Hacking WordPress](./hacking-wordpress-guide.md), and relevant cheat sheets.

### 6. Exploit Vulnerabilities
   - **Explanation**: Develop PoCs to confirm impact (e.g., data exfil, RCE), chain vulns (XSS + CSRF), and test boundaries.
   - **Why It's Done**: Proves real-world risk for reports.
   - **Example**: Chain XSS for cookie theft; reference exploitation steps in linked guides.

### 7. Report Findings
   - **Explanation**: Write detailed reports with title, description, PoC, impact, and remediation; submit via platform.
   - **Why It's Done**: Communicates vulns for fixes and bounties.
   - **Example**: XSS report with PoC; link to [Bug Bounty Reporting Guide](./bug-bounty-reporting-guide.md).

### 8. Interact with the Program
   - **Explanation**: Respond to triage queries, provide clarifications, and maintain professional communication.
   - **Why It's Done**: Builds rapport and resolves issues for approval.
   - **Example**: Supply video PoC if requested.

### 9. Follow-Up and Retest
   - **Explanation**: Monitor fix status; retest if allowed to verify resolution.
   - **Why It's Done**: Ensures vulns are fixed; may earn additional bounties.
   - **Example**: Retest SQLi post-fix.

### 10. Learn and Iterate
   - **Explanation**: Review feedback, update methodologies, and track progress.
   - **Why It's Done**: Improves skills for future hunts.
   - **Example**: Analyze rejected reports for improvements.

Test ethically within scope.