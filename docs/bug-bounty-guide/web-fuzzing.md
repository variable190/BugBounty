# Web Fuzzing

## What is Web Fuzzing?

Web fuzzing injects large input sets into web applications to find vulnerabilities, hidden resources, or errors.

| Target                  | Description                     |
|-------------------------|---------------------------------|
| Hidden Directories/Files| Discover unlinked paths         |
| Insecure APIs           | Identify unprotected endpoints  |
| SQL Injection           | Find injectable query points    |
| XSS Vulnerabilities     | Detect script injection flaws   |
| Command Injection       | Uncover system command exploits |

## Installing Tools

### Prerequisits

Installing Go, Python and PIPX

```bash
sudo apt update
sudo apt install -y golang
sudo apt install -y python3 python3-pip
sudo apt install pipx
pipx ensurepath
sudo pipx ensurepath --global
```

### Tools

| Tool       | Description                        | Use Cases                          |
|------------|------------------------------------|------------------------------------|
| FFUF       | Fast Go-based web fuzzer for enumeration. | Directory/file enumeration, parameter discovery, brute-force attacks |
| Gobuster   | Simple, fast web directory fuzzer. | Content discovery, DNS subdomain enumeration, WordPress detection |
| FeroxBuster| Rust-based recursive content discovery tool. | Recursive scanning, unlinked content discovery, high-performance scans |
| wfuzz/wenum| Versatile Python fuzzer for parameter testing. | Directory/file enumeration, parameter discovery, brute-force attacks |

```bash
go install github.com/ffuf/ffuf/v2@latest
go install github.com/OJ/gobuster/v3@latest
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | sudo bash -s $HOME/.local/bin
pipx install git+https://github.com/WebFuzzForge/wenum
pipx runpip wenum install setuptools
```

## Miscellaneous Commands

| Command                           | Description                          |
|-----------------------------------|--------------------------------------|
| `sudo sh -c 'echo "SERVER_IP academy.htb" >> /etc/hosts'` | Add DNS entry to hosts file |
| `for i in $(seq 1 1000); do echo $i >> ids.txt; done` | Create numerical wordlist (1-1000) |
| `curl http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'` | Send POST request with data  |

## SecLists Wordlists

| Wordlist                                      | Description                       |
|-----------------------------------------------|-----------------------------------|
| `/usr/share/seclists/Discovery/Web-Content/common.txt` | Common directory/file names       |
| `/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt` | Extensive directory names  |
| `/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt` | Large directory collection  |
| `/usr/share/seclists/Discovery/Web-Content/big.txt` | Comprehensive directory/files  |

## Web Fuzzing Tips

| Tip                    | Explanation                          |
|------------------------|--------------------------------------|
| Choose Wordlists       | Select relevant wordlists for target |
| Combine Wordlists      | Use multiple wordlists for breadth   |
| Customize Wordlists    | Tailor based on target knowledge     |
| Monitor Performance    | Adjust for resource-intensive lists  |
| Use Community Resources| Leverage updated community wordlists |

## Parameter Fuzzing

- Altering a product ID in a shopping cart URL could reveal pricing errors or unauthorized access to other users' orders.
- Modifying a hidden parameter in a request might unlock hidden features or administrative functions.
- Injecting malicious code into a search query could expose vulnerabilities like Cross-Site Scripting (XSS) or SQL Injection (SQLi).

## FFUF Commands

| Command                           | Description                     |
|-----------------------------------|---------------------------------|
| `ffuf -u http://example.com/FUZZ` | Basic URL fuzzing               |
| `ffuf -u http://example.com/FUZZ -w wordlist.txt` | Fuzz with wordlist |
| `ffuf -u http://example.com/FUZZ -w wordlist.txt -ic` | Ignore wordlist comments |
| `ffuf -u http://example.com/FUZZ -w wordlist.txt -c` | Colorize output |
| `ffuf -u http://example.com/FUZZ -w wordlist.txt -mc 200` | Filter by status code |
| `ffuf -u http://example.com/FUZZ -w wordlist.txt -mr "Welcome"` | Filter by regex pattern |
| `ffuf -u http://example.com/FUZZ -w wordlist.txt -e .php,.html` | Add extensions |
| `ffuf -u http://example.com/FUZZ -w wordlist.txt -t 50` | Set threads (50) |
| `ffuf -u http://example.com/FUZZ -w wordlist.txt -x http://127.0.0.1:8080` | Use proxy |
| `ffuf -u http://94.237.53.81:52991/post.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "y=FUZZ" -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200 -v` |  POST parameter fuzzing, match status code 200 |

### Examples

| Command | Description |
|---------|-------------|
| `ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -ic -u http://IP:PORT/FUZZ -t 80` | Directory fuzzing, set to 80 threads |
| `ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -ic -u http://IP:PORT/w2ksvrus/FUZZ -e .php,.html,.txt,.bak,.js -v -rate 500` | File fuzzing, verbose output, limit to 500 request per second |
| `ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -ic -v -u http://IP:PORT/FUZZ -e .php,.txt,.html -recursion -recursion-depth 2` | Recursive fuzzing, limit depth to 2 |

## Gobuster Commands

| Command                           | Description                     |
|-----------------------------------|---------------------------------|
| `gobuster dir -u http://example.com -w wordlist.txt` | Directory fuzzing |
| `gobuster dir -u http://example.com -w wordlist.txt -x .php,.html` | Fuzz with extensions |
| `gobuster dir -u http://example.com -w wordlist.txt -s 200` | Filter by status code |
| `gobuster dir -u http://example.com -w wordlist.txt -t 50` | Set threads (50) |
| `gobuster dir -u http://example.com -w wordlist.txt -o results.txt` | Save output |
| `gobuster dns -d example.com -w subdomains.txt` | DNS subdomain fuzzing |
| `gobuster dns -d example.com -w subdomains.txt -i` | Show IPs for subdomains |
| `gobuster dns -d example.com -w subdomains.txt -z` | Silent mode    |

## Wenum Commands

| Command                           | Description                     |
|-----------------------------------|---------------------------------|
| `wenum -w /usr/share/seclists/Discovery/Web-Content/common.txt --hc 404 -u "http://94.237.53.81:52991/get.php?x=FUZZ"` | Parameter fuzzing, exclude 404 |
| `wenum -c -z file,wordlist.txt -d 'username=FUZZ&password=secret'` | Fuzz POST data |
| `wenum -c -z file,wordlist.txt -b 'session=12345'` | Use cookie     |
| `wenum -c -z file,wordlist.txt -H 'User-Agent: Wenum'` | Add custom header |
| `wenum -c -z file,wordlist.txt -t 50` | Set threads (50) |
| `wenum -c -z file,wordlist.txt -u http://example.com/FUZZ -X PUT` | Fuzz with PUT method |
| `wenum -c -z file,wordlist.txt --hl 50` | Filter by content length  |
| 

## Feroxbuster Commands

| Command                           | Description                     |
|-----------------------------------|---------------------------------|
| `feroxbuster -u http://example.com -w wordlist.txt` | Basic URL fuzzing |
| `feroxbuster -u http://example.com -w wordlist.txt -e` | Include extensions |
| `feroxbuster -u http://example.com -w wordlist.txt -x 404` | Exclude 404 responses |
| `feroxbuster -u http://example.com -w wordlist.txt -t 50` | Set threads (50) |
| `feroxbuster -u http://example.com -w wordlist.txt --depth 3` | Set recursion depth (3) |
| `feroxbuster -u http://example.com -w wordlist.txt -o results.txt` | Save output |
| `feroxbuster -u http://example.com -w wordlist.txt --no-recursion` | Disable recursion |
| `feroxbuster -u http://example.com -w wordlist.txt --url-redirect` | Follow redirects |

## Web API Types

| Type   | Description                     | Features                           |
|--------|---------------------------------|------------------------------------|
| REST   | Uses HTTP methods for resources | JSON/XML, stateless, scalable, caching |
| SOAP   | XML-based protocol for services | XML, stateful/stateless, WS-Security |
| GraphQL| Query language for APIs         | JSON, single endpoint, flexible queries |

## REST Fuzzing Tips

| Tip                    | Explanation                          |
|------------------------|--------------------------------------|
| Test All Methods       | Check GET, POST, PUT, DELETE for vulns |
| Validate Input Fields  | Fuzz inputs with unexpected data     |
| Examine Errors         | Analyze messages for info disclosure |
| Test Authentication    | Check for weak auth controls         |
| Explore Rate Limits    | Test throttling for bypasses         |
| Use Comprehensive Payloads | Test SQLi, XSS payloads          |
| Check Representations  | Test JSON/XML for consistency flaws  |

## SOAP Fuzzing Tips

| Tip                    | Explanation                          |
|------------------------|--------------------------------------|
| Analyze WSDL Files     | Understand service operations        |
| Validate XML Schema    | Test for validation flaws            |
| Check XML Injection    | Fuzz for injection vulnerabilities   |
| Test SOAP Headers      | Identify header misconfigurations    |
| Evaluate WS-Security   | Verify security implementations      |
| Test Transport Security| Ensure HTTPS enforcement             |
| Examine SOAP Faults    | Check for info leakage in faults     |

## GraphQL Fuzzing Tips

| Tip                    | Explanation                          |
|------------------------|--------------------------------------|
| Test Query Depth       | Check handling of complex queries    |
| Validate Input Types   | Fuzz arguments for validation flaws  |
| Examine Query Aliasing| Test aliased queries for leakage      |
| Check Introspection    | Ensure no sensitive schema exposure  |
| Assess Authorization   | Verify query access controls         |
| Evaluate Rate Limiting | Test handling of excessive queries   |
| Fuzz Mutations         | Test data-altering queries for flaws |