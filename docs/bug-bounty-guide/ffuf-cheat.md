# Attacking Web Applications with Ffuf Cheat Sheet

## Commands
| Command | Description |
|---------|-------------|
| `ffuf -h` | Display ffuf help menu |
| `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ` | Directory Fuzzing to discover hidden directories |
| `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/indexFUZZ` | Extension Fuzzing to identify file types |
| `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php` | Page Fuzzing to find dynamic pages |
| `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v` | Recursive Fuzzing to explore subdirectories with verbose output |
| `ffuf -w wordlist.txt:FUZZ -u https://FUZZ.hackthebox.eu/` | Sub-domain Fuzzing to enumerate subdomains |
| `ffuf -w wordlist.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb' -fs xxx` | VHost Fuzzing to detect virtual hosts, filtering by size |
| `ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx` | Parameter Fuzzing - GET to find injectable parameters |
| `ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx` | Parameter Fuzzing - POST to test POST-based parameters |
| `ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx` | Value Fuzzing to test parameter value vulnerabilities |

## Wordlists
| Command | Description |
|---------|-------------|
| `/opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt` | Directory/Page Wordlist for fuzzing directories and pages |
| `/opt/useful/seclists/Discovery/Web-Content/web-extensions.txt` | Extensions Wordlist for fuzzing file extensions |
| `/opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt` | Domain Wordlist for subdomain enumeration |
| `/opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt` | Parameters Wordlist for parameter fuzzing |

## Misc
| Command | Description |
|---------|-------------|
| `sudo sh -c 'echo "SERVER_IP academy.htb" >> /etc/hosts'` | Add a DNS entry to resolve custom domains |
| `for i in $(seq 1 1000); do echo $i >> ids.txt; done` | Create a sequence wordlist for value fuzzing |
| `curl http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'` | Example curl command with POST request |